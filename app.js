require('ejs');
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const db = require('./db');

const nodemailer = require('nodemailer');
const crypto = require('crypto');


require('dotenv').config(); // Make sure you have dotenv installed and a .env file
const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');


app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production' && process.env.FORCE_HTTPS === 'true',
    sameSite: 'strict',
    maxAge: 1000 * 60 * 60
  }
}));

const cookieParser = require('cookie-parser');
app.use(cookieParser(process.env.COOKIE_SECRET)); // Add a secret in your .env


const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  },
  tls: {
    rejectUnauthorized: false
  }
});


// Auth middleware
const requireAuth = (req, res, next) => {
  if (!req.session.user) return res.redirect('/login');
  if (req.session.user.login != "login") return res.redirect('/login')
  next();
};

const requireAuthForMFA = (req, res, next) => {
  if (!req.session.user) return res.redirect('/login');
  if (req.session.user.login != "mfa") return res.redirect('/')
  next();
};

app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;

  db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
    if (err) throw err;
    if (!user) {
      // commebt
      const errorMsg = 'Invalid credentials';

      return res.render('login', { error: errorMsg });
    }
    // Check if account is locked due to too many failed login attempts
    if (user.login_lock_until && Date.now() < user.login_lock_until) {
      return res.render('login', { error: 'Too many login attempts. Please wait 30 seconds.' });
    }

    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      // Track failed login attempts
      const failedLogins = user.failed_logins + 1;

      // Lock account if 5 failed attempts
      let lockUntil = user.login_lock_until;
      if (failedLogins >= 5) {
        lockUntil = Date.now() + 30000; // Lock for 30 seconds
      }

      db.run(`UPDATE users SET failed_logins = ?, login_lock_until = ? WHERE id = ?`, [failedLogins, lockUntil, user.id], (err) => {
        if (err) throw err;

        const errorMsg = failedLogins >= 5
          ? 'Too many attempts. Please wait 30 seconds.'
          : 'Invalid credentials';

        return res.render('login', { error: errorMsg });
      });
    } else {
      // Reset failed login attempts on successful login
      db.run(`UPDATE users SET failed_logins = 0, login_lock_until = 0 WHERE id = ?`, [user.id], (err) => {
        if (err) throw err;
        const deviceToken = req.signedCookies.trusted_device;
        if (deviceToken) {
          db.get(`SELECT * FROM trusted_devices WHERE user_id = ? AND device_token = ?`, [user.id, deviceToken], (err, trustedDevice) => {
            if (err) throw err;

            if (trustedDevice) {
              // Device is trusted — skip MFA
              req.session.user = { id: user.id, name: user.username, role: user.role, login: "login" };
              return res.redirect('/');
            } else {
              // Not trusted — go to MFA
              req.session.user = { id: user.id, name: user.username, role: user.role, login: "mfa" };
              return res.redirect('/mfa');
            }
          });
        } else {
          req.session.user = { id: user.id, name: user.username, role: user.role, login: "mfa" };
          res.redirect('/mfa');
        }
      });
    }
  });
});

app.get('/mfa', requireAuthForMFA, (req, res) => {
  // Generate 6-digit code
  const code = crypto.randomInt(100000, 999999).toString();

  // Save it in session
  req.session.mfaCode = code;

  // Render the MFA page immediately
  res.render('mfa', { error: null });

  // Now send the email in the background
  db.get(`SELECT email FROM users WHERE id = ?`, [req.session.user.id], (err, row) => {
    if (err || !row) {
      console.error('Could not fetch user email');
      return;
    }

    const mailOptions = {
      from: process.env.EMAIL_USER,
      to: row.email,
      subject: 'Your MFA Code for PFS Assignment',
      text: `Your authentication code is: ${code}\n\nDo not share this code with anyone.\n\n\nIf you did not attempt to login, I would suggest changing your password as soon as possible.`
    };

    transporter.sendMail(mailOptions, (error, info) => {
      if (error) {
        console.error('Failed to send email', error);
      } else {
        console.log('Email sent: ' + info.response);
      }
    });
  });
});

app.post('/mfa', requireAuthForMFA, (req, res) => {
  const { code } = req.body;

  // Get the user data from the database
  db.get(`SELECT * FROM users WHERE id = ?`, [req.session.user.id], (err, user) => {
    if (err) throw err;

    // Check if account is locked due to too many failed MFA attempts
    if (user.mfa_lock_until && Date.now() < user.mfa_lock_until) { // crazy bit manip
      return res.render('mfa', { error: 'Too many attempts. Please wait 30 seconds.' });
    }

    // No code? Redirect to login
    if (!req.session.mfaCode) {
      return res.redirect('/login');
    }

    // Check if the submitted MFA code is correct
    if (code === req.session.mfaCode) {
      // Success — reset MFA attempts
      db.run(`UPDATE users SET mfa_attempts = 0, mfa_lock_until = 0 WHERE id = ?`, [user.id], (err) => {
        if (err) throw err;

        if (!req.body.remember_device) {

          req.session.user.login = "login"
          delete req.session.mfaCode;
          return res.redirect('/');
        }

        // Check if user opted to remember this device (e.g. via a checkbox in the form)
        // if (req.body.remember_device) {
        const deviceToken = require('crypto').randomBytes(32).toString('hex');
        const createdAt = Date.now();

        // Store in DB
        db.run(`INSERT INTO trusted_devices (user_id, device_token, created_at) VALUES (?, ?, ?)`,
          [user.id, deviceToken, createdAt], (err) => {
            if (err) throw err;

            // Set signed, HTTP-only cookie for 30 days
            res.cookie('trusted_device', deviceToken, {
              maxAge: 30 * 24 * 60 * 60 * 1000,
              httpOnly: true,
              signed: true,
              sameSite: 'strict'
            });
            req.session.user.login = "login"
            delete req.session.mfaCode;
            return res.redirect('/');
          });
        // } else {
        //   req.session.user.login = "login"
        //   delete req.session.mfaCode;
        //   return res.redirect('/');
        // }
      });
    } else {
      // Incorrect code — increment attempts
      const newAttempts = user.mfa_attempts + 1;
      let lockUntil = 0;

      if (newAttempts >= 5) { // or however many attempts you want to allow
        lockUntil = Date.now() + (30 * 1000); // lock for 30 seconds
      }

      db.run(`UPDATE users SET mfa_attempts = ?, mfa_lock_until = ? WHERE id = ?`,
        [newAttempts, lockUntil, user.id], (err) => {
          if (err) throw err;

          let errorMsg = 'Invalid code. Please try again.';
          if (lockUntil) {
            errorMsg = 'Too many attempts. Please wait 30 seconds.';

            const mailOptions = {
              from: process.env.EMAIL_USER,
              to: user.email,
              subject: 'Failed log in attempts to your account',
              text: `A user has failed to log into your account. If you have not attempted to log in, please change your password immediately!`
            };

            transporter.sendMail(mailOptions, (error, info) => {
              if (error) {
                console.error('Failed to send email', error);
              } else {
                console.log('Email sent: ' + info.response);
              }
            });
          }
          return res.render('mfa', { error: errorMsg });
        });
    }

  });
});

app.get('/forgot-password', (req, res) => {
  const deviceToken = req.signedCookies.trusted_device;

  if (!deviceToken) {
    return res.status(403).send('Password reset only available on trusted devices.');
  }

  // If trusted device, show form to enter username to request reset
  res.render('forgot-password', { error: null });
});

app.post('/forgot-password', (req, res) => {
  const { username } = req.body;
  const deviceToken = req.signedCookies.trusted_device;

  if (!deviceToken) {
    return res.status(403).send('Password reset only available on trusted devices.');
  }

  db.get(`SELECT * FROM users WHERE username = ?`, [username], (err, user) => {
    if (err) throw err;
    if (!user) {
      return res.render('forgot-password', { error: 'No user found with that username' });
    }

    // Generate a code
    const resetCode = Math.floor(100000 + Math.random() * 900000).toString();

    // Send email
    // const transporter = nodemailer.createTransport({
    //   service: 'gmail',
    //   auth: {
    //     user: process.env.EMAIL_ADDRESS,
    //     pass: process.env.EMAIL_PASSWORD
    //   }
    // });

    const mailOptions = {
      from: process.env.EMAIL_ADDRESS,
      to: user.email,
      subject: 'Password Reset Code',
      text: `Your password reset code is: ${resetCode}\n\nNever share this code with someone else.\n\n\nIf you did not request this it means someone tried to reset your password from your device.`
    };

    transporter.sendMail(mailOptions, (err, info) => {
      if (err) {
        console.error(err);
        return res.status(500).send('Failed to send email');
      }

      // Save code in session
      req.session.resetCode = resetCode;
      req.session.resetUser = { id: user.id, username: user.username };

      res.redirect('/reset-password');
    });
  });
});

app.get('/reset-password', (req, res) => {
  res.render('reset-password', { error: null });
});

app.post('/reset-password', async (req, res) => {
  const { code, newPassword } = req.body;

  if (!req.session.resetCode || !req.session.resetUser) {
    return res.status(403).send('Reset session expired. Start over.');
  }

  if (code !== req.session.resetCode) {
    return res.render('reset-password', { error: 'Invalid code.' });
  }

  const hashedPassword = await bcrypt.hash(newPassword, 10);

  db.run(`UPDATE users SET password_hash = ? WHERE id = ?`, [hashedPassword, req.session.resetUser.id], (err) => {
    if (err) throw err;

    // Clear reset session data
    delete req.session.resetCode;
    delete req.session.resetUser;

    res.redirect('/login');
  });
});

// app.post()

function requireRole(role) {
  return (req, res, next) => {
    if (!req.session.user || req.session.user.role !== role) {
      return res.status(403).send('Forbidden');
    }
    next();
  };
}



app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login');
  });
});

app.use(requireAuth);

app.get('/', (req, res) => {
  db.all('SELECT * FROM inventory', (err, rows) => {
    if (err) throw err;
    res.render('index', { items: rows, user: req.session.user });
  });
});


app.post('/add', requireRole('admin'), (req, res) => {
  // if (req.session.user.role !== 'admin') return res.status(403).send('Forbidden');

  const { name, quantity, location, supplier } = req.body;
  const parsedQuantity = parseInt(quantity, 10);

  // Validate quantity
  if (isNaN(parsedQuantity) || parsedQuantity < 0) {
    return res.status(400).send('Invalid Quantity! Item Quantity Cannot Be Less Than 0!');
  }

  if (quantity > 999999999) {
    return res.status(400).send('Invalid Input! Item Quantity cannot exceed 999999999!');
  }

  // Check for duplicate based on name, location, and supplier
  db.get(
    `SELECT * FROM inventory 
     WHERE LOWER(name) = LOWER(?) AND LOWER(location) = LOWER(?) AND LOWER(supplier) = LOWER(?)`,
    [name, location, supplier],
    (err, row) => {
      if (err) return res.status(500).send('Database error');
      if (row) return res.status(409).send('Item with this name, location, and supplier already exists');

      // If valid and not duplicate, insert the item
      db.run(
        `INSERT INTO inventory (name, quantity, location, supplier) VALUES (?, ?, ?, ?)`,
        [name, parsedQuantity, location, supplier],
        (err) => {
          if (err) return res.status(500).send('Error adding item');
          res.redirect('/');
        }
      );
    }
  );
});


app.post('/delete/:id', requireRole('admin'), (req, res) => {
  // if (req.session.user.role !== 'admin') return res.status(403).send('Forbidden');
  db.run(`DELETE FROM inventory WHERE id = ?`, [req.params.id], () => res.redirect('/'));
});

app.post('/update/:id', requireRole('admin'), (req, res) => {
  // if (req.session.user.role !== 'admin') return res.status(403).send('Forbidden');
  let quantity = parseInt(req.body.quantity, 10);

  // Validate quantity
  if (isNaN(quantity) || quantity < 0) {
    return res.status(400).send('Invalid Input! Item Quantity cannot be less than 0!');
  }
  if (quantity > 999999999) {
    return res.status(400).send('Invalid Input! Item Quantity cannot exceed 999999999!');
  }

  // const { quantity } = req.body;
  db.run(`UPDATE inventory SET quantity = ? WHERE id = ?`, [quantity, req.params.id], () => res.redirect('/'));
});

app.listen(3000, () => console.log('Server running on http://localhost:3000'));
