const express = require('express');
const session = require('express-session');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const db = require('./db');
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


// Auth middleware
const requireAuth = (req, res, next) => {
  if (!req.session.user) return res.redirect('/login');
  next();
};

app.get('/login', (req, res) => {
  res.render('login', { error: null });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  db.get(`SELECT * FROM users WHERE username = ?`, [username], async (err, user) => {
    if (err) throw err;
    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.render('login', { error: 'Invalid credentials' });
    }
    req.session.user = { id: user.id, name: user.username, role: user.role };
    res.redirect('/');
  });
});

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


app.post('/add', (req, res) => {
  if (req.session.user.role !== 'admin') return res.status(403).send('Forbidden');

  const { name, quantity, location, supplier } = req.body;
  const parsedQuantity = parseInt(quantity, 10);

  // Validate quantity
  if (isNaN(parsedQuantity) || parsedQuantity < 0) {
    return res.status(400).send('Invalid Quantity! Item Quantity Cannot Be Less Than 0!');
  }

  if ( quantity > 999999999) {
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


app.post('/delete/:id', (req, res) => {
  if (req.session.user.role !== 'admin') return res.status(403).send('Forbidden');
  db.run(`DELETE FROM inventory WHERE id = ?`, [req.params.id], () => res.redirect('/'));
});

app.post('/update/:id', (req, res) => {
  if (req.session.user.role !== 'admin') return res.status(403).send('Forbidden');
  let quantity = parseInt(req.body.quantity, 10);

  // Validate quantity
  if (isNaN(quantity) || quantity < 0) {
    return res.status(400).send('Invalid Input! Item Quantity cannot be less than 0!');
  }
  if ( quantity > 999999999) {
    return res.status(400).send('Invalid Input! Item Quantity cannot exceed 999999999!');
  }

  // const { quantity } = req.body;
  db.run(`UPDATE inventory SET quantity = ? WHERE id = ?`, [quantity, req.params.id], () => res.redirect('/'));
});

app.listen(3000, () => console.log('Server running on http://localhost:3000'));
