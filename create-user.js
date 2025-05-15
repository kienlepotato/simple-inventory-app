const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./inventory.db');

// const username = 'admin';
// const password = 'adminpass';
// const role = 'admin';
// const email = 'palutenaisbestwaifu@gmail.com';

// const username = 'user';
// const password = 'userpass';
// const role = 'user';
// const email = 'safjfvbh@gmail.com';


const username = 'parakh';
const password = 'parakh';
const role = 'admin';
const email = 'parakhdayal@gmail.com';

bcrypt.hash(password, 10).then(hash => {
  db.run(`INSERT INTO users (username, password_hash, role, email) VALUES (?, ?, ?, ?)`,
    [username, hash, role, email],
    () => {
      console.log('User created');
      db.close();
    });
  const userid = 2;
  // db.run(
  //   `DELETE FROM trusted_devices WHERE user_id = ?`,
  //   [userid],
  //   function (err) {
  //     if (err) {
  //       console.error('Error deleting trusted devices:', err.message);
  //     } else {
  //       console.log(`Deleted trusted devices for user ID ${userid}`);
  //     }
  //     db.close();
  //   }
  // );
});

