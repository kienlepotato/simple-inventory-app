const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./inventory.db');

const username = 'admin';
const password = 'adminpass';
const role = 'admin';
const email = 'palutenaisbestwaifu@gmail.com';

// const username = 'user';
// const password = 'userpass';
// const role = 'user';
// const email = 'safjfvbh@gmail.com';


bcrypt.hash(password, 10).then(hash => {
  db.run(`INSERT INTO users (username, password_hash, role, email) VALUES (?, ?, ?, ?)`,
    [username, hash, role, email],
    () => {
      console.log('User created');
      db.close();
    });
});
