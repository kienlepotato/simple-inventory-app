const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./inventory.db');

const username = 'admin';
const password = 'adminpass';
const role = 'admin';

bcrypt.hash(password, 10).then(hash => {
  db.run(`INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)`,
    [username, hash, role],
    () => {
      console.log('User created');
      db.close();
    });
});
