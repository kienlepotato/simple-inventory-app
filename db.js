const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./inventory.db');

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS inventory (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT,
      quantity INTEGER,
      location TEXT,
      supplier TEXT
    )
  `);

  // db.run(`DROP TABLE users`, (err) => {
  //   if (err) {
  //     console.error("Error deleting table:", err.message);
  //   } else {
  //     console.log("Table deleted successfully.");
  //   }
  // });i

  db.run(`
  CREATE TABLE IF NOT EXISTS trusted_devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    device_token TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
  )
`)
  
  


  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      failed_logins INTEGER DEFAULT 0,
      login_lock_until INTEGER DEFAULT 0,
      mfa_attempts INTEGER DEFAULT 0,
      mfa_lock_until INTEGER DEFAULT 0
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS user_fingerprints (
      user_id INTEGER NOT NULL,
      fingerprint TEXT NOT NULL,
      PRIMARY KEY (user_id, fingerprint),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
  `);
});

module.exports = db;
