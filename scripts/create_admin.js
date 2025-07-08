function getActiveSubscription(userId, cb) {
  db.get(
    'SELECT * FROM subscriptions WHERE user_id = ? AND expires_at > CURRENT_TIMESTAMP ORDER BY expires_at DESC LIMIT 1',
    [userId],
    cb
  );
}

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();

const email = 'admin@gmail.com';
const password = '123456';

bcrypt.hash(password, 10).then((hashedPassword) => {
  const db = new sqlite3.Database('./database.sqlite');
  db.run(
    "UPDATE users SET password = ? WHERE email = ?",
    [hashedPassword, email],
    function (err) {
      if (err) {
        console.error('Error updating admin password:', err.message);
      } else {
        console.log('Admin password updated successfully!');
      }
      db.close();
    }
  );
}); 