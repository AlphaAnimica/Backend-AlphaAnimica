const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./database.sqlite');

db.serialize(() => {
  db.run("ALTER TABLE users RENAME TO users_old", function (err) {
    if (err) {
      console.error('Error renaming table:', err.message);
      db.close();
      return;
    }
    db.run(`CREATE TABLE users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      name TEXT NOT NULL,
      user_type TEXT NOT NULL CHECK(user_type IN ('trainee', 'clinic', 'admin')),
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`, function (err2) {
      if (err2) {
        console.error('Error creating new table:', err2.message);
        db.close();
        return;
      }
      db.run("INSERT INTO users (id, email, password, name, user_type, created_at) SELECT id, email, password, name, user_type, created_at FROM users_old WHERE user_type IN ('trainee', 'clinic')", function (err3) {
        if (err3) {
          console.error('Error copying data:', err3.message);
        } else {
          console.log('Table fixed! Old users copied.');
        }
        db.run("DROP TABLE users_old", () => db.close());
      });
    });
  });
}); 