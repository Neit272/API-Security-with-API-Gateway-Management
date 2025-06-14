import sqlite3 from "sqlite3";

const db = new sqlite3.Database("./database.sqlite", (err) => {
  if (err) {
    console.error("Could not open database", err);
  } else {
    console.log("Connected to SQLite database");
  }
});

db.serialize(() => {
  db.run(
    `
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      secret TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `,
    (err) => {
      if (err) {
        console.error("Could not create users table", err);
      } else {
        console.log("Users table ready");
      }
    }
  );

  db.run(
    `
    CREATE TABLE IF NOT EXISTS kong_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      client_ip TEXT,
      request_uri TEXT,
      status INTEGER,
      response_time REAL,
      service TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `,
    (err) => {
      if (err) {
        console.error("Could not create kong_logs table", err);
      } else {
        console.log("kong_logs table ready");
      }
    }
  );

  db.run(
    `
    CREATE TABLE IF NOT EXISTS refresh_tokens (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      token_hash TEXT UNIQUE NOT NULL,
      kong_jwt_key TEXT,
      expires_at DATETIME NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
    )
  `,
    (err) => {
      if (err) {
        console.error("Could not create refresh_tokens table", err);
      } else {
        console.log("Refresh_tokens table ready");
      }
    }
  );

  db.run(
    `
    CREATE TABLE IF NOT EXISTS blacklisted_tokens (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      token_hash TEXT UNIQUE NOT NULL,
      user_id INTEGER NOT NULL,
      blacklisted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      expires_at DATETIME NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
    )
  `,
    (err) => {
      if (err) {
        console.error("Could not create blacklisted_tokens table", err);
      } else {
        console.log("Blacklisted_tokens table ready");
      }
    }
  );
});

export function saveLog(data) {
  const { client_ip, request_uri, status, response_time, service } = data;
  db.run(
    `
      INSERT INTO kong_logs (client_ip, request_uri, status, response_time, service)
      VALUES (?, ?, ?, ?, ?)`,
    [client_ip, request_uri, status, response_time, service]
  );
}

export default db;
