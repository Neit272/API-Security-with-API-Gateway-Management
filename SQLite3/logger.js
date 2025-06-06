// SQLite3/logger.js
import sqlite3 from 'sqlite3';
const db = new sqlite3.Database('logs.db');

// Tạo bảng nếu chưa có
db.run(`
  CREATE TABLE IF NOT EXISTS kong_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_ip TEXT,
    request_uri TEXT,
    status INTEGER,
    response_time REAL,
    service TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`);

export function saveLog(data) {
  const { client_ip, request_uri, status, response_time, service } = data;
  db.run(`
    INSERT INTO kong_logs (client_ip, request_uri, status, response_time, service)
    VALUES (?, ?, ?, ?, ?)`,
    [client_ip, request_uri, status, response_time, service]
  );
}
