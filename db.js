// db.js
const Database = require("better-sqlite3");

const db = new Database("data.sqlite");

// scrims table
db.exec(`
CREATE TABLE IF NOT EXISTS scrims (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  game TEXT NOT NULL DEFAULT 'PUBG',
  mode TEXT NOT NULL,
  date TEXT NOT NULL,
  time TEXT NOT NULL,
  organizer TEXT NOT NULL,
  contact TEXT,
  notes TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
`);

module.exports = db;
