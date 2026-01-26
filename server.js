// server.js
require("dotenv").config();
const path = require("path");
const express = require("express");
const helmet = require("helmet");
const cookieParser = require("cookie-parser");
const rateLimit = require("express-rate-limit");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const db = require("./db");

const app = express();

app.use(helmet()); // Express security best practice :contentReference[oaicite:5]{index=5}
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 120, // مناسب كبداية
});
app.use(limiter);

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  throw new Error("JWT_SECRET is missing in .env");
}

function signAdminToken() {
  return jwt.sign({ role: "admin" }, JWT_SECRET, { expiresIn: "8h" });
}

function requireAdmin(req, res, next) {
  const token = req.cookies?.admin_token;
  if (!token) return res.status(401).json({ error: "Unauthorized" });

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload.role !== "admin") return res.status(403).json({ error: "Forbidden" });
    next();
  } catch (e) {
    return res.status(401).json({ error: "Invalid/Expired token" });
  }
}

// -------------------- Public APIs --------------------

// Add scrim (public)
app.post("/api/scrims", (req, res) => {
  const { title, game = "PUBG", mode, date, time, organizer, contact, notes } = req.body || {};

  if (!title || !mode || !date || !time || !organizer) {
    return res.status(400).json({ error: "Missing required fields" });
  }

  const stmt = db.prepare(`
    INSERT INTO scrims (title, game, mode, date, time, organizer, contact, notes)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `);
  const info = stmt.run(title.trim(), game.trim(), mode.trim(), date.trim(), time.trim(), organizer.trim(), (contact || "").trim(), (notes || "").trim());

  return res.json({ ok: true, id: info.lastInsertRowid });
});

// List scrims (public)
app.get("/api/scrims", (req, res) => {
  const rows = db.prepare(`SELECT * FROM scrims ORDER BY id DESC LIMIT 200`).all();
  res.json(rows);
});

// -------------------- Admin APIs --------------------

app.post("/api/admin/login", async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: "Missing credentials" });

  // Admin creds from env (بس الأفضل لاحقًا تخزينه في DB)
  const envUser = process.env.ADMIN_USER || "admin";
  const envPass = process.env.ADMIN_PASS || "change_this_password";

  // بنعمل hash في runtime للمقارنة بشكل آمن
  // (للإنتاج: خزّن hash جاهز بدل النص الصريح)
  const hash = await bcrypt.hash(envPass, 12); // OWASP recommends strong password hashing like bcrypt :contentReference[oaicite:6]{index=6}
  const okUser = username === envUser;
  const okPass = await bcrypt.compare(password, hash);

  if (!okUser || !okPass) return res.status(401).json({ error: "Invalid login" });

  const token = signAdminToken();

  // HttpOnly cookie: recommended to reduce token theft via XSS :contentReference[oaicite:7]{index=7}
  res.cookie("admin_token", token, {
    httpOnly: true,
    sameSite: "lax",
    secure: false, // في الإنتاج (HTTPS) خليها true
    maxAge: 8 * 60 * 60 * 1000,
  });

  res.json({ ok: true });
});

app.post("/api/admin/logout", (req, res) => {
  res.clearCookie("admin_token");
  res.json({ ok: true });
});

app.get("/api/admin/scrims", requireAdmin, (req, res) => {
  const rows = db.prepare(`SELECT * FROM scrims ORDER BY id DESC`).all();
  res.json(rows);
});

app.put("/api/admin/scrims/:id", requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  const { title, game, mode, date, time, organizer, contact, notes } = req.body || {};

  const existing = db.prepare(`SELECT * FROM scrims WHERE id = ?`).get(id);
  if (!existing) return res.status(404).json({ error: "Not found" });

  db.prepare(`
    UPDATE scrims
    SET title = ?, game = ?, mode = ?, date = ?, time = ?, organizer = ?, contact = ?, notes = ?
    WHERE id = ?
  `).run(
    (title ?? existing.title),
    (game ?? existing.game),
    (mode ?? existing.mode),
    (date ?? existing.date),
    (time ?? existing.time),
    (organizer ?? existing.organizer),
    (contact ?? existing.contact),
    (notes ?? existing.notes),
    id
  );

  res.json({ ok: true });
});

app.delete("/api/admin/scrims/:id", requireAdmin, (req, res) => {
  const id = Number(req.params.id);
  db.prepare(`DELETE FROM scrims WHERE id = ?`).run(id);
  res.json({ ok: true });
});

app.get("/api/admin/me", requireAdmin, (req, res) => {
  res.json({ ok: true, role: "admin" });
});

// -------------------- Run --------------------
const port = Number(process.env.PORT || 3000);
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
