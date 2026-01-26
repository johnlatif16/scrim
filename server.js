const express = require("express");
const path = require("path");
const cors = require("cors");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const app = express();

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "secret";
const ADMIN_USER = process.env.ADMIN_USER || "admin";
const ADMIN_PASS = process.env.ADMIN_PASS || "123456";

/**
 * DB بسيط في الذاكرة
 * ⚠️ restart = البيانات تروح
 */
let scrims = [];

function authJWT(req, res, next) {
  const authHeader = req.headers["authorization"];
  if (!authHeader) return res.status(401).json({ error: "Missing token" });

  const token = authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Invalid token format" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.admin = decoded;
    next();
  } catch (e) {
    return res.status(401).json({ error: "Unauthorized token" });
  }
}

// صفحات
app.get("/", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));
app.get("/login", (req, res) => res.sendFile(path.join(__dirname, "public", "login.html")));
app.get("/dashboard", (req, res) => res.sendFile(path.join(__dirname, "public", "dashboard.html")));

// Admin login
app.post("/api/admin/login", (req, res) => {
  const { username, password } = req.body;

  if (username !== ADMIN_USER || password !== ADMIN_PASS) {
    return res.status(401).json({ error: "Wrong username or password" });
  }

  const token = jwt.sign({ role: "admin", username }, JWT_SECRET, { expiresIn: "7d" });
  res.json({ ok: true, token });
});

// Public create scrim
app.post("/api/scrims", (req, res) => {
  const { name, role, teamName, leaderName, leaderId, players } = req.body;

  const allowedRoles = ["Fragger", "Flanker", "Viper", "Support"];
  if (!name || !role || !teamName || !leaderName || !leaderId) {
    return res.status(400).json({ error: "Missing required fields" });
  }
  if (!allowedRoles.includes(String(role))) {
    return res.status(400).json({ error: "Invalid role" });
  }

  const entry = {
    id: Date.now().toString(),
    name: String(name).trim(),
    role: String(role).trim(),
    teamName: String(teamName).trim(),
    leaderName: String(leaderName).trim(),
    leaderId: String(leaderId).trim(),
    players: Array.isArray(players) ? players.map(String) : [],
    createdAt: new Date().toISOString(),
  };

  scrims.unshift(entry);
  res.status(201).json({ ok: true, entry });
});

// Public list
app.get("/api/scrims", (req, res) => {
  res.json({ items: scrims });
});

// Admin list (protected)
app.get("/api/admin/scrims", authJWT, (req, res) => {
  res.json({ items: scrims });
});

// Admin delete (protected)
app.delete("/api/admin/scrims/:id", authJWT, (req, res) => {
  const id = req.params.id;
  scrims = scrims.filter((x) => x.id !== id);
  res.json({ ok: true });
});

// Admin edit (protected)
app.put("/api/admin/scrims/:id", authJWT, (req, res) => {
  const id = req.params.id;
  const idx = scrims.findIndex((x) => x.id === id);
  if (idx === -1) return res.status(404).json({ error: "Not found" });

  const allowedRoles = ["Fragger", "Flanker", "Viper", "Support"];
  const patch = req.body || {};

  if (patch.role && !allowedRoles.includes(String(patch.role))) {
    return res.status(400).json({ error: "Invalid role" });
  }

  // نحدّث الحقول اللي الأدمن يبعته بس
  scrims[idx] = {
    ...scrims[idx],
    ...(patch.name != null ? { name: String(patch.name).trim() } : {}),
    ...(patch.role != null ? { role: String(patch.role).trim() } : {}),
    ...(patch.teamName != null ? { teamName: String(patch.teamName).trim() } : {}),
    ...(patch.leaderName != null ? { leaderName: String(patch.leaderName).trim() } : {}),
    ...(patch.leaderId != null ? { leaderId: String(patch.leaderId).trim() } : {}),
    ...(patch.players != null && Array.isArray(patch.players) ? { players: patch.players.map(String) } : {}),
  };

  res.json({ ok: true, entry: scrims[idx] });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
