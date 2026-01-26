const express = require("express");
const path = require("path");
const cors = require("cors");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// Env
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "secret";
const ADMIN_USER = process.env.ADMIN_USER || "admin";
const ADMIN_PASS = process.env.ADMIN_PASS || "123456";

// In-memory DB (Restart => data lost)
let scrims = []; // {id, name, role, createdAt}

// Helpers
const allowedRoles = ["Fragger", "Flanker", "Viper", "Support"];

function cleanString(v) {
  return String(v ?? "").trim();
}

function makeId() {
  // يقلل احتمالية تكرار الـ id لو اتعملت requests بسرعة
  return `${Date.now()}_${Math.random().toString(16).slice(2)}`;
}

function authJWT(req, res, next) {
  const authHeader = req.headers["authorization"];
  if (!authHeader) return res.status(401).json({ error: "Missing token" });

  const parts = authHeader.split(" ");
  if (parts.length !== 2 || parts[0] !== "Bearer")
    return res.status(401).json({ error: "Invalid token format" });

  const token = parts[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (!decoded || decoded.role !== "admin") {
      return res.status(401).json({ error: "Unauthorized token" });
    }
    req.admin = decoded;
    next();
  } catch (e) {
    return res.status(401).json({ error: "Unauthorized token" });
  }
}

// Pages (optional لأن express.static كافي، بس نخليه واضح)
app.get("/", (req, res) =>
  res.sendFile(path.join(__dirname, "public", "index.html"))
);
app.get("/login", (req, res) =>
  res.sendFile(path.join(__dirname, "public", "login.html"))
);
app.get("/dashboard", (req, res) =>
  res.sendFile(path.join(__dirname, "public", "dashboard.html"))
);

// ======================
// Admin Auth
// ======================
app.post("/api/admin/login", (req, res) => {
  const username = cleanString(req.body?.username);
  const password = cleanString(req.body?.password);

  if (username !== ADMIN_USER || password !== ADMIN_PASS) {
    return res.status(401).json({ error: "Wrong username or password" });
  }

  const token = jwt.sign({ role: "admin", username }, JWT_SECRET, {
    expiresIn: "7d",
  });

  res.json({ ok: true, token });
});

// ======================
// Public: Create + List
// ======================
app.post("/api/scrims", (req, res) => {
  const name = cleanString(req.body?.name);
  const role = cleanString(req.body?.role);

  if (!name || !role) {
    return res.status(400).json({ error: "Missing required fields" });
  }
  if (!allowedRoles.includes(role)) {
    return res.status(400).json({ error: "Invalid role" });
  }

  // (اختياري) منع تكرار نفس الاسم (Case-insensitive)
  const exists = scrims.some(
    (x) => x.name.toLowerCase() === name.toLowerCase()
  );
  if (exists) {
    return res.status(409).json({ error: "Name already registered" });
  }

  const entry = {
    id: makeId(),
    name,
    role,
    createdAt: new Date().toISOString(),
  };

  scrims.unshift(entry);
  return res.status(201).json({ ok: true, entry });
});

app.get("/api/scrims", (req, res) => {
  res.json({ items: scrims });
});

// ======================
// Admin: List / Edit / Delete (Protected)
// ======================
app.get("/api/admin/scrims", authJWT, (req, res) => {
  res.json({ items: scrims });
});

app.put("/api/admin/scrims/:id", authJWT, (req, res) => {
  const id = req.params.id;
  const idx = scrims.findIndex((x) => x.id === id);
  if (idx === -1) return res.status(404).json({ error: "Not found" });

  const name = req.body?.name != null ? cleanString(req.body.name) : null;
  const role = req.body?.role != null ? cleanString(req.body.role) : null;

  if (name !== null && !name) {
    return res.status(400).json({ error: "Invalid name" });
  }
  if (role !== null && !allowedRoles.includes(role)) {
    return res.status(400).json({ error: "Invalid role" });
  }

  // لو الأدمن غيّر الاسم: (اختياري) منع تكرار الاسم
  if (name !== null) {
    const exists = scrims.some(
      (x, i) => i !== idx && x.name.toLowerCase() === name.toLowerCase()
    );
    if (exists) {
      return res.status(409).json({ error: "Name already registered" });
    }
  }

  scrims[idx] = {
    ...scrims[idx],
    ...(name !== null ? { name } : {}),
    ...(role !== null ? { role } : {}),
  };

  res.json({ ok: true, entry: scrims[idx] });
});

app.delete("/api/admin/scrims/:id", authJWT, (req, res) => {
  const id = req.params.id;
  const before = scrims.length;
  scrims = scrims.filter((x) => x.id !== id);

  if (scrims.length === before) {
    return res.status(404).json({ error: "Not found" });
  }

  res.json({ ok: true });
});

// ======================
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
