const express = require("express");
const path = require("path");
const cors = require("cors");
const jwt = require("jsonwebtoken");
require("dotenv").config();

// Firebase Admin (Firestore)
const { initializeApp, cert, getApps } = require("firebase-admin/app");
const { getFirestore, FieldValue } = require("firebase-admin/firestore");

const app = express();

// -------------------- Middleware --------------------
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// -------------------- Env --------------------
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "secret";
const ADMIN_USER = process.env.ADMIN_USER || "admin";
const ADMIN_PASS = process.env.ADMIN_PASS || "123456";

// -------------------- Firestore Init --------------------
function loadServiceAccountFromEnv() {
  const raw = process.env.FIREBASE_CONFIG;
  if (!raw) throw new Error("Missing FIREBASE_CONFIG in .env");

  const svc = JSON.parse(raw);

  // Fix newline escapes in private_key if stored as \n in env
  if (svc.private_key && typeof svc.private_key === "string") {
    svc.private_key = svc.private_key.replace(/\\n/g, "\n");
  }

  return svc;
}

if (!getApps().length) {
  const serviceAccount = loadServiceAccountFromEnv();
  initializeApp({ credential: cert(serviceAccount) });
}

const db = getFirestore();
const scrimsCol = db.collection("scrims");

// -------------------- Helpers --------------------
const allowedRoles = ["Fragger", "Flanker", "Viper", "Support"];

function cleanString(v) {
  return String(v ?? "").trim();
}

function authJWT(req, res, next) {
  const authHeader = req.headers["authorization"];
  if (!authHeader) return res.status(401).json({ error: "Missing token" });

  const parts = authHeader.split(" ");
  if (parts.length !== 2 || parts[0] !== "Bearer") {
    return res.status(401).json({ error: "Invalid token format" });
  }

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

function toIso(ts) {
  try {
    if (ts && typeof ts.toDate === "function") return ts.toDate().toISOString();
  } catch {}
  return new Date().toISOString();
}

// -------------------- Pages (Optional) --------------------
app.get("/", (req, res) =>
  res.sendFile(path.join(__dirname, "public", "index.html"))
);
app.get("/login", (req, res) =>
  res.sendFile(path.join(__dirname, "public", "login.html"))
);
app.get("/dashboard", (req, res) =>
  res.sendFile(path.join(__dirname, "public", "dashboard.html"))
);

// ==================== Admin Login (JWT) ====================
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

// ==================== Public: Create (name + role) ====================
app.post("/api/scrims", async (req, res) => {
  try {
    const name = cleanString(req.body?.name);
    const role = cleanString(req.body?.role);

    if (!name || !role) {
      return res.status(400).json({ error: "Missing required fields" });
    }
    if (!allowedRoles.includes(role)) {
      return res.status(400).json({ error: "Invalid role" });
    }

    // Optional: prevent duplicate name (case-insensitive)
    const dupSnap = await scrimsCol
      .where("nameLower", "==", name.toLowerCase())
      .limit(1)
      .get();

    if (!dupSnap.empty) {
      return res.status(409).json({ error: "Name already registered" });
    }

    const docRef = await scrimsCol.add({
      name,
      nameLower: name.toLowerCase(),
      role,
      createdAt: FieldValue.serverTimestamp(),
    });

    // Return a consistent shape
    res.status(201).json({
      ok: true,
      entry: { id: docRef.id, name, role, createdAt: new Date().toISOString() },
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Server error" });
  }
});

// ==================== Public: List ====================
app.get("/api/scrims", async (req, res) => {
  try {
    const snap = await scrimsCol.orderBy("createdAt", "desc").limit(500).get();
    const items = snap.docs.map((d) => {
      const data = d.data();
      return {
        id: d.id,
        name: data.name,
        role: data.role,
        createdAt: toIso(data.createdAt),
      };
    });
    res.json({ items });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Server error" });
  }
});

// ==================== Admin: List (Protected) ====================
app.get("/api/admin/scrims", authJWT, async (req, res) => {
  try {
    const snap = await scrimsCol.orderBy("createdAt", "desc").limit(1000).get();
    const items = snap.docs.map((d) => {
      const data = d.data();
      return {
        id: d.id,
        name: data.name,
        role: data.role,
        createdAt: toIso(data.createdAt),
      };
    });
    res.json({ items });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Server error" });
  }
});

// ==================== Admin: Edit (Protected) ====================
app.put("/api/admin/scrims/:id", authJWT, async (req, res) => {
  try {
    const id = req.params.id;

    const docRef = scrimsCol.doc(id);
    const snap = await docRef.get();
    if (!snap.exists) return res.status(404).json({ error: "Not found" });

    const name =
      req.body?.name != null ? cleanString(req.body.name) : null;
    const role =
      req.body?.role != null ? cleanString(req.body.role) : null;

    if (name !== null && !name) {
      return res.status(400).json({ error: "Invalid name" });
    }
    if (role !== null && !allowedRoles.includes(role)) {
      return res.status(400).json({ error: "Invalid role" });
    }

    // Optional: prevent duplicate if name changes
    if (name !== null) {
      const dupSnap = await scrimsCol
        .where("nameLower", "==", name.toLowerCase())
        .limit(1)
        .get();

      const dupDoc = dupSnap.docs[0];
      if (dupDoc && dupDoc.id !== id) {
        return res.status(409).json({ error: "Name already registered" });
      }
    }

    const patch = {};
    if (name !== null) {
      patch.name = name;
      patch.nameLower = name.toLowerCase();
    }
    if (role !== null) patch.role = role;

    await docRef.update(patch);

    const merged = { ...snap.data(), ...patch };
    res.json({
      ok: true,
      entry: {
        id,
        name: merged.name,
        role: merged.role,
        createdAt: toIso(merged.createdAt),
      },
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Server error" });
  }
});

// ==================== Admin: Delete (Protected) ====================
app.delete("/api/admin/scrims/:id", authJWT, async (req, res) => {
  try {
    const id = req.params.id;

    const docRef = scrimsCol.doc(id);
    const snap = await docRef.get();
    if (!snap.exists) return res.status(404).json({ error: "Not found" });

    await docRef.delete();
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Server error" });
  }
});

// -------------------- Start --------------------
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
