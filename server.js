
const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const rateLimit = require("express-rate-limit");
const path = require("path");

const app = express();
app.set("trust proxy", 1);
app.use(express.json({ limit: "100kb" }));

const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET;
const ADMIN_EMAIL = process.env.ADMIN_EMAIL;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

if (!SECRET || !ADMIN_EMAIL || !ADMIN_PASSWORD) {
  throw new Error("JWT_SECRET, ADMIN_EMAIL and ADMIN_PASSWORD are required");
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL &&
       !/localhost|127\.0\.0\.1/.test(process.env.DATABASE_URL)
       ? { rejectUnauthorized: false }
       : false
});

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS admins (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS gallery (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      category TEXT DEFAULT 'Wood Carving',
      image_url TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS enquiries (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      phone TEXT NOT NULL,
      design TEXT NOT NULL,
      message TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS services (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      description TEXT DEFAULT '',
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);

  const email = ADMIN_EMAIL.toLowerCase().trim();
  const existing = await pool.query(
    "SELECT id FROM admins WHERE email=$1",
    [email]
  );

  if (!existing.rowCount) {
    const hash = await bcrypt.hash(ADMIN_PASSWORD, 12);
    await pool.query(
      "INSERT INTO admins(email,password) VALUES($1,$2)",
      [email, hash]
    );
  }

  console.log("Database connected and initialized");
}

function auth(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "Login required" });
  }

  try {
    req.admin = jwt.verify(token, SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Invalid or expired login" });
  }
}

const loginLimit = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: true,
  legacyHeaders: false
});

app.get("/api/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ ok: true, database: "connected" });
  } catch {
    res.status(503).json({ ok: false, database: "disconnected" });
  }
});

// Admin login
app.post("/api/login", loginLimit, async (req, res) => {
  try {
    const email = String(req.body.email || "").toLowerCase().trim();
    const password = String(req.body.password || "");

    const result = await pool.query(
      "SELECT * FROM admins WHERE email=$1",
      [email]
    );

    if (!result.rowCount ||
        !(await bcrypt.compare(password, result.rows[0].password))) {
      return res.status(401).json({ error: "Wrong email or password" });
    }

    const token = jwt.sign(
      { id: result.rows[0].id, email },
      SECRET,
      { expiresIn: "12h" }
    );

    res.json({ token, message: "Login successful" });
  } catch {
    res.status(500).json({ error: "Login failed" });
  }
});

// Public gallery
app.get("/api/gallery", async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM gallery ORDER BY created_at DESC"
    );
    res.json(result.rows);
  } catch {
    res.status(500).json({ error: "Gallery loading failed" });
  }
});

// Add gallery image
app.post("/api/gallery", auth, async (req, res) => {
  try {
    const { title, category, image_url } = req.body;

    if (!title || !image_url ||
        !/^https:\/\//i.test(image_url) ||
        image_url.length > 2000) {
      return res.status(400).json({ error: "Valid title and HTTPS image URL required" });
    }

    const result = await pool.query(
      `INSERT INTO gallery(title,category,image_url)
       VALUES($1,$2,$3) RETURNING *`,
      [title.slice(0,120), String(category || "Wood Carving").slice(0,80), image_url]
    );

    res.json(result.rows[0]);
  } catch {
    res.status(500).json({ error: "Image could not be added" });
  }
});

// Delete gallery image
app.delete("/api/gallery/:id", auth, async (req, res) => {
  try {
    const result = await pool.query(
      "DELETE FROM gallery WHERE id=$1 RETURNING id",
      [req.params.id]
    );

    if (!result.rowCount) {
      return res.status(404).json({ error: "Image not found" });
    }

    res.json({ message: "Image deleted" });
  } catch {
    res.status(500).json({ error: "Delete failed" });
  }
});

// Customer enquiry
app.post("/api/enquiries", loginLimit, async (req, res) => {
  try {
    const name = String(req.body.name || "").trim();
    const phone = String(req.body.phone || "").trim();
    const design = String(req.body.design || "").trim();
    const message = String(req.body.message || "").trim();

    if (!name || name.length > 100 ||
        !/^[0-9]{10}$/.test(phone) ||
        !design || design.length > 150 ||
        message.length > 2000) {
      return res.status(400).json({ error: "Please enter valid details" });
    }

    const result = await pool.query(
      `INSERT INTO enquiries(name,phone,design,message)
       VALUES($1,$2,$3,$4) RETURNING id`,
      [name, phone, design, message]
    );

    res.json({
      message: "Enquiry submitted successfully",
      id: result.rows[0].id
    });
  } catch {
    res.status(500).json({ error: "Enquiry submission failed" });
  }
});

// Admin: see customer enquiries
app.get("/api/enquiries", auth, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM enquiries ORDER BY created_at DESC"
    );
    res.json(result.rows);
  } catch {
    res.status(500).json({ error: "Could not load enquiries" });
  }
});

// Public services
app.get("/api/services", async (req, res) => {
  const result = await pool.query(
    "SELECT * FROM services ORDER BY id DESC"
  );
  res.json(result.rows);
});

// Admin: add service
app.post("/api/services", auth, async (req, res) => {
  try {
    const title = String(req.body.title || "").trim();
    const description = String(req.body.description || "").trim();

    if (!title || title.length > 120 || description.length > 1000) {
      return res.status(400).json({ error: "Invalid service details" });
    }

    const result = await pool.query(
      "INSERT INTO services(title,description) VALUES($1,$2) RETURNING *",
      [title, description]
    );
    res.json(result.rows[0]);
  } catch {
    res.status(500).json({ error: "Service could not be added" });
  }
});

app.delete("/api/services/:id", auth, async (req, res) => {
  try {
    await pool.query("DELETE FROM services WHERE id=$1", [req.params.id]);
    res.json({ message: "Service deleted" });
  } catch {
    res.status(500).json({ error: "Delete failed" });
  }
});

// Serve frontend
app.use(express.static(path.join(__dirname, "public")));

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

initDB()
  .then(() => {
    app.listen(PORT, "0.0.0.0", () => {
      console.log("Rajkumar Wood Carving server running on " + PORT);
    });
  })
  .catch(error => {
    console.error("Server startup failed:", error);
    process.exit(1);
  });
