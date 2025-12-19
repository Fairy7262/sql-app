const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const path = require('path');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { body, validationResult } = require('express-validator');

const app = express();
const port = 3000;
const JWT_SECRET = 'supersecretkey'; // should be env var in production

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Database setup
const db = new sqlite3.Database('./users.db');

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE,
    password TEXT,
    role TEXT
  )`);

  // Insert sample users (hashed passwords)
  const adminPass = bcrypt.hashSync('password', 10);
  const userPass = bcrypt.hashSync('pass', 10);

  db.run(`INSERT OR IGNORE INTO users (username, password, role) VALUES ('admin', ?, 'admin')`, [adminPass]);
  db.run(`INSERT OR IGNORE INTO users (username, password, role) VALUES ('user', ?, 'user')`, [userPass]);
});


// 🔐 JWT Authentication Middleware
function authenticateJWT(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).send('Token missing');
  const token = authHeader.split(' ')[1];
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).send('Invalid token');
    req.user = user;
    next();
  });
}

// 🔐 Role-Based Access Control Middleware
function authorizeRole(role) {
  return (req, res, next) => {
    if (req.user.role !== role) {
      return res.status(403).send('Access denied');
    }
    next();
  };
}

// Routes
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

//Login with Validation + JWT
app.post(
  '/login',
  body('username').isAlphanumeric().isLength({ min: 3 }),
  body('password').isLength({ min: 4 }),
  (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    const { username, password } = req.body;
    const query = `SELECT * FROM users WHERE username = ?`;
    db.get(query, [username], async (err, user) => {
      if (err) return res.status(500).send('Database error');
      if (!user) return res.status(401).send('Invalid credentials');
      const validPassword = await bcrypt.compare(password, user.password);
      if (!validPassword) return res.status(401).send('Invalid credentials');
      const token = jwt.sign(
        { id: user.id, username: user.username, role: user.role },
        JWT_SECRET,
        { expiresIn: '1h' }
      );
      res.json({ token });
    });
  }
);

// 🔐 Protected dashboard (any authenticated user)
app.get('/dashboard', authenticateJWT, (req, res) => {
  res.send(`Welcome ${req.user.username}`);
});

// 🔐 Admin-only route
app.get('/admin', authenticateJWT, authorizeRole('admin'), (req, res) => {
  res.send('Admin panel');
});

app.listen(port, () => {
  console.log(`Secure server running at http://localhost:${port}`);
});
