const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'ledger_super_secret_key_2024_change_in_prod';

// Ensure data directory exists
const dataDir = '/app/data';
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

// Init SQLite DB
const db = new Database(path.join(dataDir, 'ledger.db'));

// Create tables
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    full_name TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS categories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    icon TEXT DEFAULT '📁',
    type TEXT DEFAULT 'both'
  );

  CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    type TEXT NOT NULL CHECK(type IN ('debit','credit')),
    amount REAL NOT NULL,
    description TEXT NOT NULL,
    category_id INTEGER,
    reference TEXT,
    note TEXT,
    date TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (category_id) REFERENCES categories(id)
  );

  CREATE TABLE IF NOT EXISTS transaction_links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    transaction_id INTEGER NOT NULL,
    linked_transaction_id INTEGER NOT NULL,
    FOREIGN KEY (transaction_id) REFERENCES transactions(id),
    FOREIGN KEY (linked_transaction_id) REFERENCES transactions(id)
  );
`);

// Seed default categories if empty
const catCount = db.prepare('SELECT COUNT(*) as c FROM categories').get();
if (catCount.c === 0) {
  const insertCat = db.prepare('INSERT INTO categories (name, icon, type) VALUES (?, ?, ?)');
  const cats = [
    ['Salary', '💼', 'credit'], ['Freelance', '💻', 'credit'], ['Investment', '📈', 'credit'],
    ['Rent', '🏠', 'debit'], ['Food & Dining', '🍽️', 'debit'], ['Transport', '🚗', 'debit'],
    ['Shopping', '🛍️', 'debit'], ['Utilities', '⚡', 'debit'], ['Healthcare', '🏥', 'debit'],
    ['Entertainment', '🎬', 'debit'], ['Education', '📚', 'debit'], ['Travel', '✈️', 'both'],
    ['Transfer', '🔄', 'both'], ['Other', '📌', 'both']
  ];
  cats.forEach(c => insertCat.run(...c));
}

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Auth Middleware
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer '))
    return res.status(401).json({ error: 'Unauthorized' });
  try {
    const token = authHeader.split(' ')[1];
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// ── AUTH ROUTES ──────────────────────────────────────────────────────────────
app.post('/api/auth/register', (req, res) => {
  const { username, password, full_name } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });

  const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username.toLowerCase().trim());
  if (existing) return res.status(409).json({ error: 'Username already taken' });

  const hash = bcrypt.hashSync(password, 10);
  const result = db.prepare('INSERT INTO users (username, password_hash, full_name) VALUES (?, ?, ?)').run(
    username.toLowerCase().trim(), hash, full_name || username
  );
  const token = jwt.sign({ id: result.lastInsertRowid, username: username.toLowerCase().trim() }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id: result.lastInsertRowid, username, full_name: full_name || username } });
});

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username.toLowerCase().trim());
  if (!user || !bcrypt.compareSync(password, user.password_hash))
    return res.status(401).json({ error: 'Invalid credentials' });

  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id: user.id, username: user.username, full_name: user.full_name } });
});

// ── CATEGORY ROUTES ──────────────────────────────────────────────────────────
app.get('/api/categories', authMiddleware, (req, res) => {
  const cats = db.prepare('SELECT * FROM categories ORDER BY name').all();
  res.json(cats);
});

// ── TRANSACTION ROUTES ───────────────────────────────────────────────────────
app.get('/api/transactions', authMiddleware, (req, res) => {
  const { type, category_id, reference, from_date, to_date, search, limit = 100, offset = 0 } = req.query;
  let query = `
    SELECT t.*, c.name as category_name, c.icon as category_icon
    FROM transactions t
    LEFT JOIN categories c ON t.category_id = c.id
    WHERE t.user_id = ?
  `;
  const params = [req.user.id];

  if (type) { query += ' AND t.type = ?'; params.push(type); }
  if (category_id) { query += ' AND t.category_id = ?'; params.push(category_id); }
  if (reference) { query += ' AND t.reference LIKE ?'; params.push(`%${reference}%`); }
  if (from_date) { query += ' AND t.date >= ?'; params.push(from_date); }
  if (to_date) { query += ' AND t.date <= ?'; params.push(to_date); }
  if (search) { query += ' AND (t.description LIKE ? OR t.note LIKE ? OR t.reference LIKE ?)'; params.push(`%${search}%`, `%${search}%`, `%${search}%`); }

  query += ' ORDER BY t.date DESC, t.created_at DESC LIMIT ? OFFSET ?';
  params.push(Number(limit), Number(offset));

  const transactions = db.prepare(query).all(...params);
  const countQuery = query.replace(/SELECT t\.\*, c\.name as category_name, c\.icon as category_icon/, 'SELECT COUNT(*) as total').replace(/ORDER BY.*/, '');

  res.json({ transactions, total: db.prepare(countQuery).get(...params.slice(0, -2)).total });
});

app.post('/api/transactions', authMiddleware, (req, res) => {
  const { type, amount, description, category_id, reference, note, date, linked_ids } = req.body;
  if (!type || !amount || !description || !date) return res.status(400).json({ error: 'type, amount, description, date are required' });
  if (!['debit', 'credit'].includes(type)) return res.status(400).json({ error: 'type must be debit or credit' });
  if (amount <= 0) return res.status(400).json({ error: 'amount must be positive' });

  const result = db.prepare(`
    INSERT INTO transactions (user_id, type, amount, description, category_id, reference, note, date)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).run(req.user.id, type, parseFloat(amount), description, category_id || null, reference || null, note || null, date);

  const txnId = result.lastInsertRowid;

  // Link related transactions
  if (linked_ids && Array.isArray(linked_ids) && linked_ids.length > 0) {
    const linkStmt = db.prepare('INSERT OR IGNORE INTO transaction_links (transaction_id, linked_transaction_id) VALUES (?, ?)');
    linked_ids.forEach(lid => {
      linkStmt.run(txnId, lid);
      linkStmt.run(lid, txnId);
    });
  }

  const txn = db.prepare(`
    SELECT t.*, c.name as category_name, c.icon as category_icon
    FROM transactions t LEFT JOIN categories c ON t.category_id = c.id WHERE t.id = ?
  `).get(txnId);

  res.json(txn);
});

app.put('/api/transactions/:id', authMiddleware, (req, res) => {
  const { type, amount, description, category_id, reference, note, date } = req.body;
  const txn = db.prepare('SELECT * FROM transactions WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!txn) return res.status(404).json({ error: 'Transaction not found' });

  db.prepare(`
    UPDATE transactions SET type=?, amount=?, description=?, category_id=?, reference=?, note=?, date=?
    WHERE id = ? AND user_id = ?
  `).run(
    type || txn.type, parseFloat(amount) || txn.amount, description || txn.description,
    category_id !== undefined ? category_id : txn.category_id,
    reference !== undefined ? reference : txn.reference,
    note !== undefined ? note : txn.note,
    date || txn.date, req.params.id, req.user.id
  );

  const updated = db.prepare(`
    SELECT t.*, c.name as category_name, c.icon as category_icon
    FROM transactions t LEFT JOIN categories c ON t.category_id = c.id WHERE t.id = ?
  `).get(req.params.id);
  res.json(updated);
});

app.delete('/api/transactions/:id', authMiddleware, (req, res) => {
  const txn = db.prepare('SELECT * FROM transactions WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!txn) return res.status(404).json({ error: 'Transaction not found' });
  db.prepare('DELETE FROM transaction_links WHERE transaction_id = ? OR linked_transaction_id = ?').run(req.params.id, req.params.id);
  db.prepare('DELETE FROM transactions WHERE id = ? AND user_id = ?').run(req.params.id, req.user.id);
  res.json({ success: true });
});

// Get linked transactions for a given transaction
app.get('/api/transactions/:id/links', authMiddleware, (req, res) => {
  const txn = db.prepare('SELECT * FROM transactions WHERE id = ? AND user_id = ?').get(req.params.id, req.user.id);
  if (!txn) return res.status(404).json({ error: 'Transaction not found' });

  const links = db.prepare(`
    SELECT t.*, c.name as category_name, c.icon as category_icon
    FROM transaction_links tl
    JOIN transactions t ON t.id = tl.linked_transaction_id
    LEFT JOIN categories c ON t.category_id = c.id
    WHERE tl.transaction_id = ? AND t.user_id = ?
  `).all(req.params.id, req.user.id);
  res.json(links);
});

// ── SUMMARY / ANALYTICS ──────────────────────────────────────────────────────
app.get('/api/summary', authMiddleware, (req, res) => {
  const { month, year } = req.query;
  let dateFilter = '';
  const params = [req.user.id];

  if (month && year) {
    dateFilter = `AND strftime('%Y-%m', date) = ?`;
    params.push(`${year}-${String(month).padStart(2, '0')}`);
  } else if (year) {
    dateFilter = `AND strftime('%Y', date) = ?`;
    params.push(year);
  }

  const totals = db.prepare(`
    SELECT
      COALESCE(SUM(CASE WHEN type='credit' THEN amount ELSE 0 END), 0) as total_credit,
      COALESCE(SUM(CASE WHEN type='debit' THEN amount ELSE 0 END), 0) as total_debit,
      COUNT(*) as total_transactions
    FROM transactions WHERE user_id = ? ${dateFilter}
  `).get(...params);

  const byCategory = db.prepare(`
    SELECT c.name, c.icon, t.type,
      SUM(t.amount) as total, COUNT(*) as count
    FROM transactions t
    LEFT JOIN categories c ON t.category_id = c.id
    WHERE t.user_id = ? ${dateFilter}
    GROUP BY t.category_id, t.type
    ORDER BY total DESC
  `).all(...params);

  const monthly = db.prepare(`
    SELECT strftime('%Y-%m', date) as month,
      SUM(CASE WHEN type='credit' THEN amount ELSE 0 END) as credit,
      SUM(CASE WHEN type='debit' THEN amount ELSE 0 END) as debit
    FROM transactions WHERE user_id = ?
    GROUP BY month ORDER BY month DESC LIMIT 12
  `).all(req.user.id);

  const recentTransactions = db.prepare(`
    SELECT t.*, c.name as category_name, c.icon as category_icon
    FROM transactions t LEFT JOIN categories c ON t.category_id = c.id
    WHERE t.user_id = ? ${dateFilter}
    ORDER BY t.date DESC LIMIT 5
  `).all(...params);

  res.json({
    ...totals,
    balance: totals.total_credit - totals.total_debit,
    by_category: byCategory,
    monthly,
    recent: recentTransactions
  });
});

// Catch-all for SPA
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => console.log(`Ledger App running on port ${PORT}`));
