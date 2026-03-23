const express = require('express');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'ledger_super_secret_key_2024_change_in_prod';

// Data storage (in production, use a proper database)
let users = [];
let transactions = [];
let categories = [
  { id: 1, name: 'Salary', icon: '💼', type: 'credit' },
  { id: 2, name: 'Freelance', icon: '💻', type: 'credit' },
  { id: 3, name: 'Investment', icon: '📈', type: 'credit' },
  { id: 4, name: 'Rent', icon: '🏠', type: 'debit' },
  { id: 5, name: 'Food & Dining', icon: '🍽️', type: 'debit' },
  { id: 6, name: 'Transport', icon: '🚗', type: 'debit' },
  { id: 7, name: 'Shopping', icon: '🛍️', type: 'debit' },
  { id: 8, name: 'Utilities', icon: '⚡', type: 'debit' },
  { id: 9, name: 'Healthcare', icon: '🏥', type: 'debit' },
  { id: 10, name: 'Entertainment', icon: '🎬', type: 'debit' },
  { id: 11, name: 'Education', icon: '📚', type: 'debit' },
  { id: 12, name: 'Travel', icon: '✈️', type: 'both' },
  { id: 13, name: 'Transfer', icon: '🔄', type: 'both' },
  { id: 14, name: 'Other', icon: '📌', type: 'both' }
];

// Load data from files
const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

const usersFile = path.join(dataDir, 'users.json');
const transactionsFile = path.join(dataDir, 'transactions.json');

if (fs.existsSync(usersFile)) {
  users = JSON.parse(fs.readFileSync(usersFile, 'utf8'));
}
if (fs.existsSync(transactionsFile)) {
  transactions = JSON.parse(fs.readFileSync(transactionsFile, 'utf8'));
}

// Save functions
function saveUsers() {
  fs.writeFileSync(usersFile, JSON.stringify(users, null, 2));
}

function saveTransactions() {
  fs.writeFileSync(transactionsFile, JSON.stringify(transactions, null, 2));
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

  const existing = users.find(u => u.username.toLowerCase() === username.toLowerCase().trim());
  if (existing) return res.status(409).json({ error: 'Username already taken' });

  const hash = bcrypt.hashSync(password, 10);
  const newUser = {
    id: Date.now(),
    username: username.toLowerCase().trim(),
    password_hash: hash,
    full_name: full_name || username,
    created_at: new Date().toISOString()
  };
  users.push(newUser);
  saveUsers();

  const token = jwt.sign({ id: newUser.id, username: newUser.username }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id: newUser.id, username: newUser.username, full_name: newUser.full_name } });
});

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

  const user = users.find(u => u.username === username.toLowerCase().trim());
  if (!user || !bcrypt.compareSync(password, user.password_hash))
    return res.status(401).json({ error: 'Invalid credentials' });

  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id: user.id, username: user.username, full_name: user.full_name } });
});

// ── CATEGORY ROUTES ──────────────────────────────────────────────────────────
app.get('/api/categories', authMiddleware, (req, res) => {
  res.json(categories);
});

// ── TRANSACTION ROUTES ───────────────────────────────────────────────────────
app.get('/api/transactions', authMiddleware, (req, res) => {
  const { type, category_id, reference, from_date, to_date, search, limit = 100, offset = 0 } = req.query;

  let filtered = transactions.filter(t => t.user_id === req.user.id);

  if (type) filtered = filtered.filter(t => t.type === type);
  if (category_id) filtered = filtered.filter(t => t.category_id == category_id);
  if (reference) filtered = filtered.filter(t => t.reference && t.reference.toLowerCase().includes(reference.toLowerCase()));
  if (from_date) filtered = filtered.filter(t => t.date >= from_date);
  if (to_date) filtered = filtered.filter(t => t.date <= to_date);
  if (search) {
    const searchLower = search.toLowerCase();
    filtered = filtered.filter(t =>
      t.description.toLowerCase().includes(searchLower) ||
      (t.note && t.note.toLowerCase().includes(searchLower)) ||
      (t.reference && t.reference.toLowerCase().includes(searchLower))
    );
  }

  // Sort by date desc, then created_at desc
  filtered.sort((a, b) => {
    if (a.date !== b.date) return b.date.localeCompare(a.date);
    return b.created_at.localeCompare(a.created_at);
  });

  const total = filtered.length;
  const paginated = filtered.slice(Number(offset), Number(offset) + Number(limit));

  // Add category info
  const result = paginated.map(t => {
    const category = categories.find(c => c.id == t.category_id);
    return {
      ...t,
      category_name: category ? category.name : null,
      category_icon: category ? category.icon : null
    };
  });

  res.json({ transactions: result, total });
});

app.post('/api/transactions', authMiddleware, (req, res) => {
  const { type, amount, description, category_id, reference, note, date, linked_ids } = req.body;
  if (!type || !amount || !description || !date) return res.status(400).json({ error: 'type, amount, description, date are required' });
  if (!['debit', 'credit'].includes(type)) return res.status(400).json({ error: 'type must be debit or credit' });
  if (amount <= 0) return res.status(400).json({ error: 'amount must be positive' });

  const newTransaction = {
    id: Date.now(),
    user_id: req.user.id,
    type,
    amount: parseFloat(amount),
    description,
    category_id: category_id || null,
    reference: reference || null,
    note: note || null,
    date,
    created_at: new Date().toISOString()
  };

  transactions.push(newTransaction);
  saveTransactions();

  const category = categories.find(c => c.id == newTransaction.category_id);
  const result = {
    ...newTransaction,
    category_name: category ? category.name : null,
    category_icon: category ? category.icon : null
  };

  res.json(result);
});

app.put('/api/transactions/:id', authMiddleware, (req, res) => {
  const { type, amount, description, category_id, reference, note, date } = req.body;
  const txnIndex = transactions.findIndex(t => t.id == req.params.id && t.user_id === req.user.id);
  if (txnIndex === -1) return res.status(404).json({ error: 'Transaction not found' });

  const txn = transactions[txnIndex];
  const updated = {
    ...txn,
    type: type || txn.type,
    amount: amount ? parseFloat(amount) : txn.amount,
    description: description || txn.description,
    category_id: category_id !== undefined ? category_id : txn.category_id,
    reference: reference !== undefined ? reference : txn.reference,
    note: note !== undefined ? note : txn.note,
    date: date || txn.date
  };

  transactions[txnIndex] = updated;
  saveTransactions();

  const category = categories.find(c => c.id == updated.category_id);
  res.json({
    ...updated,
    category_name: category ? category.name : null,
    category_icon: category ? category.icon : null
  });
});

app.delete('/api/transactions/:id', authMiddleware, (req, res) => {
  const txnIndex = transactions.findIndex(t => t.id == req.params.id && t.user_id === req.user.id);
  if (txnIndex === -1) return res.status(404).json({ error: 'Transaction not found' });

  transactions.splice(txnIndex, 1);
  saveTransactions();
  res.json({ success: true });
});

// ── SUMMARY / ANALYTICS ──────────────────────────────────────────────────────
app.get('/api/summary', authMiddleware, (req, res) => {
  const { month, year } = req.query;

  let filtered = transactions.filter(t => t.user_id === req.user.id);

  if (month && year) {
    filtered = filtered.filter(t => {
      const d = new Date(t.date);
      return d.getFullYear() == year && d.getMonth() + 1 == month;
    });
  } else if (year) {
    filtered = filtered.filter(t => new Date(t.date).getFullYear() == year);
  }

  const totals = filtered.reduce((acc, t) => {
    acc.total_credit += t.type === 'credit' ? t.amount : 0;
    acc.total_debit += t.type === 'debit' ? t.amount : 0;
    acc.total_transactions += 1;
    return acc;
  }, { total_credit: 0, total_debit: 0, total_transactions: 0 });

  const byCategory = {};
  filtered.forEach(t => {
    const cat = categories.find(c => c.id == t.category_id) || { name: 'Uncategorized', icon: '📌' };
    const key = `${cat.name}|${t.type}`;
    if (!byCategory[key]) {
      byCategory[key] = { name: cat.name, icon: cat.icon, type: t.type, total: 0, count: 0 };
    }
    byCategory[key].total += t.amount;
    byCategory[key].count += 1;
  });

  const monthly = {};
  transactions.filter(t => t.user_id === req.user.id).forEach(t => {
    const monthKey = t.date.substring(0, 7); // YYYY-MM
    if (!monthly[monthKey]) monthly[monthKey] = { month: monthKey, credit: 0, debit: 0 };
    monthly[monthKey][t.type] += t.amount;
  });

  const recentTransactions = filtered
    .sort((a, b) => b.date.localeCompare(a.date) || b.created_at.localeCompare(a.created_at))
    .slice(0, 5)
    .map(t => {
      const category = categories.find(c => c.id == t.category_id);
      return {
        ...t,
        category_name: category ? category.name : null,
        category_icon: category ? category.icon : null
      };
    });

  res.json({
    ...totals,
    balance: totals.total_credit - totals.total_debit,
    by_category: Object.values(byCategory).sort((a, b) => b.total - a.total),
    monthly: Object.values(monthly).sort((a, b) => b.month.localeCompare(a.month)),
    recent: recentTransactions
  });
});

// Catch-all for SPA
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => console.log(`Ledger App running on port ${PORT}`));
