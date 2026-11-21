import 'dotenv/config';
import express from 'express';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

if (!ADMIN_PASSWORD) {
  console.error('FATAL: ADMIN_PASSWORD is not set in environment variables');
  process.exit(1);
}

app.use(express.json({ limit: '2mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const db = new DatabaseSync(path.join(__dirname, 'kavexro.db'));
db.exec('PRAGMA journal_mode = WAL;');
db.exec('PRAGMA foreign_keys = ON;');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'buyer',
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS listings (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    roblox_username TEXT NOT NULL,
    category TEXT NOT NULL,
    price REAL NOT NULL,
    robux INTEGER NOT NULL DEFAULT 0,
    join_year INTEGER NOT NULL,
    level INTEGER NOT NULL DEFAULT 1,
    item_count INTEGER NOT NULL DEFAULT 0,
    rap INTEGER NOT NULL DEFAULT 0,
    avatar_preset TEXT NOT NULL DEFAULT 'dominus',
    description TEXT NOT NULL,
    inventory_json TEXT NOT NULL DEFAULT '[]',
    featured INTEGER NOT NULL DEFAULT 0,
    views INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'available',
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS orders (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    buyer_email TEXT NOT NULL,
    items_json TEXT NOT NULL,
    total REAL NOT NULL,
    status TEXT NOT NULL DEFAULT 'Completed',
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS tickets (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL,
    subject TEXT NOT NULL,
    message TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Open',
    created_at TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS activity_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    created_at TEXT NOT NULL
  );
`);

const adminTokens = new Map();
const userSessions = new Map();

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  const [salt, key] = stored.split(':');
  const keyBuf = Buffer.from(key, 'hex');
  const derived = crypto.scryptSync(password, salt, 64);
  return crypto.timingSafeEqual(keyBuf, derived);
}

function timingSafeStringMatch(a, b) {
  const bufA = Buffer.from(String(a));
  const bufB = Buffer.from(String(b));
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

function logActivity(actor, action) {
  db.prepare('INSERT INTO activity_logs (actor, action, created_at) VALUES (?, ?, ?)')
    .run(actor, action, new Date().toISOString());
}

function requireAdmin(req, res, next) {
  const token = req.headers['x-admin-token'];
  const expiry = adminTokens.get(token);
  if (!token || !expiry || Date.now() > expiry) {
    adminTokens.delete(token);
    return res.status(401).json({ error: 'Unauthorized: Valid Admin Password required.' });
  }
  next();
}

function getAuthUser(req) {
  const token = req.headers['x-user-token'];
  const userId = userSessions.get(token);
  if (!userId) return null;
  return db.prepare('SELECT id, username, email, role, created_at FROM users WHERE id = ?').get(userId);
}

app.get('/api/listings', (req, res) => {
  const rows = db.prepare('SELECT * FROM listings ORDER BY created_at DESC').all();
  res.json(rows.map(r => ({
    ...r,
    featured: Boolean(r.featured),
    inventory: JSON.parse(r.inventory_json || '[]')
  })));
});

app.get('/api/listings/:id', (req, res) => {
  const row = db.prepare('SELECT * FROM listings WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).json({ error: 'Listing not found' });
  db.prepare('UPDATE listings SET views = views + 1 WHERE id = ?').run(req.params.id);
  res.json({
    ...row,
    views: row.views + 1,
    featured: Boolean(row.featured),
    inventory: JSON.parse(row.inventory_json || '[]')
  });
});

app.post('/api/auth/register', (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password || password.length < 6) {
    return res.status(400).json({ error: 'Username, valid email, and 6+ char password required.' });
  }
  const existing = db.prepare('SELECT id FROM users WHERE email = ? OR username = ?').get(email.toLowerCase(), username);
  if (existing) {
    return res.status(409).json({ error: 'Username or email already registered.' });
  }
  const id = 'USR-' + crypto.randomBytes(4).toString('hex').toUpperCase();
  const createdAt = new Date().toISOString();
  db.prepare('INSERT INTO users (id, username, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(id, username.trim(), email.toLowerCase().trim(), hashPassword(password), 'buyer', createdAt);

  const token = crypto.randomBytes(32).toString('hex');
  userSessions.set(token, id);
  logActivity(username, 'Registered new buyer account');
  res.status(201).json({ token, user: { id, username, email: email.toLowerCase(), role: 'buyer', created_at: createdAt } });
});

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password required.' });

  const row = db.prepare('SELECT * FROM users WHERE email = ?').get(email.toLowerCase().trim());
  if (!row || !verifyPassword(password, row.password_hash)) {
    return res.status(401).json({ error: 'Invalid email or password.' });
  }
  const token = crypto.randomBytes(32).toString('hex');
  userSessions.set(token, row.id);
  logActivity(row.username, 'Signed in');
  res.json({
    token,
    user: { id: row.id, username: row.username, email: row.email, role: row.role, created_at: row.created_at }
  });
});

app.get('/api/auth/me', (req, res) => {
  const user = getAuthUser(req);
  if (!user) return res.status(401).json({ error: 'Not authenticated' });
  const orders = db.prepare('SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC').all(user.id)
    .map(o => ({ ...o, items: JSON.parse(o.items_json) }));
  res.json({ user, orders });
});

app.post('/api/orders', (req, res) => {
  const user = getAuthUser(req);
  if (!user) return res.status(401).json({ error: 'Sign in required to place orders.' });

  const { listingIds } = req.body;
  if (!Array.isArray(listingIds) || listingIds.length === 0) {
    return res.status(400).json({ error: 'Cart is empty.' });
  }

  const items = [];
  let total = 0;

  for (const id of listingIds) {
    const item = db.prepare('SELECT * FROM listings WHERE id = ? AND status = ?').get(id, 'available');
    if (!item) return res.status(400).json({ error: `Listing ${id} is no longer available.` });
    items.push({ id: item.id, title: item.title, roblox_username: item.roblox_username, price: item.price });
    total += item.price;
  }

  const orderId = 'ORD-' + crypto.randomBytes(4).toString('hex').toUpperCase();
  const createdAt = new Date().toISOString();

  db.exec('BEGIN');
  try {
    db.prepare('INSERT INTO orders (id, user_id, buyer_email, items_json, total, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
      .run(orderId, user.id, user.email, JSON.stringify(items), total, 'Completed', createdAt);

    const markSold = db.prepare('UPDATE listings SET status = ? WHERE id = ?');
    for (const item of items) markSold.run('sold', item.id);
    db.exec('COMMIT');
  } catch {
    db.exec('ROLLBACK');
    return res.status(500).json({ error: 'Transaction failed.' });
  }

  logActivity(user.username, `Completed order ${orderId} ($${total.toFixed(2)})`);
  res.status(201).json({ id: orderId, items, total, status: 'Completed', created_at: createdAt });
});

app.post('/api/tickets', (req, res) => {
  const { email, subject, message } = req.body;
  if (!email || !subject || !message) return res.status(400).json({ error: 'All fields required.' });
  const id = 'TCK-' + crypto.randomBytes(3).toString('hex').toUpperCase();
  db.prepare('INSERT INTO tickets (id, email, subject, message, status, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run(id, email, subject, message, 'Open', new Date().toISOString());
  logActivity(email, `Opened support ticket ${id}`);
  res.status(201).json({ id });
});

app.post('/api/admin/unlock', (req, res) => {
  const { password } = req.body;
  if (!password || !timingSafeStringMatch(password, ADMIN_PASSWORD)) {
    return res.status(401).json({ error: 'Incorrect Admin Password.' });
  }
  const token = crypto.randomBytes(32).toString('hex');
  adminTokens.set(token, Date.now() + 1000 * 60 * 60 * 8);
  logActivity('ADMIN', 'Unlocked Admin Panel');
  res.json({ adminToken: token });
});

app.get('/api/admin/overview', requireAdmin, (req, res) => {
  const listings = db.prepare('SELECT * FROM listings ORDER BY created_at DESC').all()
    .map(r => ({ ...r, featured: Boolean(r.featured), inventory: JSON.parse(r.inventory_json || '[]') }));
  const users = db.prepare('SELECT id, username, email, role, created_at FROM users ORDER BY created_at DESC').all();
  const orders = db.prepare('SELECT * FROM orders ORDER BY created_at DESC').all()
    .map(o => ({ ...o, items: JSON.parse(o.items_json) }));
  const tickets = db.prepare('SELECT * FROM tickets ORDER BY created_at DESC').all();
  const logs = db.prepare('SELECT * FROM activity_logs ORDER BY id DESC LIMIT 50').all();

  const revenue = orders.reduce((sum, o) => sum + o.total, 0);
  res.json({
    stats: {
      totalUsers: users.length,
      totalListings: listings.length,
      totalOrders: orders.length,
      revenue
    },
    listings,
    users,
    orders,
    tickets,
    logs
  });
});

app.post('/api/admin/listings', requireAdmin, (req, res) => {
  const {
    title, roblox_username, category, price, robux,
    join_year, level, item_count, rap, avatar_preset,
    description, inventory, featured
  } = req.body;

  if (!title || !roblox_username || !category || price === undefined || !join_year) {
    return res.status(400).json({ error: 'Title, Roblox username, category, price, and join year are required.' });
  }

  const id = 'KVX-' + crypto.randomBytes(3).toString('hex').toUpperCase();
  const createdAt = new Date().toISOString();
  const invArray = Array.isArray(inventory)
    ? inventory
    : String(inventory || '').split(',').map(s => s.trim()).filter(Boolean);

  db.prepare(`
    INSERT INTO listings (
      id, title, roblox_username, category, price, robux,
      join_year, level, item_count, rap, avatar_preset,
      description, inventory_json, featured, views, status, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 'available', ?)
  `).run(
    id,
    title.trim(),
    roblox_username.trim(),
    category,
    Number(price),
    Number(robux || 0),
    Number(join_year),
    Number(level || 1),
    Number(item_count || invArray.length),
    Number(rap || 0),
    avatar_preset || 'dominus',
    description || 'Verified Roblox account listing.',
    JSON.stringify(invArray),
    featured ? 1 : 0,
    createdAt
  );

  logActivity('ADMIN', `Created listing ${id} (${title})`);
  res.status(201).json({ id });
});

app.patch('/api/admin/listings/:id', requireAdmin, (req, res) => {
  const { price, featured, status } = req.body;
  const current = db.prepare('SELECT * FROM listings WHERE id = ?').get(req.params.id);
  if (!current) return res.status(404).json({ error: 'Listing not found.' });

  db.prepare('UPDATE listings SET price = ?, featured = ?, status = ? WHERE id = ?').run(
    price !== undefined ? Number(price) : current.price,
    featured !== undefined ? (featured ? 1 : 0) : current.featured,
    status !== undefined ? status : current.status,
    req.params.id
  );

  logActivity('ADMIN', `Updated listing ${req.params.id}`);
  res.json({ ok: true });
});

app.delete('/api/admin/listings/:id', requireAdmin, (req, res) => {
  db.prepare('DELETE FROM listings WHERE id = ?').run(req.params.id);
  logActivity('ADMIN', `Deleted listing ${req.params.id}`);
  res.json({ ok: true });
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`KAVEXRO running on port ${PORT}`);
});
