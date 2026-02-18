const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const { getDb, COLLECTIONS, hmacKeyHash, getNextSessionId, ensureSeedData } = require('./db');
const dotenv = require('dotenv');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 4000;

app.use(cors());
app.use(express.json());

function signToken(payload) {
  const secret = process.env.JWT_SECRET;
  if (!secret) throw new Error('JWT_SECRET is not set');
  const expiresIn = process.env.JWT_EXPIRES_IN || '7d';
  return jwt.sign(payload, secret, { expiresIn });
}

function authMiddleware(requiredRole) {
  return async (req, res, next) => {
    try {
      const header = req.headers.authorization || '';
      const m = header.match(/^Bearer\s+(.+)$/i);
      if (!m) return res.status(401).json({ error: 'unauthorized' });
      const token = m[1];
      const payload = jwt.verify(token, process.env.JWT_SECRET);
      req.user = { userName: payload.sub, role: payload.role };
      if (requiredRole && payload.role !== requiredRole) {
        return res.status(403).json({ error: 'forbidden' });
      }
      next();
    } catch {
      return res.status(401).json({ error: 'unauthorized' });
    }
  };
}

// ---------- Auth ----------

// Old gamer: пароль -> UserName (без логина по имени)
app.post('/api/auth/player-login-old', async (req, res) => {
  try {
    const { password } = req.body || {};
    if (!password) return res.status(400).json({ error: 'missing_password' });
    const db = await getDb();
    const user = await db.collection(COLLECTIONS.users).findOne({
      isAdmin: false,
      keyHash: hmacKeyHash(password),
    });
    if (!user) return res.status(401).json({ error: 'invalid_password' });
    const token = signToken({ sub: user.userName, role: 'player' });
    return res.json({ token, userName: user.userName, role: 'player' });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'server_error' });
  }
});

// Admin: пароль -> админ
app.post('/api/auth/admin-login', async (req, res) => {
  try {
    const { password } = req.body || {};
    if (!password) return res.status(400).json({ error: 'missing_password' });
    const db = await getDb();
    const user = await db.collection(COLLECTIONS.users).findOne({
      isAdmin: true,
      keyHash: hmacKeyHash(password),
    });
    if (!user) return res.status(401).json({ error: 'invalid_password' });
    const token = signToken({ sub: user.userName, role: 'admin' });
    return res.json({ token, userName: user.userName, role: 'admin' });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'server_error' });
  }
});

// New gamer: регистрация по UserName + пароль
app.post('/api/auth/player-register', async (req, res) => {
  try {
    const { userName, password } = req.body || {};
    if (!userName || !password) return res.status(400).json({ error: 'missing_fields' });
    const db = await getDb();
    const coll = db.collection(COLLECTIONS.users);
    const existing = await coll.findOne({ userName });
    if (existing) return res.status(409).json({ error: 'username_taken' });
    await coll.insertOne({
      userName,
      isAdmin: false,
      passwordHash: null,
      keyHash: hmacKeyHash(password),
      createdAt: new Date(),
    });
    const token = signToken({ sub: userName, role: 'player' });
    return res.status(201).json({ token, userName, role: 'player' });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'server_error' });
  }
});

// ---------- Sessions ----------

// GET /api/sessions  (игрок и админ)
app.get('/api/sessions', authMiddleware(), async (req, res) => {
  try {
    const db = await getDb();
    const docs = await db
      .collection(COLLECTIONS.sessions)
      .find({})
      .sort({ startAt: -1 })
      .toArray();
    const sessions = docs.map((d) => {
      const dt = d.startAt instanceof Date ? d.startAt : new Date(d.startAt);
      const startDate = dt.toISOString().slice(0, 10);
      const startTime = dt.toISOString().slice(11, 16);
      return {
        id: d.id,
        startDate,
        startTime,
        description: d.description || '',
      };
    });
    return res.json({ sessions });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'server_error' });
  }
});

// POST /api/sessions (admin)
app.post('/api/sessions', authMiddleware('admin'), async (req, res) => {
  try {
    const { startDate, startTime, description } = req.body || {};
    if (!startDate || !startTime) return res.status(400).json({ error: 'invalid_datetime' });
    const ts = Date.parse(`${startDate}T${startTime}:00Z`);
    if (Number.isNaN(ts)) return res.status(400).json({ error: 'invalid_datetime' });
    const db = await getDb();
    const id = await getNextSessionId(db);
    const doc = {
      id,
      startAt: new Date(ts),
      description: description || '',
      createdAt: new Date(),
    };
    await db.collection(COLLECTIONS.sessions).insertOne(doc);
    return res.status(201).json({
      session: {
        id,
        startDate,
        startTime,
        description: doc.description,
      },
    });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'server_error' });
  }
});

// DELETE /api/sessions/:id (admin)
app.delete('/api/sessions/:id', authMiddleware('admin'), async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isFinite(id)) return res.status(400).json({ error: 'invalid_id' });
    const db = await getDb();
    await db.collection(COLLECTIONS.sessions).deleteOne({ id });
    await db.collection(COLLECTIONS.attempts).deleteMany({ sessionId: id });
    return res.status(204).end();
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'server_error' });
  }
});

// ---------- Leaderboard & attempts ----------

// GET /api/sessions/:id/leaderboard
app.get('/api/sessions/:id/leaderboard', authMiddleware(), async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isFinite(id)) return res.status(400).json({ error: 'invalid_id' });
    const db = await getDb();
    const pipeline = [
      { $match: { sessionId: id } },
      { $group: { _id: '$userName', rate: { $max: '$rate' } } },
      { $sort: { rate: -1, _id: 1 } },
    ];
    const docs = await db.collection(COLLECTIONS.attempts).aggregate(pipeline).toArray();
    const leaderboard = docs.map((d, idx) => ({
      rank: idx + 1,
      userName: d._id,
      rate: d.rate,
    }));
    return res.json({ leaderboard });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'server_error' });
  }
});

// GET /api/sessions/:id/attempts?userName=...
app.get('/api/sessions/:id/attempts', authMiddleware(), async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isFinite(id)) return res.status(400).json({ error: 'invalid_id' });
    const { userName } = req.query;
    if (!userName || typeof userName !== 'string') return res.status(400).json({ error: 'missing_userName' });
    const authUser = req.user;
    if (authUser.role !== 'admin' && authUser.userName !== userName) {
      return res.status(403).json({ error: 'forbidden' });
    }
    const db = await getDb();
    const docs = await db
      .collection(COLLECTIONS.attempts)
      .find({ sessionId: id, userName })
      .sort({ createdAt: -1 })
      .toArray();
    const attempts = docs.map((d) => ({
      id: String(d._id),
      sessionId: d.sessionId,
      userName: d.userName,
      rate: d.rate,
      dateTime: d.createdAt instanceof Date ? d.createdAt.toISOString() : new Date(d.createdAt).toISOString(),
    }));
    return res.json({ attempts });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'server_error' });
  }
});

// POST /api/sessions/:id/attempts  body: { rate }
app.post('/api/sessions/:id/attempts', authMiddleware('player'), async (req, res) => {
  try {
    const id = Number(req.params.id);
    if (!Number.isFinite(id)) return res.status(400).json({ error: 'invalid_id' });
    const { rate } = req.body || {};
    const r = Number(rate);
    if (!Number.isFinite(r) || r < 1 || r > 100) return res.status(400).json({ error: 'invalid_rate' });
    const db = await getDb();
    await db.collection(COLLECTIONS.attempts).insertOne({
      sessionId: id,
      userName: req.user.userName,
      rate: r,
      createdAt: new Date(),
    });
    return res.status(201).json({ ok: true });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'server_error' });
  }
});

// ---------- Start ----------

(async () => {
  try {
    await ensureSeedData();
    app.listen(PORT, () => {
      console.log(`siteBack API listening on http://localhost:${PORT}`);
    });
  } catch (e) {
    console.error('Failed to start server', e);
    process.exit(1);
  }
})();

