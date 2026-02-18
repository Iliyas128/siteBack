const { MongoClient } = require('mongodb');
const crypto = require('crypto');
const dotenv = require('dotenv');

dotenv.config();

const uri = process.env.MONGODB_URI;
if (!uri) {
  throw new Error('MONGODB_URI is not set in siteBack/.env');
}

const client = new MongoClient(uri);
let dbPromise;

function getDb() {
  if (!dbPromise) {
    const dbName = process.env.MONGODB_DB || 'flightkoy_siteback';
    dbPromise = client.connect().then(() => client.db(dbName));
  }
  return dbPromise;
}

const COLLECTIONS = {
  users: 'quest_users',
  sessions: 'quest_sessions',
  attempts: 'quest_attempts',
  counters: 'quest_counters',
};

function hmacKeyHash(password) {
  const secret = process.env.JWT_SECRET || 'change-me';
  return crypto.createHmac('sha256', secret).update(String(password).trim()).digest('hex');
}

async function getNextSessionId(db) {
  const doc = await db.collection(COLLECTIONS.counters).findOneAndUpdate(
    { _id: 'sessionId' },
    { $inc: { seq: 1 } },
    { upsert: true, returnDocument: 'after' },
  );
  // Драйвер mongodb возвращает документ напрямую (не { value: document })
  return doc?.seq != null ? doc.seq : 1;
}

async function ensureSeedData() {
  const db = await getDb();

  // Admin
  const admin = await db.collection(COLLECTIONS.users).findOne({ isAdmin: true, userName: 'admin' });
  if (!admin) {
    const pwd = 'admin';
    await db.collection(COLLECTIONS.users).insertOne({
      userName: 'admin',
      isAdmin: true,
      passwordHash: null,
      keyHash: hmacKeyHash(pwd),
      createdAt: new Date(),
    });
  }

  // Players
  const seedPlayers = [
    { userName: 'Artur_1', password: 'artur' },
    { userName: 'Antuan', password: 'a' },
    { userName: 'Maria', password: 'm' },
    { userName: 'Ivan', password: 'i' },
  ];
  for (const p of seedPlayers) {
    const exists = await db.collection(COLLECTIONS.users).findOne({ userName: p.userName });
    if (!exists) {
      await db.collection(COLLECTIONS.users).insertOne({
        userName: p.userName,
        isAdmin: false,
        passwordHash: null,
        keyHash: hmacKeyHash(p.password),
        createdAt: new Date(),
      });
    }
  }

  // Sessions + attempts (only if no sessions yet)
  const sessionsCount = await db.collection(COLLECTIONS.sessions).countDocuments();
  if (sessionsCount === 0) {
    const now = new Date();
    const s1Date = new Date(now.getTime() + 24 * 60 * 60 * 1000);
    const s2Date = new Date(now.getTime() + 2 * 24 * 60 * 60 * 1000);

    const id1 = await getNextSessionId(db);
    const id2 = await getNextSessionId(db);

    await db.collection(COLLECTIONS.sessions).insertMany([
      {
        id: id1,
        startAt: s1Date,
        description: 'Текстовое описание сессии 1',
        createdAt: new Date(),
      },
      {
        id: id2,
        startAt: s2Date,
        description: 'Текстовое описание сессии 2',
        createdAt: new Date(),
      },
    ]);

    await db.collection(COLLECTIONS.attempts).insertMany([
      { sessionId: id1, userName: 'Antuan', rate: 98, createdAt: new Date(s1Date.getTime() + 5 * 60 * 1000) },
      { sessionId: id1, userName: 'Maria', rate: 81, createdAt: new Date(s1Date.getTime() + 10 * 60 * 1000) },
      { sessionId: id1, userName: 'Ivan', rate: 69, createdAt: new Date(s1Date.getTime() + 15 * 60 * 1000) },
      { sessionId: id1, userName: 'Artur_1', rate: 78, createdAt: new Date(s1Date.getTime() + 20 * 60 * 1000) },
    ]);
  }
}

module.exports = {
  getDb,
  COLLECTIONS,
  hmacKeyHash,
  getNextSessionId,
  ensureSeedData,
};

