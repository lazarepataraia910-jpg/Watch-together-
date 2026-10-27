try { process.loadEnvFile(); } catch {} // loads .env locally if present; on Render env vars are injected directly

const express = require('express');
const http = require('http');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { Server } = require('socket.io');
const { Pool } = require('pg');
const compression = require('compression');

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || '';
const DATABASE_URL = process.env.DATABASE_URL || '';
// Render sets RENDER=true; there the site is served over https, so cookies get the Secure flag.
const IS_PROD = !!process.env.RENDER || process.env.NODE_ENV === 'production';
const COOKIE_FLAGS = `HttpOnly; Path=/; SameSite=Lax${IS_PROD ? '; Secure' : ''}`;

const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const ROOMS_FILE = path.join(DATA_DIR, 'rooms.json');
const SESSIONS_FILE = path.join(DATA_DIR, 'sessions.json');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

function loadJSON(file) {
  if (!fs.existsSync(file)) return [];
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return [];
  }
}
function saveJSON(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

let users = []; // [{id, username, usernameLower, email, emailLower, passwordHash, avatar, friends, createdAt}], filled by loadUsers() at startup
let rooms = loadJSON(ROOMS_FILE); // [{id, name, ownerId, ownerUsername, passwordHash, videoUrl, admins, createdAt}]

// ---------- Users database ----------
// With DATABASE_URL set (production), users live in a Postgres "users" table so they survive
// Render wiping the disk on every deploy/restart. Without it (local dev), data/users.json is used.
const db = DATABASE_URL
  ? new Pool({ connectionString: DATABASE_URL, ssl: /@(localhost|127\.0\.0\.1)[:/]/.test(DATABASE_URL) ? false : { rejectUnauthorized: false } })
  : null;

async function loadUsers() {
  if (!db) return loadJSON(USERS_FILE);
  await db.query(`CREATE TABLE IF NOT EXISTS users (
    id text PRIMARY KEY,
    username text NOT NULL,
    username_lower text NOT NULL UNIQUE,
    email text NOT NULL DEFAULT '',
    email_lower text NOT NULL DEFAULT '',
    password_hash text,
    avatar text,
    friends jsonb NOT NULL DEFAULT '[]',
    created_at bigint NOT NULL
  )`);
  await db.query('ALTER TABLE users ENABLE ROW LEVEL SECURITY');
  const { rows } = await db.query('SELECT * FROM users');
  return rows.map((r) => ({
    id: r.id,
    username: r.username,
    usernameLower: r.username_lower,
    email: r.email,
    emailLower: r.email_lower,
    passwordHash: r.password_hash,
    avatar: r.avatar || undefined,
    friends: r.friends,
    createdAt: Number(r.created_at),
  }));
}

// Writes one user (insert or update). Throws if the database write fails.
async function saveUser(u) {
  if (!db) return saveJSON(USERS_FILE, users);
  await db.query(
    `INSERT INTO users (id, username, username_lower, email, email_lower, password_hash, avatar, friends, created_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
     ON CONFLICT (id) DO UPDATE SET username = $2, username_lower = $3, email = $4, email_lower = $5,
       password_hash = $6, avatar = $7, friends = $8`,
    [u.id, u.username, u.usernameLower, u.email || '', u.emailLower || '', u.passwordHash || null, u.avatar || null,
      JSON.stringify(u.friends || []), u.createdAt],
  );
}

// token -> userId, persisted so a server restart doesn't log everyone out
const sessions = new Map(loadJSON(SESSIONS_FILE).map((s) => [s.token, s.userId]));
function saveSessions() {
  saveJSON(SESSIONS_FILE, [...sessions.entries()].map(([token, userId]) => ({ token, userId })));
}
// roomId -> Set(userId) who verified the room password (or own it)
const roomAccess = new Map();
// roomId -> { participants: Map(socketId -> {userId, username}), video: {...}, chat: [] }
const roomState = new Map();

function parseCookieHeader(header) {
  const out = {};
  if (!header) return out;
  header.split(';').forEach((pair) => {
    const idx = pair.indexOf('=');
    if (idx === -1) return;
    out[pair.slice(0, idx).trim()] = decodeURIComponent(pair.slice(idx + 1).trim());
  });
  return out;
}

function setSessionCookie(res, token) {
  const maxAge = 60 * 60 * 24 * 30; // 30 days
  res.setHeader('Set-Cookie', `watch_session=${token}; Max-Age=${maxAge}; ${COOKIE_FLAGS}`);
}
function clearSessionCookie(res) {
  res.setHeader('Set-Cookie', `watch_session=; Max-Age=0; ${COOKIE_FLAGS}`);
}

function getUserFromReq(req) {
  const cookies = parseCookieHeader(req.headers.cookie);
  const token = cookies['watch_session'];
  if (!token) return null;
  const userId = sessions.get(token);
  if (!userId) return null;
  return users.find((u) => u.id === userId) || null;
}

function requireAuth(req, res, next) {
  const user = getUserFromReq(req);
  if (!user) return res.status(401).json({ error: 'AUTH_REQUIRED' });
  req.user = user;
  next();
}

// Avatars go out as a cacheable image URL rather than the inline data URL, so the participant
// list broadcast on every join/leave stays small. ?v= changes whenever the photo changes.
function avatarUrl(u) {
  if (!u.avatar) return null;
  const v = crypto.createHash('md5').update(u.avatar).digest('hex').slice(0, 10);
  return `/api/users/${u.id}/avatar?v=${v}`;
}
function publicUser(u) {
  return { id: u.id, username: u.username, avatar: avatarUrl(u) };
}
function publicRoom(r) {
  const state = roomState.get(r.id);
  return {
    id: r.id,
    name: r.name,
    ownerUsername: r.ownerUsername,
    createdAt: r.createdAt,
    viewerCount: state ? state.participants.size : 0,
    hasVideo: !!(state && state.video && state.video.url) || !!r.videoUrl,
  };
}

const USERNAME_RE = /^[a-zA-Z0-9_Ⴀ-ჿ]+$/;
// Avatars are resized client-side and stored inline in users.json as a small data URL.
const AVATAR_RE = /^data:image\/(png|jpeg|webp);base64,[A-Za-z0-9+/=]+$/;
const AVATAR_MAX_LEN = 200 * 1024;

// Returns an error code, or null if the username is valid and free.
function usernameError(name, exceptUserId) {
  if (name.length < 3 || name.length > 20 || !USERNAME_RE.test(name)) return 'BAD_USERNAME';
  const lower = name.toLowerCase();
  if (users.some((u) => u.usernameLower === lower && u.id !== exceptUserId)) return 'USERNAME_TAKEN';
  return null;
}

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1); // Render's proxy: req.ip is the visitor, not the proxy

// Security headers. Script/frame sources stay open because video players (YouTube, Twitch, Vimeo,
// embedded pages) need them; the rest blocks plugins, base-tag tricks and framing of this site.
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Content-Security-Policy', "object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'");
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  if (IS_PROD) res.setHeader('Strict-Transport-Security', 'max-age=15552000; includeSubDomains');
  next();
});

// Slows down password guessing: at most `limit` attempts per IP per window.
function rateLimit(limit, windowMs) {
  const hits = new Map(); // ip -> { count, resetAt }
  setInterval(() => {
    const now = Date.now();
    for (const [ip, h] of hits) if (h.resetAt <= now) hits.delete(ip);
  }, windowMs).unref();
  return (req, res, next) => {
    const now = Date.now();
    let h = hits.get(req.ip);
    if (!h || h.resetAt <= now) { h = { count: 0, resetAt: now + windowMs }; hits.set(req.ip, h); }
    if (++h.count > limit) return res.status(429).json({ error: 'TOO_MANY_ATTEMPTS' });
    next();
  };
}
const authLimiter = rateLimit(10, 60 * 1000);

app.use(compression());
app.use(express.json({ limit: '300kb' }));
app.use(express.static(path.join(__dirname, 'public'), { index: 'index.html' }));

app.get('/api/users/:id/avatar', (req, res) => {
  const user = users.find((u) => u.id === req.params.id);
  const m = user && user.avatar && user.avatar.match(AVATAR_RE);
  if (!m) return res.status(404).end();
  res.setHeader('Content-Type', `image/${m[1]}`);
  res.setHeader('Cache-Control', 'public, max-age=31536000, immutable'); // URL carries a content hash
  res.end(Buffer.from(user.avatar.slice(user.avatar.indexOf(',') + 1), 'base64'));
});

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// ---------- Auth ----------
app.post('/api/register', authLimiter, async (req, res) => {
  const { username, password, email } = req.body || {};
  if (typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'INVALID_INPUT' });
  }
  const name = username.trim();
  const nameErr = usernameError(name);
  if (nameErr) return res.status(nameErr === 'USERNAME_TAKEN' ? 409 : 400).json({ error: nameErr });
  if (password.length < 4) {
    return res.status(400).json({ error: 'BAD_PASSWORD' });
  }
  const lower = name.toLowerCase();
  let emailTrimmed = '';
  let emailLower = '';
  if (typeof email === 'string' && email.trim()) {
    emailTrimmed = email.trim();
    if (!EMAIL_RE.test(emailTrimmed)) {
      return res.status(400).json({ error: 'BAD_EMAIL' });
    }
    emailLower = emailTrimmed.toLowerCase();
    if (users.some((u) => u.emailLower === emailLower)) {
      return res.status(409).json({ error: 'EMAIL_TAKEN' });
    }
  }
  const user = {
    id: crypto.randomUUID(),
    username: name,
    usernameLower: lower,
    email: emailTrimmed,
    emailLower,
    passwordHash: await bcrypt.hash(password, 10),
    createdAt: Date.now(),
  };
  // Re-check after the await: another request may have taken the name meanwhile.
  if (usernameError(name)) return res.status(409).json({ error: 'USERNAME_TAKEN' });
  users.push(user);
  try {
    await saveUser(user);
  } catch (err) {
    console.error('register: saving user failed:', err.message);
    users = users.filter((u) => u !== user);
    return res.status(500).json({ error: 'DB_ERROR' });
  }

  const token = crypto.randomBytes(24).toString('hex');
  sessions.set(token, user.id);
  saveSessions();
  setSessionCookie(res, token);
  res.json({ ok: true, user: publicUser(user) });
});

app.post('/api/login', authLimiter, async (req, res) => {
  const { username, password } = req.body || {};
  if (typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'INVALID_INPUT' });
  }
  const identifier = username.trim().toLowerCase();
  const user = users.find((u) => u.usernameLower === identifier || (u.emailLower && u.emailLower === identifier));
  if (!user || !user.passwordHash || !(await bcrypt.compare(password, user.passwordHash))) {
    return res.status(401).json({ error: 'INVALID_CREDENTIALS' });
  }
  const token = crypto.randomBytes(24).toString('hex');
  sessions.set(token, user.id);
  saveSessions();
  setSessionCookie(res, token);
  res.json({ ok: true, user: publicUser(user) });
});

app.post('/api/logout', (req, res) => {
  const cookies = parseCookieHeader(req.headers.cookie);
  const token = cookies['watch_session'];
  if (token) {
    sessions.delete(token);
    saveSessions();
  }
  clearSessionCookie(res);
  res.json({ ok: true });
});

// ---------- Google sign-in ----------
function requestBaseUrl(req) {
  const proto = req.headers['x-forwarded-proto'] || req.protocol;
  const host = req.headers['x-forwarded-host'] || req.get('host');
  return `${proto}://${host}`;
}

app.get('/api/auth/google', (req, res) => {
  if (!GOOGLE_CLIENT_ID) return res.redirect('/login.html?error=GOOGLE_NOT_CONFIGURED');
  const redirectUri = `${requestBaseUrl(req)}/api/auth/google/callback`;
  const state = crypto.randomBytes(16).toString('hex');
  res.setHeader('Set-Cookie', `oauth_state=${state}; Max-Age=600; ${COOKIE_FLAGS}`);
  const params = new URLSearchParams({
    client_id: GOOGLE_CLIENT_ID,
    redirect_uri: redirectUri,
    response_type: 'code',
    scope: 'openid email profile',
    state,
    prompt: 'select_account',
  });
  res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`);
});

app.get('/api/auth/google/callback', async (req, res) => {
  if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) return res.redirect('/login.html?error=GOOGLE_NOT_CONFIGURED');
  const { code, state } = req.query;
  const cookies = parseCookieHeader(req.headers.cookie);
  if (typeof code !== 'string' || !state || state !== cookies['oauth_state']) {
    return res.redirect('/login.html?error=GOOGLE_AUTH_FAILED');
  }
  try {
    const redirectUri = `${requestBaseUrl(req)}/api/auth/google/callback`;
    const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id: GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        redirect_uri: redirectUri,
        grant_type: 'authorization_code',
      }),
    });
    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) throw new Error('token exchange failed');

    const profileRes = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });
    const profile = await profileRes.json();
    if (!profile.email) throw new Error('no email in profile');

    const emailLower = profile.email.toLowerCase();
    let user = users.find((u) => u.emailLower === emailLower);
    if (!user) {
      let base = (profile.name || profile.email.split('@')[0]).replace(/[^a-zA-Z0-9_Ⴀ-ჿ]/g, '').slice(0, 20);
      if (base.length < 3) base = (base || 'user').padEnd(3, '0');
      let candidate = base;
      let n = 1;
      while (users.some((u) => u.usernameLower === candidate.toLowerCase())) {
        candidate = (base + n).slice(0, 20);
        n++;
      }
      user = {
        id: crypto.randomUUID(),
        username: candidate,
        usernameLower: candidate.toLowerCase(),
        email: profile.email,
        emailLower,
        passwordHash: null,
        createdAt: Date.now(),
      };
      users.push(user);
      try {
        await saveUser(user);
      } catch (err) {
        users = users.filter((u) => u !== user);
        throw err;
      }
    }

    const token = crypto.randomBytes(24).toString('hex');
    sessions.set(token, user.id);
    saveSessions();
    setSessionCookie(res, token);
    res.redirect('/index.html');
  } catch {
    res.redirect('/login.html?error=GOOGLE_AUTH_FAILED');
  }
});

app.get('/api/me', requireAuth, (req, res) => {
  res.json({ ok: true, user: { ...publicUser(req.user), email: req.user.email || '' } });
});

// ---------- Profile settings ----------
app.patch('/api/me', requireAuth, async (req, res) => {
  const { username, avatar } = req.body || {};
  if (username !== undefined) {
    if (typeof username !== 'string') return res.status(400).json({ error: 'INVALID_INPUT' });
    const name = username.trim();
    const nameErr = usernameError(name, req.user.id);
    if (nameErr) return res.status(nameErr === 'USERNAME_TAKEN' ? 409 : 400).json({ error: nameErr });
    req.user.username = name;
    req.user.usernameLower = name.toLowerCase();
    rooms.forEach((r) => { if (r.ownerId === req.user.id) r.ownerUsername = name; });
    saveJSON(ROOMS_FILE, rooms);
  }
  if (avatar !== undefined) {
    if (avatar === null) {
      delete req.user.avatar;
    } else if (typeof avatar !== 'string' || avatar.length > AVATAR_MAX_LEN || !AVATAR_RE.test(avatar)) {
      return res.status(400).json({ error: 'BAD_AVATAR' });
    } else {
      req.user.avatar = avatar;
    }
  }
  try {
    await saveUser(req.user);
  } catch (err) {
    console.error('profile: saving user failed:', err.message);
    return res.status(500).json({ error: 'DB_ERROR' });
  }
  res.json({ ok: true, user: publicUser(req.user) });
});

// ---------- Friends ----------
app.get('/api/friends', requireAuth, (req, res) => {
  const friendIds = req.user.friends || [];
  const list = friendIds.map((id) => users.find((u) => u.id === id)).filter(Boolean).map(publicUser);
  res.json({ ok: true, friends: list });
});

app.post('/api/friends', requireAuth, async (req, res) => {
  const { email } = req.body || {};
  if (typeof email !== 'string' || !email.trim()) {
    return res.status(400).json({ error: 'BAD_EMAIL' });
  }
  const emailLower = email.trim().toLowerCase();
  const friend = users.find((u) => u.emailLower === emailLower);
  if (!friend) return res.status(404).json({ error: 'NOT_FOUND' });
  if (friend.id === req.user.id) return res.status(400).json({ error: 'CANNOT_ADD_SELF' });
  if (!req.user.friends) req.user.friends = [];
  if (req.user.friends.includes(friend.id)) return res.status(409).json({ error: 'ALREADY_FRIEND' });
  req.user.friends.push(friend.id);
  try {
    await saveUser(req.user);
  } catch (err) {
    req.user.friends = req.user.friends.filter((id) => id !== friend.id);
    return res.status(500).json({ error: 'DB_ERROR' });
  }
  res.json({ ok: true, friend: publicUser(friend) });
});

app.delete('/api/friends/:id', requireAuth, async (req, res) => {
  req.user.friends = (req.user.friends || []).filter((id) => id !== req.params.id);
  try {
    await saveUser(req.user);
  } catch (err) {
    return res.status(500).json({ error: 'DB_ERROR' });
  }
  res.json({ ok: true });
});

// ---------- Rooms ----------
// Public so guests can browse rooms before logging in; joining still requires auth.
app.get('/api/rooms', (req, res) => {
  const q = (req.query.search || '').toString().trim().toLowerCase();
  let list = rooms;
  if (q) list = list.filter((r) => r.name.toLowerCase().includes(q));
  list = list.slice().sort((a, b) => b.createdAt - a.createdAt);
  res.json({ ok: true, rooms: list.map(publicRoom) });
});

app.post('/api/rooms', requireAuth, async (req, res) => {
  const { name, password, videoUrl } = req.body || {};
  if (typeof name !== 'string' || name.trim().length < 2 || name.trim().length > 40) {
    return res.status(400).json({ error: 'BAD_NAME' });
  }
  if (typeof password !== 'string' || password.length < 3) {
    return res.status(400).json({ error: 'BAD_PASSWORD' });
  }
  const room = {
    id: crypto.randomUUID(),
    name: name.trim(),
    ownerId: req.user.id,
    ownerUsername: req.user.username,
    passwordHash: await bcrypt.hash(password, 10),
    videoUrl: typeof videoUrl === 'string' ? videoUrl.trim() : '',
    admins: [],
    createdAt: Date.now(),
  };
  rooms.push(room);
  saveJSON(ROOMS_FILE, rooms);
  roomAccess.set(room.id, new Set([req.user.id]));
  res.json({ ok: true, room: publicRoom(room) });
});

app.post('/api/rooms/:id/join', authLimiter, requireAuth, async (req, res) => {
  const room = rooms.find((r) => r.id === req.params.id);
  if (!room) return res.status(404).json({ error: 'NOT_FOUND' });
  const { password } = req.body || {};
  const isOwner = room.ownerId === req.user.id;
  if (!isOwner) {
    if (typeof password !== 'string' || !(await bcrypt.compare(password, room.passwordHash))) {
      return res.status(403).json({ error: 'WRONG_PASSWORD' });
    }
  }
  if (!roomAccess.has(room.id)) roomAccess.set(room.id, new Set());
  roomAccess.get(room.id).add(req.user.id);
  res.json({ ok: true, room: publicRoom(room) });
});

app.delete('/api/rooms/:id', requireAuth, (req, res) => {
  const room = rooms.find((r) => r.id === req.params.id);
  if (!room) return res.status(404).json({ error: 'NOT_FOUND' });
  if (room.ownerId !== req.user.id) return res.status(403).json({ error: 'FORBIDDEN' });
  rooms = rooms.filter((r) => r.id !== room.id);
  saveJSON(ROOMS_FILE, rooms);
  roomAccess.delete(room.id);
  roomState.delete(room.id);
  res.json({ ok: true });
});

// YouTube channel live links (/@name/live, /channel/ID/live, /c/name/live) have no video id in
// the URL, so look up the current stream's watch URL once on the server (only youtube.com is fetched).
const YT_CHANNEL_LIVE_RE = /^https?:\/\/(?:www\.|m\.)?youtube\.com\/(?:@[\w.-]+|channel\/[\w-]+|c\/[\w.-]+|user\/[\w.-]+)\/live\/?(?:[?#].*)?$/i;
async function resolveVideoUrl(url) {
  if (!YT_CHANNEL_LIVE_RE.test(url)) return url;
  try {
    const res = await fetch(url, { headers: { 'Accept-Language': 'en' }, signal: AbortSignal.timeout(8000) });
    const html = await res.text();
    const m = html.match(/<link rel="canonical" href="https:\/\/www\.youtube\.com\/watch\?v=([\w-]{11})"/);
    return m ? `https://www.youtube.com/watch?v=${m[1]}` : url;
  } catch {
    return url;
  }
}

app.use('/api', (req, res) => res.status(404).json({ error: 'NOT_FOUND' }));
app.use((req, res) => res.status(404).sendFile(path.join(__dirname, 'public', '404.html')));
app.use((err, req, res, next) => {
  if (!err.status || err.status >= 500) console.error(err);
  res.status(err.status || 500).json({ error: err.status === 400 ? 'INVALID_INPUT' : 'SERVER_ERROR' });
});

const server = http.createServer(app);
// Only accept socket connections from this site's own pages (blocks other sites from using a
// visitor's login cookie to open a socket in their name).
const io = new Server(server, {
  allowRequest: (req, cb) => {
    const origin = req.headers.origin;
    if (!origin) return cb(null, true);
    try {
      cb(null, new URL(origin).host === (req.headers['x-forwarded-host'] || req.headers.host));
    } catch {
      cb(null, false);
    }
  },
});

io.use((socket, next) => {
  const cookies = parseCookieHeader(socket.handshake.headers.cookie);
  const token = cookies['watch_session'];
  const userId = token && sessions.get(token);
  const user = userId && users.find((u) => u.id === userId);
  if (!user) return next(new Error('AUTH_REQUIRED'));
  socket.user = user;
  next();
});

io.on('connection', (socket) => {
  let currentRoomId = null;

  function getState() {
    return currentRoomId ? roomState.get(currentRoomId) : null;
  }
  function currentRoom() {
    return currentRoomId ? rooms.find((r) => r.id === currentRoomId) : null;
  }
  function canControl() {
    const room = currentRoom();
    if (!room) return false;
    return room.ownerId === socket.user.id || (room.admins || []).includes(socket.user.id);
  }

  socket.on('room:join', (roomId) => {
    const room = rooms.find((r) => r.id === roomId);
    if (!room) return socket.emit('room:error', 'NOT_FOUND');
    const access = roomAccess.get(roomId);
    const allowed = room.ownerId === socket.user.id || (access && access.has(socket.user.id));
    if (!allowed) return socket.emit('room:error', 'NO_ACCESS');

    currentRoomId = roomId;
    socket.join(roomId);

    if (!roomState.has(roomId)) {
      roomState.set(roomId, {
        participants: new Map(),
        video: { url: room.videoUrl || '', playing: false, time: 0, updatedAt: Date.now() },
        chat: [],
        screenSharer: null,
      });
    }
    const state = roomState.get(roomId);
    state.participants.set(socket.id, { userId: socket.user.id, username: socket.user.username, avatar: avatarUrl(socket.user) });

    socket.emit('room:init', {
      roomName: room.name,
      ownerId: room.ownerId,
      admins: room.admins || [],
      me: publicUser(socket.user),
      video: state.video,
      chat: state.chat.slice(-100),
      participants: [...state.participants.values()],
      isOwner: room.ownerId === socket.user.id,
      screenSharer: state.screenSharer,
    });

    const sysMsg = { system: true, text: `${socket.user.username} შემოვიდა ოთახში`, ts: Date.now() };
    state.chat.push(sysMsg);
    socket.to(roomId).emit('chat:message', sysMsg);
    io.to(roomId).emit('room:participants', [...state.participants.values()]);
  });

  // Clients measure their clock offset against the server so "time X at moment T" means the
  // same thing for everyone, regardless of how wrong each device's clock is.
  socket.on('time:ping', (cb) => { if (typeof cb === 'function') cb(Date.now()); });

  socket.on('video:setSource', async (url) => {
    const state = getState();
    const roomId = currentRoomId;
    if (!state || !roomId) return;
    if (!canControl()) return;
    if (typeof url !== 'string' || url.length > 2000) return;
    if (url.trim() && !/^https?:\/\//i.test(url.trim())) return;
    const resolved = await resolveVideoUrl(url.trim());
    if (getState() !== state) return; // left the room while resolving
    if (state.screenSharer) {
      state.screenSharer = null;
      io.to(roomId).emit('screen:stopped');
    }
    state.leader = socket.id;
    state.video = { url: resolved, playing: false, time: 0, updatedAt: Date.now() };
    io.to(roomId).emit('video:source', state.video);
  });

  // payload: { time, at } where `at` is the sender's server-clock timestamp of that position.
  // Older clients sent a bare number; that still works, just without latency compensation.
  function updateVideoState(partial, payload) {
    const state = getState();
    if (!state) return;
    const now = Date.now();
    const at = payload && Number(payload.at);
    const updatedAt = at && Math.abs(at - now) < 5000 ? at : now;
    state.video = { ...state.video, ...partial, updatedAt };
    socket.to(currentRoomId).emit('video:state', state.video);
  }
  function timeOf(payload) {
    const t = Number(payload && typeof payload === 'object' ? payload.time : payload);
    return Number.isFinite(t) && t >= 0 ? t : 0;
  }
  // Whoever last pressed play/pause/seek is the leader; only their periodic sync is trusted,
  // so two admins with slightly different positions don't fight each other.
  function takeLead() { const st = getState(); if (st) st.leader = socket.id; }

  socket.on('video:play', (p) => { if (canControl()) { takeLead(); updateVideoState({ playing: true, time: timeOf(p) }, p); } });
  socket.on('video:pause', (p) => { if (canControl()) { takeLead(); updateVideoState({ playing: false, time: timeOf(p) }, p); } });
  socket.on('video:seek', (p) => { if (canControl()) { takeLead(); updateVideoState({ time: timeOf(p) }, p); } });
  socket.on('video:sync', (p) => {
    const state = getState();
    if (!state || !canControl() || !state.video.playing) return;
    if (state.leader && state.leader !== socket.id) return;
    state.leader = socket.id;
    updateVideoState({ time: timeOf(p) }, p);
  });

  socket.on('screen:start', () => {
    const state = getState();
    if (!state || !canControl()) return;
    state.screenSharer = { socketId: socket.id, userId: socket.user.id, username: socket.user.username };
    io.to(currentRoomId).emit('screen:started', { username: socket.user.username });
  });

  socket.on('screen:stop', () => {
    const state = getState();
    if (!state || !state.screenSharer || state.screenSharer.socketId !== socket.id) return;
    state.screenSharer = null;
    io.to(currentRoomId).emit('screen:stopped');
  });

  // WebRTC signaling is just relayed through the socket — the server never sees media, only
  // connection setup messages passed between the sharer and each viewer's peer connection.
  socket.on('webrtc:request', () => {
    const state = getState();
    if (!state || !state.screenSharer) return;
    io.to(state.screenSharer.socketId).emit('webrtc:request', { viewerSocketId: socket.id, viewerUsername: socket.user.username });
  });

  // Signals may only go to someone in the same room, and one side must be the current sharer.
  function canSignal(to) {
    const state = getState();
    if (typeof to !== 'string' || !state || !state.screenSharer || !state.participants.has(to)) return false;
    return state.screenSharer.socketId === socket.id || state.screenSharer.socketId === to;
  }

  socket.on('webrtc:offer', ({ to, sdp } = {}) => {
    if (!canSignal(to)) return;
    io.to(to).emit('webrtc:offer', { from: socket.id, sdp });
  });

  socket.on('webrtc:answer', ({ to, sdp } = {}) => {
    if (!canSignal(to)) return;
    io.to(to).emit('webrtc:answer', { from: socket.id, sdp });
  });

  socket.on('webrtc:ice-candidate', ({ to, candidate } = {}) => {
    if (!canSignal(to)) return;
    io.to(to).emit('webrtc:ice-candidate', { from: socket.id, candidate });
  });

  socket.on('room:promote', (targetUserId) => {
    const room = currentRoom();
    if (!room || room.ownerId !== socket.user.id) return;
    if (typeof targetUserId !== 'string' || targetUserId === room.ownerId) return;
    if (!room.admins) room.admins = [];
    if (!room.admins.includes(targetUserId)) {
      room.admins.push(targetUserId);
      saveJSON(ROOMS_FILE, rooms);
    }
    io.to(currentRoomId).emit('room:admins', room.admins);
  });

  socket.on('chat:send', (text) => {
    const state = getState();
    if (!state || typeof text !== 'string') return;
    const clean = text.trim().slice(0, 500);
    if (!clean) return;
    const msg = { username: socket.user.username, text: clean, ts: Date.now() };
    state.chat.push(msg);
    if (state.chat.length > 200) state.chat.shift();
    io.to(currentRoomId).emit('chat:message', msg);
  });

  socket.on('disconnect', () => {
    const state = getState();
    if (!state) return;
    if (state.screenSharer && state.screenSharer.socketId === socket.id) {
      state.screenSharer = null;
      io.to(currentRoomId).emit('screen:stopped');
    }
    const p = state.participants.get(socket.id);
    state.participants.delete(socket.id);
    if (p) {
      const sysMsg = { system: true, text: `${p.username} გავიდა ოთახიდან`, ts: Date.now() };
      state.chat.push(sysMsg);
      io.to(currentRoomId).emit('chat:message', sysMsg);
    }
    io.to(currentRoomId).emit('room:participants', [...state.participants.values()]);
  });
});

const PORT = process.env.PORT || 3000;
loadUsers()
  .then((loaded) => {
    users = loaded;
    server.listen(PORT, () => {
      console.log(`Watch Together listening on http://localhost:${PORT} (users: ${db ? 'Postgres' : 'data/users.json'})`);
    });
  })
  .catch((err) => {
    console.error('Could not load users from the database:', err.message);
    process.exit(1);
  });
