try { process.loadEnvFile(); } catch {} // loads .env locally if present; on Render env vars are injected directly

const express = require('express');
const http = require('http');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { Server } = require('socket.io');

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || '';
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || '';

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

let users = loadJSON(USERS_FILE); // [{id, username, usernameLower, email, emailLower, passwordHash, friends, createdAt}]
let rooms = loadJSON(ROOMS_FILE); // [{id, name, ownerId, ownerUsername, passwordHash, videoUrl, admins, createdAt}]

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
  res.setHeader('Set-Cookie', `watch_session=${token}; HttpOnly; Path=/; Max-Age=${maxAge}; SameSite=Lax`);
}
function clearSessionCookie(res) {
  res.setHeader('Set-Cookie', 'watch_session=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax');
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

function publicUser(u) {
  return { id: u.id, username: u.username };
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

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public'), { index: 'login.html' }));

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

// ---------- Auth ----------
app.post('/api/register', (req, res) => {
  const { username, password, email } = req.body || {};
  if (typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'INVALID_INPUT' });
  }
  const name = username.trim();
  if (name.length < 3 || name.length > 20 || !USERNAME_RE.test(name)) {
    return res.status(400).json({ error: 'BAD_USERNAME' });
  }
  if (password.length < 4) {
    return res.status(400).json({ error: 'BAD_PASSWORD' });
  }
  const lower = name.toLowerCase();
  if (users.some((u) => u.usernameLower === lower)) {
    return res.status(409).json({ error: 'USERNAME_TAKEN' });
  }
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
    passwordHash: bcrypt.hashSync(password, 10),
    createdAt: Date.now(),
  };
  users.push(user);
  saveJSON(USERS_FILE, users);

  const token = crypto.randomBytes(24).toString('hex');
  sessions.set(token, user.id);
  saveSessions();
  setSessionCookie(res, token);
  res.json({ ok: true, user: publicUser(user) });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  if (typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'INVALID_INPUT' });
  }
  const identifier = username.trim().toLowerCase();
  const user = users.find((u) => u.usernameLower === identifier || (u.emailLower && u.emailLower === identifier));
  if (!user || !user.passwordHash || !bcrypt.compareSync(password, user.passwordHash)) {
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
  res.setHeader('Set-Cookie', `oauth_state=${state}; HttpOnly; Path=/; Max-Age=600; SameSite=Lax`);
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
      saveJSON(USERS_FILE, users);
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
  res.json({ ok: true, user: publicUser(req.user) });
});

// ---------- Friends ----------
app.get('/api/friends', requireAuth, (req, res) => {
  const friendIds = req.user.friends || [];
  const list = friendIds.map((id) => users.find((u) => u.id === id)).filter(Boolean).map(publicUser);
  res.json({ ok: true, friends: list });
});

app.post('/api/friends', requireAuth, (req, res) => {
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
  saveJSON(USERS_FILE, users);
  res.json({ ok: true, friend: publicUser(friend) });
});

app.delete('/api/friends/:id', requireAuth, (req, res) => {
  req.user.friends = (req.user.friends || []).filter((id) => id !== req.params.id);
  saveJSON(USERS_FILE, users);
  res.json({ ok: true });
});

// ---------- Rooms ----------
app.get('/api/rooms', requireAuth, (req, res) => {
  const q = (req.query.search || '').toString().trim().toLowerCase();
  let list = rooms;
  if (q) list = list.filter((r) => r.name.toLowerCase().includes(q));
  list = list.slice().sort((a, b) => b.createdAt - a.createdAt);
  res.json({ ok: true, rooms: list.map(publicRoom) });
});

app.post('/api/rooms', requireAuth, (req, res) => {
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
    passwordHash: bcrypt.hashSync(password, 10),
    videoUrl: typeof videoUrl === 'string' ? videoUrl.trim() : '',
    admins: [],
    createdAt: Date.now(),
  };
  rooms.push(room);
  saveJSON(ROOMS_FILE, rooms);
  roomAccess.set(room.id, new Set([req.user.id]));
  res.json({ ok: true, room: publicRoom(room) });
});

app.post('/api/rooms/:id/join', requireAuth, (req, res) => {
  const room = rooms.find((r) => r.id === req.params.id);
  if (!room) return res.status(404).json({ error: 'NOT_FOUND' });
  const { password } = req.body || {};
  const isOwner = room.ownerId === req.user.id;
  if (!isOwner) {
    if (typeof password !== 'string' || !bcrypt.compareSync(password, room.passwordHash)) {
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

const server = http.createServer(app);
const io = new Server(server);

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
    state.participants.set(socket.id, { userId: socket.user.id, username: socket.user.username });

    socket.emit('room:init', {
      roomName: room.name,
      ownerId: room.ownerId,
      admins: room.admins || [],
      me: { id: socket.user.id, username: socket.user.username },
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

  socket.on('video:setSource', (url) => {
    const state = getState();
    if (!state || !currentRoomId) return;
    if (!canControl()) return;
    if (typeof url !== 'string') return;
    if (state.screenSharer) {
      state.screenSharer = null;
      io.to(currentRoomId).emit('screen:stopped');
    }
    state.video = { url: url.trim(), playing: false, time: 0, updatedAt: Date.now() };
    io.to(currentRoomId).emit('video:source', state.video);
  });

  function updateVideoState(partial) {
    const state = getState();
    if (!state) return;
    state.video = { ...state.video, ...partial, updatedAt: Date.now() };
    socket.to(currentRoomId).emit('video:state', state.video);
  }

  socket.on('video:play', (time) => { if (canControl()) updateVideoState({ playing: true, time: Number(time) || 0 }); });
  socket.on('video:pause', (time) => { if (canControl()) updateVideoState({ playing: false, time: Number(time) || 0 }); });
  socket.on('video:seek', (time) => { if (canControl()) updateVideoState({ time: Number(time) || 0 }); });

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

  socket.on('webrtc:offer', ({ to, sdp } = {}) => {
    if (typeof to !== 'string') return;
    io.to(to).emit('webrtc:offer', { from: socket.id, sdp });
  });

  socket.on('webrtc:answer', ({ to, sdp } = {}) => {
    if (typeof to !== 'string') return;
    io.to(to).emit('webrtc:answer', { from: socket.id, sdp });
  });

  socket.on('webrtc:ice-candidate', ({ to, candidate } = {}) => {
    if (typeof to !== 'string') return;
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
server.listen(PORT, () => {
  console.log(`Watch Together listening on http://localhost:${PORT}`);
});
