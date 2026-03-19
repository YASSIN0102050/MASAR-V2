const express     = require('express');
const initSqlJs   = require('sql.js');
const bcrypt      = require('bcryptjs');
const jwt         = require('jsonwebtoken');
const cookieParser= require('cookie-parser');
const path        = require('path');
const fs          = require('fs');
const cors        = require('cors');

const app        = express();
const PORT       = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'masar-secret-2025';
const DB_PATH    = path.join(__dirname, 'masar.db');

let db;

async function initDB() {
  const SQL = await initSqlJs();
  if (fs.existsSync(DB_PATH)) {
    db = new SQL.Database(fs.readFileSync(DB_PATH));
  } else {
    db = new SQL.Database();
  }
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      field TEXT DEFAULT '',
      joined_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS progress (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      course_id TEXT NOT NULL,
      field TEXT DEFAULT '',
      sub_field TEXT DEFAULT '',
      watched_seconds INTEGER DEFAULT 0,
      completed INTEGER DEFAULT 0,
      last_watched TEXT DEFAULT (datetime('now')),
      UNIQUE(user_id, course_id)
    );
    CREATE TABLE IF NOT EXISTS notes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      course_id TEXT NOT NULL,
      timestamp_sec INTEGER DEFAULT 0,
      note TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS saved_courses (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      course_id TEXT NOT NULL,
      UNIQUE(user_id, course_id)
    );
    CREATE TABLE IF NOT EXISTS certificates (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      course_id TEXT NOT NULL,
      course_title TEXT,
      field TEXT,
      level TEXT,
      duration TEXT,
      issued_at TEXT DEFAULT (datetime('now')),
      cert_code TEXT UNIQUE NOT NULL
    );
  `);
  saveDB();
  console.log('✅ Database ready');
}

function saveDB() {
  fs.writeFileSync(DB_PATH, Buffer.from(db.export()));
}

function dbGet(sql, p) {
  p = p || [];
  var s = db.prepare(sql);
  s.bind(p);
  var r = s.step() ? s.getAsObject() : null;
  s.free();
  return r;
}

function dbAll(sql, p) {
  p = p || [];
  var s = db.prepare(sql);
  s.bind(p);
  var r = [];
  while (s.step()) r.push(s.getAsObject());
  s.free();
  return r;
}

function dbRun(sql, p) {
  p = p || [];
  db.run(sql, p);
  saveDB();
  var r = db.exec('SELECT last_insert_rowid() as id');
  return r[0] ? r[0].values[0][0] : null;
}

// ─── MIDDLEWARE ───────────────────────────────────────────
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(cookieParser());

// Serve everything from the root folder (flat structure)
app.use(express.static(path.join(__dirname, '..')));

function auth(req, res, next) {
  var token = req.cookies.masar_token || (req.headers.authorization || '').replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'يجب تسجيل الدخول' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch(e) {
    res.status(401).json({ error: 'الجلسة منتهية' });
  }
}

// ─── AUTH ─────────────────────────────────────────────────
app.post('/api/auth/register', function(req, res) {
  var name     = req.body.name;
  var email    = req.body.email;
  var password = req.body.password;
  var field    = req.body.field || '';
  if (!name || !name.trim() || !email || !email.trim() || !password)
    return res.status(400).json({ error: 'كل الحقول مطلوبة' });
  if (password.length < 6)
    return res.status(400).json({ error: 'كلمة المرور 6 أحرف على الأقل' });
  if (email.indexOf('@') === -1)
    return res.status(400).json({ error: 'بريد إلكتروني غير صحيح' });
  if (dbGet('SELECT id FROM users WHERE email=?', [email.toLowerCase()]))
    return res.status(409).json({ error: 'البريد مسجّل بالفعل' });
  var hashed = bcrypt.hashSync(password, 10);
  var id = dbRun('INSERT INTO users (name,email,password,field) VALUES (?,?,?,?)',
    [name.trim(), email.toLowerCase(), hashed, field]);
  var user  = { id: id, name: name.trim(), email: email.toLowerCase(), field: field };
  var token = jwt.sign(user, JWT_SECRET, { expiresIn: '30d' });
  res.cookie('masar_token', token, { httpOnly: true, maxAge: 30*24*60*60*1000, sameSite: 'lax' });
  res.json({ success: true, user: user, token: token });
});

app.post('/api/auth/login', function(req, res) {
  var email    = req.body.email;
  var password = req.body.password;
  if (!email || !password)
    return res.status(400).json({ error: 'ادخل البريد وكلمة المرور' });
  var user = dbGet('SELECT * FROM users WHERE email=?', [email.toLowerCase()]);
  if (!user || !bcrypt.compareSync(password, user.password))
    return res.status(401).json({ error: 'البريد أو كلمة المرور غلط' });
  var payload = { id: user.id, name: user.name, email: user.email, field: user.field };
  var token   = jwt.sign(payload, JWT_SECRET, { expiresIn: '30d' });
  res.cookie('masar_token', token, { httpOnly: true, maxAge: 30*24*60*60*1000, sameSite: 'lax' });
  res.json({ success: true, user: payload, token: token });
});

app.post('/api/auth/logout', function(req, res) {
  res.clearCookie('masar_token');
  res.json({ success: true });
});

app.get('/api/auth/me', auth, function(req, res) {
  var user = dbGet('SELECT id,name,email,field,joined_at FROM users WHERE id=?', [req.user.id]);
  if (!user) return res.status(404).json({ error: 'المستخدم مش موجود' });
  res.json({
    id:        user.id,
    name:      user.name,
    email:     user.email,
    field:     user.field,
    joined_at: user.joined_at,
    stats: {
      courses:   dbGet('SELECT COUNT(*) as c FROM progress WHERE user_id=?',              [req.user.id]).c || 0,
      completed: dbGet('SELECT COUNT(*) as c FROM progress WHERE user_id=? AND completed=1',[req.user.id]).c || 0,
      certs:     dbGet('SELECT COUNT(*) as c FROM certificates WHERE user_id=?',           [req.user.id]).c || 0,
      saved:     dbGet('SELECT COUNT(*) as c FROM saved_courses WHERE user_id=?',          [req.user.id]).c || 0,
    }
  });
});

// ─── PROGRESS ─────────────────────────────────────────────
app.get('/api/progress', auth, function(req, res) {
  res.json(dbAll('SELECT * FROM progress WHERE user_id=? ORDER BY last_watched DESC', [req.user.id]));
});

app.post('/api/progress', auth, function(req, res) {
  var cid  = req.body.course_id;
  var fld  = req.body.field     || '';
  var sub  = req.body.sub_field || '';
  var secs = req.body.watched_seconds || 0;
  var done = req.body.completed ? 1 : 0;
  var ex   = dbGet('SELECT id FROM progress WHERE user_id=? AND course_id=?', [req.user.id, cid]);
  if (ex) {
    dbRun('UPDATE progress SET watched_seconds=MAX(watched_seconds,?),completed=MAX(completed,?),last_watched=datetime("now") WHERE user_id=? AND course_id=?',
      [secs, done, req.user.id, cid]);
  } else {
    dbRun('INSERT INTO progress (user_id,course_id,field,sub_field,watched_seconds,completed) VALUES (?,?,?,?,?,?)',
      [req.user.id, cid, fld, sub, secs, done]);
  }
  res.json({ success: true });
});

// ─── NOTES ────────────────────────────────────────────────
app.get('/api/notes/:id', auth, function(req, res) {
  res.json(dbAll('SELECT * FROM notes WHERE user_id=? AND course_id=? ORDER BY id ASC', [req.user.id, req.params.id]));
});

app.post('/api/notes', auth, function(req, res) {
  var cid  = req.body.course_id;
  var ts   = req.body.timestamp_sec || 0;
  var note = req.body.note;
  if (!cid || !note || !note.trim()) return res.status(400).json({ error: 'بيانات ناقصة' });
  var id = dbRun('INSERT INTO notes (user_id,course_id,timestamp_sec,note) VALUES (?,?,?,?)',
    [req.user.id, cid, ts, note.trim()]);
  res.json({ success: true, id: id });
});

app.delete('/api/notes/:id', auth, function(req, res) {
  dbRun('DELETE FROM notes WHERE id=? AND user_id=?', [req.params.id, req.user.id]);
  res.json({ success: true });
});

// ─── SAVED ────────────────────────────────────────────────
app.get('/api/saved', auth, function(req, res) {
  res.json(dbAll('SELECT course_id FROM saved_courses WHERE user_id=?', [req.user.id]).map(function(r){ return r.course_id; }));
});

app.post('/api/saved/toggle', auth, function(req, res) {
  var cid = req.body.course_id;
  var ex  = dbGet('SELECT id FROM saved_courses WHERE user_id=? AND course_id=?', [req.user.id, cid]);
  if (ex) {
    dbRun('DELETE FROM saved_courses WHERE user_id=? AND course_id=?', [req.user.id, cid]);
    res.json({ saved: false });
  } else {
    dbRun('INSERT OR IGNORE INTO saved_courses (user_id,course_id) VALUES (?,?)', [req.user.id, cid]);
    res.json({ saved: true });
  }
});

// ─── CERTIFICATES ─────────────────────────────────────────
app.get('/api/certificates', auth, function(req, res) {
  res.json(dbAll('SELECT * FROM certificates WHERE user_id=? ORDER BY issued_at DESC', [req.user.id]));
});

app.post('/api/certificates/issue', auth, function(req, res) {
  var cid   = req.body.course_id;
  var title = req.body.course_title;
  var fld   = req.body.field;
  var lvl   = req.body.level;
  var dur   = req.body.duration;
  if (dbGet('SELECT id FROM certificates WHERE user_id=? AND course_id=?', [req.user.id, cid]))
    return res.json({ success: true, already: true });
  var code = 'MSR-' + Date.now().toString(36).toUpperCase() + '-' + Math.random().toString(36).substr(2,4).toUpperCase();
  dbRun('INSERT INTO certificates (user_id,course_id,course_title,field,level,duration,cert_code) VALUES (?,?,?,?,?,?,?)',
    [req.user.id, cid, title, fld, lvl, dur, code]);
  res.json({ success: true, cert_code: code });
});

// ─── PROFILE ──────────────────────────────────────────────
app.put('/api/profile', auth, function(req, res) {
  var name  = req.body.name;
  var field = req.body.field || '';
  if (!name || !name.trim()) return res.status(400).json({ error: 'الاسم مطلوب' });
  dbRun('UPDATE users SET name=?,field=? WHERE id=?', [name.trim(), field, req.user.id]);
  res.json({ success: true });
});

// ─── FALLBACK ─────────────────────────────────────────────
app.get('*', function(req, res) {
  res.sendFile(path.join(__dirname, '../index.html'));
});

// ─── START ────────────────────────────────────────────────
initDB().then(function() {
  app.listen(PORT, function() {
    console.log('');
    console.log('=================================');
    console.log('  مَسار شغّال على المنفذ ' + PORT);
    console.log('  http://localhost:' + PORT);
    console.log('=================================');
    console.log('');
  });
});