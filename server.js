require('dotenv').config();
const express = require('express');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const archiver = require('archiver');
const Database = require('better-sqlite3');
const { google } = require('googleapis');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, SESSION_SECRET, ADMIN_EMAILS = '' } = process.env;
const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
const MAX_MB = 25;
const STUDENT_DOMAIN = (process.env.STUDENT_EMAIL_DOMAIN || '').toLowerCase().replace(/^@/, '');
const ALLOWED = ['pdf','doc','docx','ppt','pptx','xls','xlsx','txt','zip','png','jpg','jpeg','py','java','c','cpp','ipynb'];

// ---------- Database ----------
const db = new Database(process.env.DB_PATH || path.join(__dirname, 'data.db'));
db.exec(`
CREATE TABLE IF NOT EXISTS admins(email TEXT PRIMARY KEY, refresh_token TEXT, is_super INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS courses(id INTEGER PRIMARY KEY, title TEXT NOT NULL, description TEXT, color TEXT, owner_email TEXT, folder_id TEXT);
CREATE TABLE IF NOT EXISTS homework(id INTEGER PRIMARY KEY, course_id INTEGER, title TEXT NOT NULL, description TEXT, deadline TEXT, folder_id TEXT);
CREATE TABLE IF NOT EXISTS submissions(id INTEGER PRIMARY KEY, homework_id INTEGER, student_name TEXT, file_name TEXT, drive_file_id TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
`);
try { db.exec('ALTER TABLE submissions ADD COLUMN student_email TEXT'); } catch {}
ADMIN_EMAILS.split(',').map(e => e.trim().toLowerCase()).filter(Boolean).forEach(e =>
  db.prepare('INSERT INTO admins(email,is_super) VALUES(?,1) ON CONFLICT(email) DO UPDATE SET is_super=1').run(e));

// ---------- Google helpers ----------
const oauth = () => new google.auth.OAuth2(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, `${BASE_URL}/auth/callback`);
function driveFor(email) {
  const row = db.prepare('SELECT refresh_token FROM admins WHERE email=?').get(email);
  if (!row || !row.refresh_token) throw new Error('The course owner has not connected Google Drive yet.');
  const c = oauth(); c.setCredentials({ refresh_token: row.refresh_token });
  return google.drive({ version: 'v3', auth: c });
}
async function makeFolder(drive, name, parent) {
  const r = await drive.files.create({
    requestBody: { name, mimeType: 'application/vnd.google-apps.folder', ...(parent && { parents: [parent] }) },
    fields: 'id'
  });
  return r.data.id;
}
const clean = s => String(s).replace(/[^\p{L}\p{N}._\- ]/gu, '_').trim().slice(0, 100) || 'untitled';

// ---------- Drive backup of the database ----------
const BACKUP_NAME = 'homework-portal-backup.db';
let backupTimer = null, backupBusy = false, backupFileId = null, lastBackup = null, lastError = null;
function backupClient() {
  let rt = process.env.BACKUP_REFRESH_TOKEN;
  if (!rt) { const r = db.prepare('SELECT refresh_token FROM admins WHERE is_super=1 AND refresh_token IS NOT NULL LIMIT 1').get(); rt = r && r.refresh_token; }
  if (!rt) return null;
  const c = oauth(); c.setCredentials({ refresh_token: rt });
  return google.drive({ version: 'v3', auth: c });
}
async function runBackup() {
  if (backupBusy) return scheduleBackup();
  const drive = backupClient(); if (!drive) return;
  backupBusy = true; const tmp = path.join(os.tmpdir(), 'hp-backup-' + process.pid + '.db');
  try {
    await db.backup(tmp);
    const media = { body: fs.createReadStream(tmp) };
    if (!backupFileId) {
      const l = await drive.files.list({ q: `name='${BACKUP_NAME}' and trashed=false`, orderBy: 'modifiedTime desc', fields: 'files(id)' });
      backupFileId = l.data.files[0] ? l.data.files[0].id : null;
    }
    if (backupFileId) await drive.files.update({ fileId: backupFileId, media });
    else backupFileId = (await drive.files.create({ requestBody: { name: BACKUP_NAME }, media, fields: 'id' })).data.id;
    lastBackup = new Date().toISOString(); lastError = null;
  } catch (e) { lastError = e.message; backupFileId = null; console.error('Backup failed:', e.message); }
  finally { backupBusy = false; fs.unlink(tmp, () => {}); }
}
function scheduleBackup() { clearTimeout(backupTimer); backupTimer = setTimeout(runBackup, 5000); }

// ---------- App ----------
const app = express();
app.set('trust proxy', 1);
app.use(express.json());
app.use('/api', (req, res, next) => { // back up after every successful change
  if (req.method !== 'GET') res.on('finish', () => { if (res.statusCode < 400) scheduleBackup(); });
  next();
});
app.use(session({
  secret: SESSION_SECRET || 'dev-secret', resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: BASE_URL.startsWith('https'), maxAge: 7 * 864e5 }
}));
app.use(express.static(path.join(__dirname, 'public')));

const getAdmin = req => req.session.email && db.prepare('SELECT * FROM admins WHERE email=?').get(req.session.email);
const needAdmin = (req, res, next) => { const a = getAdmin(req); if (!a) return res.status(401).json({ error: 'Please sign in.' }); req.admin = a; next(); };
const needSuper = (req, res, next) => needAdmin(req, res, () => req.admin.is_super ? next() : res.status(403).json({ error: 'Super admin only.' }));
const canManage = (a, c) => !!a && (!!a.is_super || c.owner_email === a.email);
const wrap = fn => (req, res) => Promise.resolve(fn(req, res)).catch(e => res.status(500).json({ error: e.message }));

// ---------- Auth ----------
app.get('/auth/login', (req, res) => res.redirect(oauth().generateAuthUrl({
  access_type: 'offline', prompt: 'consent',
  scope: ['openid', 'email', 'https://www.googleapis.com/auth/drive.file']
})));
app.get('/auth/student', (req, res) => {
  req.session.back = /^\d+$/.test(req.query.course || '') ? `/#/course/${req.query.course}` : '/';
  res.redirect(oauth().generateAuthUrl({ scope: ['openid', 'email', 'profile'], state: 'student', prompt: 'select_account' }));
});
app.get('/auth/callback', async (req, res) => {
  try {
    const c = oauth(); const { tokens } = await c.getToken(req.query.code); c.setCredentials(tokens);
    const { data } = await google.oauth2({ version: 'v2', auth: c }).userinfo.get();
    const email = data.email.toLowerCase();
    if (req.query.state === 'student') {
      if (STUDENT_DOMAIN && !email.endsWith('@' + STUDENT_DOMAIN))
        return res.status(403).send(`Please sign in with your @${STUDENT_DOMAIN} account. <a href="/">Back</a>`);
      req.session.student = { email, name: data.name || email };
      const back = req.session.back || '/'; delete req.session.back;
      return res.redirect(back);
    }
    if (!db.prepare('SELECT 1 FROM admins WHERE email=?').get(email))
      return res.status(403).send('This Google account is not an admin. <a href="/">Back</a>');
    if (!String(tokens.scope || '').includes('auth/drive.file'))
      return res.status(403).send('Google Drive permission was not granted. On the Google screen, tick the box that allows access to Drive files, then continue. <a href="/auth/login">Try again</a>');
    if (tokens.refresh_token) db.prepare('UPDATE admins SET refresh_token=? WHERE email=?').run(tokens.refresh_token, email);
    scheduleBackup();
    req.session.email = email; res.redirect('/#/admin');
  } catch (e) { res.status(500).send('Sign-in failed. <a href="/">Back</a>'); }
});
app.get('/auth/logout', (req, res) => req.session.destroy(() => res.redirect('/')));
app.get('/api/me', (req, res) => { const a = getAdmin(req); res.json({ admin: a ? { email: a.email, isSuper: !!a.is_super } : null, student: req.session.student || null }); });

// ---------- Public: courses & homework ----------
const pub = (c, a) => ({ id: c.id, title: c.title, description: c.description, color: c.color, hw_count: c.hw_count, can_manage: canManage(a, c) });
app.get('/api/courses', (req, res) => {
  const a = getAdmin(req);
  res.json(db.prepare('SELECT c.*,(SELECT COUNT(*) FROM homework WHERE course_id=c.id) hw_count FROM courses c ORDER BY c.id DESC').all().map(c => pub(c, a)));
});
app.get('/api/courses/:id', (req, res) => {
  const c = db.prepare('SELECT * FROM courses WHERE id=?').get(req.params.id);
  if (!c) return res.status(404).json({ error: 'Course not found.' });
  res.json({ course: pub(c, getAdmin(req)), homework: db.prepare('SELECT id,title,description,deadline FROM homework WHERE course_id=? ORDER BY id').all(c.id) });
});

// ---------- Admin: courses & homework ----------
app.post('/api/courses', needAdmin, wrap(async (req, res) => {
  const { title, description = '', color = '#4f46e5' } = req.body;
  if (!title || !/^#[0-9a-f]{6}$/i.test(color)) return res.status(400).json({ error: 'Title and a valid colour are required.' });
  const folder = await makeFolder(driveFor(req.admin.email), clean(title));
  db.prepare('INSERT INTO courses(title,description,color,owner_email,folder_id) VALUES(?,?,?,?,?)').run(title, description, color, req.admin.email, folder);
  res.json({ ok: true });
}));
app.delete('/api/courses/:id', needAdmin, (req, res) => {
  const c = db.prepare('SELECT * FROM courses WHERE id=?').get(req.params.id);
  if (!c || !canManage(req.admin, c)) return res.status(403).json({ error: 'Not allowed.' });
  const ids = db.prepare('SELECT id FROM homework WHERE course_id=?').all(c.id).map(h => h.id);
  ids.forEach(id => db.prepare('DELETE FROM submissions WHERE homework_id=?').run(id));
  db.prepare('DELETE FROM homework WHERE course_id=?').run(c.id);
  db.prepare('DELETE FROM courses WHERE id=?').run(c.id);
  res.json({ ok: true }); // Drive files are kept
});
app.post('/api/courses/:id/homework', needAdmin, wrap(async (req, res) => {
  const c = db.prepare('SELECT * FROM courses WHERE id=?').get(req.params.id);
  if (!c || !canManage(req.admin, c)) return res.status(403).json({ error: 'Not allowed.' });
  const { title, description = '', deadline = null } = req.body;
  if (!title) return res.status(400).json({ error: 'Title is required.' });
  const folder = await makeFolder(driveFor(c.owner_email), clean(title), c.folder_id);
  db.prepare('INSERT INTO homework(course_id,title,description,deadline,folder_id) VALUES(?,?,?,?,?)').run(c.id, title, description, deadline || null, folder);
  res.json({ ok: true });
}));
const hwWithCourse = id => db.prepare('SELECT h.*,c.owner_email FROM homework h JOIN courses c ON c.id=h.course_id WHERE h.id=?').get(id);
app.delete('/api/homework/:id', needAdmin, (req, res) => {
  const h = hwWithCourse(req.params.id);
  if (!h || !canManage(req.admin, h)) return res.status(403).json({ error: 'Not allowed.' });
  db.prepare('DELETE FROM submissions WHERE homework_id=?').run(h.id);
  db.prepare('DELETE FROM homework WHERE id=?').run(h.id);
  res.json({ ok: true });
});
app.get('/api/homework/:id/submissions', needAdmin, (req, res) => {
  const h = hwWithCourse(req.params.id);
  if (!h || !canManage(req.admin, h)) return res.status(403).json({ error: 'Not allowed.' });
  res.json(db.prepare('SELECT student_name,student_email,file_name,drive_file_id,created_at FROM submissions WHERE homework_id=? ORDER BY id DESC').all(h.id));
});

// ---------- Super admin: manage admins ----------
app.get('/api/admins', needSuper, (req, res) =>
  res.json(db.prepare('SELECT email,is_super,refresh_token IS NOT NULL AS drive FROM admins ORDER BY email').all()));
app.post('/api/admins', needSuper, (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  if (!/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: 'Enter a valid email.' });
  db.prepare('INSERT OR IGNORE INTO admins(email) VALUES(?)').run(email); res.json({ ok: true });
});
app.delete('/api/admins/:email', needSuper, (req, res) => {
  if (req.params.email === req.admin.email) return res.status(400).json({ error: 'You cannot remove yourself.' });
  db.prepare('DELETE FROM admins WHERE email=?').run(req.params.email.toLowerCase()); res.json({ ok: true });
});

// ---------- Super admin: backup status ----------
const backupStatus = () => ({ enabled: !!backupClient(), last: lastBackup, error: lastError, tokenInEnv: !!process.env.BACKUP_REFRESH_TOKEN });
app.get('/api/backup', needSuper, (req, res) => res.json(backupStatus()));
app.post('/api/backup/now', needSuper, wrap(async (req, res) => { await runBackup(); res.json(backupStatus()); }));
app.get('/api/backup/token', needSuper, (req, res) => {
  res.set('Cache-Control', 'no-store');
  res.json({ token: req.admin.refresh_token || null });
});

// ---------- Admin: download submissions as zip ----------
async function sendZip(res, zipName, groups, ownerEmail) {
  const drive = driveFor(ownerEmail);
  res.setHeader('Content-Type', 'application/zip');
  res.setHeader('Content-Disposition', `attachment; filename*=UTF-8''${encodeURIComponent(clean(zipName))}.zip`);
  const zip = archiver('zip'); zip.on('error', () => res.end()); zip.pipe(res);
  for (const g of groups) for (const s of g.rows) {
    try {
      const r = await drive.files.get({ fileId: s.drive_file_id, alt: 'media' }, { responseType: 'stream' });
      zip.append(r.data, { name: `${g.folder ? clean(g.folder) + '/' : ''}${s.id}_${s.file_name}` });
      await new Promise(ok => { r.data.on('end', ok); r.data.on('error', ok); });
    } catch { /* file deleted from Drive: skip */ }
  }
  await zip.finalize();
}
const subsOf = id => db.prepare('SELECT id,file_name,drive_file_id FROM submissions WHERE homework_id=? ORDER BY id').all(id);
app.get('/api/homework/:id/download', needAdmin, wrap(async (req, res) => {
  const h = hwWithCourse(req.params.id);
  if (!h || !canManage(req.admin, h)) return res.status(403).json({ error: 'Not allowed.' });
  const rows = subsOf(h.id);
  if (!rows.length) return res.status(404).json({ error: 'No submissions yet.' });
  await sendZip(res, h.title, [{ rows }], h.owner_email);
}));
app.get('/api/courses/:id/download', needAdmin, wrap(async (req, res) => {
  const c = db.prepare('SELECT * FROM courses WHERE id=?').get(req.params.id);
  if (!c || !canManage(req.admin, c)) return res.status(403).json({ error: 'Not allowed.' });
  const groups = db.prepare('SELECT id,title FROM homework WHERE course_id=?').all(c.id)
    .map(h => ({ folder: h.title, rows: subsOf(h.id) })).filter(g => g.rows.length);
  if (!groups.length) return res.status(404).json({ error: 'No submissions yet.' });
  await sendZip(res, c.title, groups, c.owner_email);
}));

// ---------- Student upload (signed-in students) ----------
const upload = multer({
  dest: os.tmpdir(), limits: { fileSize: MAX_MB * 1024 * 1024 },
  fileFilter: (req, f, cb) => ALLOWED.includes(path.extname(f.originalname).slice(1).toLowerCase())
    ? cb(null, true) : cb(new Error('File type not allowed. Allowed: ' + ALLOWED.join(', ')))
});
const limiter = rateLimit({ windowMs: 10 * 60 * 1000, limit: 30, message: { error: 'Too many uploads. Try again later.' } });
app.post('/api/homework/:id/upload', limiter, (req, res) => {
  upload.single('file')(req, res, async err => {
    try {
      if (err) throw new Error(err.code === 'LIMIT_FILE_SIZE' ? `File is larger than ${MAX_MB} MB.` : err.message);
      const h = hwWithCourse(req.params.id);
      const st = req.session.student;
      if (!h) throw new Error('Assignment not found.');
      if (!st) throw new Error('Please sign in with Google to upload.');
      if (!req.file) throw new Error('Please choose a file.');
      if (h.deadline && new Date(h.deadline) < new Date()) throw new Error('The deadline has passed.');
      const drive = driveFor(h.owner_email);
      const fileName = `${clean(st.name)}_${clean(req.file.originalname)}`;
      const r = await drive.files.create({
        requestBody: { name: fileName, parents: [h.folder_id], description: st.email },
        media: { body: fs.createReadStream(req.file.path) }, fields: 'id'
      });
      db.prepare('INSERT INTO submissions(homework_id,student_name,student_email,file_name,drive_file_id) VALUES(?,?,?,?,?)').run(h.id, st.name, st.email, fileName, r.data.id);
      res.json({ ok: true });
    } catch (e) { res.status(400).json({ error: e.message }); }
    finally { if (req.file) fs.unlink(req.file.path, () => {}); }
  });
});

app.listen(process.env.PORT || 3000, () => console.log(`Running at ${BASE_URL}`));
setTimeout(runBackup, 10000);
