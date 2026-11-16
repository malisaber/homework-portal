// Runs before the server. On a fresh host (no database file) it restores the latest backup from Google Drive.
require('dotenv').config();
const fs = require('fs');
const path = require('path');
const { google } = require('googleapis');

const DB = process.env.DB_PATH || path.join(__dirname, 'data.db');
(async () => {
  const rt = process.env.BACKUP_REFRESH_TOKEN;
  if (fs.existsSync(DB) || !rt) return;
  const c = new google.auth.OAuth2(process.env.GOOGLE_CLIENT_ID, process.env.GOOGLE_CLIENT_SECRET);
  c.setCredentials({ refresh_token: rt });
  const drive = google.drive({ version: 'v3', auth: c });
  const l = await drive.files.list({ q: "name='homework-portal-backup.db' and trashed=false", orderBy: 'modifiedTime desc', fields: 'files(id)' });
  if (!l.data.files.length) return console.log('No backup found in Drive. Starting with an empty database.');
  fs.mkdirSync(path.dirname(DB), { recursive: true });
  const r = await drive.files.get({ fileId: l.data.files[0].id, alt: 'media' }, { responseType: 'stream' });
  await new Promise((ok, bad) => r.data.pipe(fs.createWriteStream(DB + '.tmp')).on('finish', ok).on('error', bad));
  fs.renameSync(DB + '.tmp', DB);
  console.log('Database restored from Google Drive.');
})().catch(e => { console.error('Restore failed. Not starting with an empty database:', e.message); process.exit(1); });
