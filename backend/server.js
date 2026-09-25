// server.js (v7 — Clean Numeric PostgreSQL ID & Search)
require('dotenv').config();
const express    = require('express');
const bodyParser = require('body-parser');
const cors       = require('cors');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const db         = require('./db');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── Environment Variables & Secrets ──
const JWT_SECRET      = process.env.JWT_SECRET || 'p26_sync_secret_change_in_prod';
const JWT_EXPIRES     = '12h';
const ADMIN_SETUP_KEY = process.env.ADMIN_SETUP_KEY || 'P26-ADMIN-8X7K-2026';

app.use(cors());
app.use(bodyParser.json());

// ═══════════════════════════════════════════════════════════
// DATABASE BOOTSTRAP & SEQUENCE SYNC
// ═══════════════════════════════════════════════════════════
async function bootstrapDB() {
  // 1. Create users table if missing
  await db.query(`
    CREATE TABLE IF NOT EXISTS users (
      id            SERIAL PRIMARY KEY,
      username      VARCHAR(50) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role          VARCHAR(10) NOT NULL CHECK (role IN ('ADMIN','TEACHER')),
      status        VARCHAR(20) NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','DISABLED')),
      created_at    TIMESTAMP DEFAULT NOW()
    )
  `);

  // Migration: Add status column if it didn't exist in older table
  await db.query(`
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name='users' AND column_name='status'
      ) THEN
        ALTER TABLE users ADD COLUMN status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','DISABLED'));
      END IF;
    END $$;
  `);

  // 2. Create audit logs table
  await db.query(`
    CREATE TABLE IF NOT EXISTS audit_logs (
      id             SERIAL PRIMARY KEY,
      admin_id       INTEGER,
      action         VARCHAR(100) NOT NULL,
      target_user_id INTEGER,
      details        TEXT,
      created_at     TIMESTAMP DEFAULT NOW()
    )
  `);

  // 3. Create students table if missing & remove legacy student_code column
  await db.query(`
    CREATE TABLE IF NOT EXISTS students (
      id         SERIAL PRIMARY KEY,
      name       VARCHAR(100) NOT NULL,
      roll_no    VARCHAR(20),
      course     VARCHAR(100),
      attendance INTEGER NOT NULL DEFAULT 0,
      version    INTEGER NOT NULL DEFAULT 1,
      updated_at TIMESTAMP DEFAULT NOW()
    );

    -- Clean up legacy student_code column if it was added earlier
    DO $$
    BEGIN
      IF EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name='students' AND column_name='student_code'
      ) THEN
        ALTER TABLE students DROP COLUMN student_code;
      END IF;
    END $$;
  `);

  // 4. Create sync_changes and conflicts tables if missing
  await db.query(`
    CREATE TABLE IF NOT EXISTS sync_changes (
      change_id    SERIAL PRIMARY KEY,
      student_id   INTEGER NOT NULL,
      user_id      VARCHAR(50),
      device_id    VARCHAR(50),
      field        VARCHAR(50),
      old_value    TEXT,
      new_value    TEXT,
      base_version INTEGER,
      status       VARCHAR(20),
      created_at   TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS conflicts (
      conflict_id      SERIAL PRIMARY KEY,
      change_id        INTEGER,
      student_id       INTEGER NOT NULL,
      server_version   INTEGER,
      incoming_version INTEGER,
      server_value     TEXT,
      incoming_value   TEXT,
      status           VARCHAR(20),
      created_at       TIMESTAMP DEFAULT NOW()
    );
  `);

  // 5. Safely sync sequence with table state (restarts at 1 if empty, or max_id if non-empty)
  const _bootstrapCount = await db.query('SELECT COUNT(*) AS cnt FROM students');
  if (parseInt(_bootstrapCount.rows[0].cnt, 10) === 0) {
    await db.query(`SELECT setval(pg_get_serial_sequence('students', 'id'), 1, false)`);
  } else {
    await db.query(`SELECT setval(pg_get_serial_sequence('students', 'id'), (SELECT MAX(id) FROM students), true)`);
  }

  const seqResult = await db.query(`SELECT last_value, is_called FROM students_id_seq`).catch(() => ({ rows: [{ last_value: 'N/A' }] }));
  console.log(`[Bootstrap] Database tables verified. Current students sequence: ${seqResult.rows[0]?.last_value} (is_called: ${seqResult.rows[0]?.is_called})`);

  // 6. Mark any orphaned OPEN conflicts (student already deleted) as STUDENT_DELETED
  const orphanResult = await db.query(`
    UPDATE conflicts
    SET status = 'STUDENT_DELETED'
    WHERE status = 'OPEN'
      AND student_id NOT IN (SELECT id FROM students)
  `);
  if (orphanResult.rowCount > 0) {
    console.log(`[Bootstrap] Marked ${orphanResult.rowCount} orphaned OPEN conflict(s) as STUDENT_DELETED.`);
  }
}

// ── Helper: Reset sequence to 1 ONLY if students table is completely empty ──
async function resetStudentSequenceIfEmpty() {
  await db.query(`
    SELECT CASE
      WHEN (SELECT COUNT(*) FROM students) = 0
      THEN setval(pg_get_serial_sequence('students', 'id'), 1, false)
    END
  `);
}

// ═══════════════════════════════════════════════════════════
// AUTH MIDDLEWARE
// ═══════════════════════════════════════════════════════════
async function requireAuth(req, res, next) {
  const header = req.headers['authorization'];
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  const token = header.slice(7);
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const { rows } = await db.query('SELECT id, username, role, status FROM users WHERE id = $1', [decoded.id]);
    if (rows.length === 0 || rows[0].status === 'DISABLED') {
      return res.status(401).json({ error: 'Your account has been disabled or removed. Contact an administrator.' });
    }
    req.user = { ...rows[0], deviceId: decoded.deviceId };
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'ADMIN') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
}

async function logAudit(adminId, action, targetUserId, details) {
  try {
    await db.query(
      `INSERT INTO audit_logs (admin_id, action, target_user_id, details) VALUES ($1, $2, $3, $4)`,
      [adminId, action, targetUserId, details]
    );
  } catch (err) {
    console.error('Audit log error:', err);
  }
}

// ═══════════════════════════════════════════════════════════
// PUBLIC AUTH ROUTES
// ═══════════════════════════════════════════════════════════

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  const { username, password, deviceId } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  try {
    const { rows } = await db.query('SELECT * FROM users WHERE username = $1', [username.trim()]);
    if (rows.length === 0) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }
    const user = rows[0];

    if (user.status === 'DISABLED') {
      return res.status(403).json({ error: 'Your account has been disabled. Contact an administrator.' });
    }

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role, deviceId: deviceId || 'WEB' },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES }
    );

    res.json({
      token,
      user: { id: user.id, username: user.username, role: user.role, status: user.status }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Server unavailable. Please try again.' });
  }
});

// POST /api/auth/register (Public — creates TEACHER only)
app.post('/api/auth/register', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !username.trim()) {
    return res.status(400).json({ error: 'Username is required' });
  }
  if (!password) {
    return res.status(400).json({ error: 'Password is required' });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  }

  try {
    const hash = await bcrypt.hash(password, 10);
    await db.query(
      `INSERT INTO users (username, password_hash, role, status) VALUES ($1, $2, 'TEACHER', 'ACTIVE')`,
      [username.trim(), hash]
    );
    res.json({ status: 'REGISTERED' });
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ error: 'Username already exists' });
    }
    console.error('Register error:', err);
    res.status(500).json({ error: 'Server unavailable. Please try again.' });
  }
});

// POST /api/auth/register-admin (Admin registration with secret setup key)
app.post('/api/auth/register-admin', async (req, res) => {
  const { username, password, adminKey } = req.body;

  if (!username || !username.trim()) {
    return res.status(400).json({ error: 'Username is required' });
  }
  if (!password) {
    return res.status(400).json({ error: 'Password is required' });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  }
  if (!adminKey || adminKey.trim() !== ADMIN_SETUP_KEY) {
    return res.status(403).json({ error: 'Invalid admin registration key' });
  }

  try {
    const hash = await bcrypt.hash(password, 10);
    const { rows } = await db.query(
      `INSERT INTO users (username, password_hash, role, status) VALUES ($1, $2, 'ADMIN', 'ACTIVE') RETURNING id, username, role`,
      [username.trim(), hash]
    );
    const newAdmin = rows[0];
    await logAudit(newAdmin.id, 'ADMIN_BOOTSTRAP_REGISTERED', newAdmin.id, `Admin registered via Setup Key: ${newAdmin.username}`);
    res.json({ status: 'REGISTERED', role: 'ADMIN' });
  } catch (err) {
    if (err.code === '23505') {
      return res.status(409).json({ error: 'Username already exists' });
    }
    console.error('Admin register error:', err);
    res.status(500).json({ error: 'Server unavailable. Please try again.' });
  }
});

// POST /api/auth/change-password
app.post('/api/auth/change-password', requireAuth, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword || newPassword.length < 6) {
    return res.status(400).json({ error: 'currentPassword and newPassword (min 6 chars) required' });
  }

  try {
    const { rows } = await db.query('SELECT * FROM users WHERE id = $1', [req.user.id]);
    const user = rows[0];
    const valid = await bcrypt.compare(currentPassword, user.password_hash);
    if (!valid) return res.status(401).json({ error: 'Current password is wrong' });

    const hash = await bcrypt.hash(newPassword, 10);
    await db.query('UPDATE users SET password_hash = $1 WHERE id = $2', [hash, req.user.id]);
    res.json({ status: 'PASSWORD_CHANGED' });
  } catch (err) {
    console.error('Change-password error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ═══════════════════════════════════════════════════════════
// ADMIN DASHBOARD & USER MANAGEMENT ROUTES (ADMIN only)
// ═══════════════════════════════════════════════════════════

async function countActiveAdmins() {
  const { rows } = await db.query(`SELECT COUNT(*) as count FROM users WHERE role = 'ADMIN' AND status = 'ACTIVE'`);
  return parseInt(rows[0].count, 10);
}

// GET /api/admin/users
app.get(['/api/users', '/api/admin/users'], requireAuth, requireAdmin, async (req, res) => {
  const query = req.query.q ? `%${req.query.q.trim()}%` : null;
  try {
    let sql = 'SELECT id, username, role, status, created_at FROM users';
    let params = [];
    if (query) {
      sql += ' WHERE username ILIKE $1';
      params.push(query);
    }
    sql += ' ORDER BY id ASC';
    const { rows } = await db.query(sql, params);
    res.json(rows);
  } catch (err) {
    console.error('Fetch users error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /api/admin/users
app.post(['/api/admin/users', '/api/users'], requireAuth, requireAdmin, async (req, res) => {
  const { username, password, role } = req.body;
  if (!username || !password || !role) {
    return res.status(400).json({ error: 'Username, password and role are required' });
  }
  if (!['ADMIN', 'TEACHER'].includes(role)) {
    return res.status(400).json({ error: 'Role must be ADMIN or TEACHER' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }

  try {
    const hash = await bcrypt.hash(password, 10);
    const { rows } = await db.query(
      `INSERT INTO users (username, password_hash, role, status) VALUES ($1, $2, $3, 'ACTIVE') RETURNING id, username, role, status, created_at`,
      [username.trim(), hash, role]
    );
    const createdUser = rows[0];
    await logAudit(req.user.id, 'ADMIN_CREATED_USER', createdUser.id, `Created ${role} account: ${username}`);
    res.json({ status: 'CREATED', user: createdUser });
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'Username already exists' });
    console.error('Create user error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /api/admin/users/:id/disable
app.post('/api/admin/users/:id/disable', requireAuth, requireAdmin, async (req, res) => {
  const targetId = parseInt(req.params.id, 10);
  try {
    const { rows } = await db.query('SELECT * FROM users WHERE id = $1', [targetId]);
    if (rows.length === 0) return res.status(404).json({ error: 'User not found' });
    const targetUser = rows[0];

    if (targetUser.role === 'ADMIN' && targetUser.status === 'ACTIVE') {
      const activeAdmins = await countActiveAdmins();
      if (activeAdmins <= 1) {
        return res.status(400).json({ error: 'At least one active ADMIN account must remain.' });
      }
    }

    await db.query(`UPDATE users SET status = 'DISABLED' WHERE id = $1`, [targetId]);
    await logAudit(req.user.id, 'ADMIN_DISABLED_USER', targetId, `Disabled user ${targetUser.username}`);
    res.json({ status: 'DISABLED', userId: targetId });
  } catch (err) {
    console.error('Disable user error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /api/admin/users/:id/enable
app.post('/api/admin/users/:id/enable', requireAuth, requireAdmin, async (req, res) => {
  const targetId = parseInt(req.params.id, 10);
  try {
    const { rows } = await db.query('SELECT * FROM users WHERE id = $1', [targetId]);
    if (rows.length === 0) return res.status(404).json({ error: 'User not found' });
    const targetUser = rows[0];

    await db.query(`UPDATE users SET status = 'ACTIVE' WHERE id = $1`, [targetId]);
    await logAudit(req.user.id, 'ADMIN_ENABLED_USER', targetId, `Enabled user ${targetUser.username}`);
    res.json({ status: 'ACTIVE', userId: targetId });
  } catch (err) {
    console.error('Enable user error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// PUT /api/admin/users/:id/role
app.put('/api/admin/users/:id/role', requireAuth, requireAdmin, async (req, res) => {
  const targetId = parseInt(req.params.id, 10);
  const { role } = req.body;
  if (!['ADMIN', 'TEACHER'].includes(role)) {
    return res.status(400).json({ error: 'Role must be ADMIN or TEACHER' });
  }

  try {
    const { rows } = await db.query('SELECT * FROM users WHERE id = $1', [targetId]);
    if (rows.length === 0) return res.status(404).json({ error: 'User not found' });
    const targetUser = rows[0];

    if (targetUser.role === 'ADMIN' && role === 'TEACHER' && targetUser.status === 'ACTIVE') {
      const activeAdmins = await countActiveAdmins();
      if (activeAdmins <= 1) {
        return res.status(400).json({ error: 'At least one active ADMIN account must remain.' });
      }
    }

    await db.query(`UPDATE users SET role = $1 WHERE id = $2`, [role, targetId]);
    await logAudit(req.user.id, 'ADMIN_CHANGED_ROLE', targetId, `Changed role of ${targetUser.username} to ${role}`);
    res.json({ status: 'ROLE_UPDATED', userId: targetId, role });
  } catch (err) {
    console.error('Change role error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /api/admin/users/:id/reset-password
app.post('/api/admin/users/:id/reset-password', requireAuth, requireAdmin, async (req, res) => {
  const targetId = parseInt(req.params.id, 10);
  const { newPassword } = req.body;
  if (!newPassword || newPassword.length < 6) {
    return res.status(400).json({ error: 'New password must be at least 6 characters' });
  }

  try {
    const { rows } = await db.query('SELECT * FROM users WHERE id = $1', [targetId]);
    if (rows.length === 0) return res.status(404).json({ error: 'User not found' });
    const targetUser = rows[0];

    const hash = await bcrypt.hash(newPassword, 10);
    await db.query('UPDATE users SET password_hash = $1 WHERE id = $2', [hash, targetId]);
    await logAudit(req.user.id, 'ADMIN_RESET_PASSWORD', targetId, `Reset password for ${targetUser.username}`);
    res.json({ status: 'PASSWORD_RESET', userId: targetId });
  } catch (err) {
    console.error('Reset password error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// DELETE /api/admin/users/:id
app.delete(['/api/admin/users/:id', '/api/users/:id'], requireAuth, requireAdmin, async (req, res) => {
  const targetId = parseInt(req.params.id, 10);
  if (targetId === req.user.id) {
    return res.status(400).json({ error: 'You cannot delete your own account' });
  }

  try {
    const { rows } = await db.query('SELECT * FROM users WHERE id = $1', [targetId]);
    if (rows.length === 0) return res.status(404).json({ error: 'User not found' });
    const targetUser = rows[0];

    if (targetUser.role === 'ADMIN' && targetUser.status === 'ACTIVE') {
      const activeAdmins = await countActiveAdmins();
      if (activeAdmins <= 1) {
        return res.status(400).json({ error: 'At least one active ADMIN account must remain.' });
      }
    }

    await db.query('DELETE FROM users WHERE id = $1', [targetId]);
    await logAudit(req.user.id, 'ADMIN_DELETED_USER', targetId, `Deleted user ${targetUser.username}`);
    res.json({ status: 'DELETED', userId: targetId });
  } catch (err) {
    console.error('Delete user error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ═══════════════════════════════════════════════════════════
// ADMIN MONITORING & SYSTEM STATUS ROUTES
// ═══════════════════════════════════════════════════════════

// GET /api/admin/sync-changes
app.get('/api/admin/sync-changes', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { rows } = await db.query(`
      SELECT 
        s.change_id,
        s.student_id,
        s.user_id,
        COALESCE(u.username, 'User #' || s.user_id::text) as username,
        s.device_id,
        s.field,
        s.old_value,
        s.new_value,
        s.base_version,
        s.status,
        s.created_at
      FROM sync_changes s
      LEFT JOIN users u ON s.user_id = u.id
      ORDER BY s.change_id DESC
      LIMIT 100
    `);
    res.json(rows);
  } catch (err) {
    console.error('Fetch sync changes error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /api/admin/conflicts
app.get('/api/admin/conflicts', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { rows } = await db.query(`
      SELECT 
        c.conflict_id,
        c.student_id,
        c.change_id,
        c.server_version,
        c.incoming_version,
        c.server_value,
        c.incoming_value,
        c.status,
        c.created_at
      FROM conflicts c
      ORDER BY c.conflict_id DESC
      LIMIT 100
    `);
    res.json(rows);
  } catch (err) {
    console.error('Fetch conflicts error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// GET /api/admin/status
app.get('/api/admin/status', requireAuth, requireAdmin, async (req, res) => {
  try {
    const usersCount = await db.query(`SELECT COUNT(*) as total, COUNT(*) FILTER (WHERE status = 'ACTIVE') as active FROM users`);
    const studentsCount = await db.query(`SELECT COUNT(*) as total FROM students`);
    const syncCount = await db.query(`SELECT COUNT(*) as total FROM sync_changes`);
    const conflictsCount = await db.query(`SELECT COUNT(*) as total, COUNT(*) FILTER (WHERE status = 'OPEN') as unresolved FROM conflicts`);

    res.json({
      postgres: 'CONNECTED',
      backend: 'ONLINE',
      users: {
        total: parseInt(usersCount.rows[0].total, 10),
        active: parseInt(usersCount.rows[0].active, 10)
      },
      students: parseInt(studentsCount.rows[0].total, 10),
      syncChangesTotal: parseInt(syncCount.rows[0].total, 10),
      conflicts: {
        total: parseInt(conflictsCount.rows[0].total, 10),
        unresolved: parseInt(conflictsCount.rows[0].unresolved, 10)
      }
    });
  } catch (err) {
    console.error('System status error:', err);
    res.status(500).json({ error: 'Database connection failed' });
  }
});

// ═══════════════════════════════════════════════════════════
// STUDENT ROUTES (Numeric PostgreSQL ID)
// ═══════════════════════════════════════════════════════════

// GET /api/students & GET /api/students/search — search by numeric ID, Name, or Roll No
app.get(['/api/students', '/api/students/search'], requireAuth, async (req, res) => {
  const q = req.query.q ? req.query.q.trim() : null;
  try {
    let sql = 'SELECT * FROM students';
    let params = [];
    if (q) {
      const isNum = !isNaN(q) && !isNaN(parseInt(q, 10)) && Number.isInteger(Number(q));
      if (isNum) {
        sql += ' WHERE id = $1 OR roll_no ILIKE $2 OR name ILIKE $2';
        params.push(parseInt(q, 10), `%${q}%`);
      } else {
        sql += ' WHERE name ILIKE $1 OR roll_no ILIKE $1';
        params.push(`%${q}%`);
      }
    }
    sql += ' ORDER BY id ASC';
    const { rows } = await db.query(sql, params);
    res.json(rows);
  } catch (err) {
    console.error('GET /api/students error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// POST /api/students — auto-generates ID via PostgreSQL sequence
app.post('/api/students', requireAuth, async (req, res) => {
  const { name, roll_no, course, attendance } = req.body;
  if (!name) return res.status(400).json({ error: 'Name is required' });

  const userId   = req.user.id;
  const deviceId = req.user.deviceId || 'WEB';

  try {
    // Reset sequence to 1 ONLY if students table is currently completely empty
    await resetStudentSequenceIfEmpty();

    const { rows } = await db.query(
      `INSERT INTO students (name, roll_no, course, attendance)
       VALUES ($1, $2, $3, $4)
       RETURNING *`,
      [name.trim(), roll_no || '', course || '', parseInt(attendance, 10) || 0]
    );
    const student = rows[0];

    await db.query(
      `INSERT INTO sync_changes (student_id, user_id, device_id, field, old_value, new_value, base_version, status)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [student.id, userId, deviceId, 'RECORD', null,
       JSON.stringify({ id: student.id, name: student.name, roll_no: student.roll_no, course: student.course, attendance: student.attendance }),
       0, 'CREATED']
    );

    res.json({ status: 'CREATED', student });
  } catch (err) {
    console.error('POST /api/students error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// PUT /api/students/:id — update student with numeric ID version checking
app.put('/api/students/:id', requireAuth, async (req, res) => {
  const studentId = parseInt(req.params.id, 10);
  const { name, roll_no, course, attendance, baseVersion } = req.body;

  if (!name || baseVersion === undefined) {
    return res.status(400).json({ error: 'Missing required fields (name, baseVersion)' });
  }

  const userId   = req.user.id;
  const deviceId = req.user.deviceId || 'WEB';

  try {
    const { rows } = await db.query('SELECT * FROM students WHERE id = $1', [studentId]);
    if (rows.length === 0) return res.status(404).json({ error: 'Student not found' });
    const current = rows[0];

    if (parseInt(baseVersion, 10) === current.version) {
      // ── No conflict ──
      const newVersion = current.version + 1;
      await db.query(
        `UPDATE students SET name=$1, roll_no=$2, course=$3, attendance=$4, version=$5, updated_at=NOW() WHERE id=$6`,
        [name.trim(), roll_no, course, parseInt(attendance, 10), newVersion, studentId]
      );
      await db.query(
        `INSERT INTO sync_changes (student_id, user_id, device_id, field, old_value, new_value, base_version, status)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
        [studentId, userId, deviceId, 'RECORD',
         JSON.stringify({ id: current.id, name: current.name, roll_no: current.roll_no, course: current.course, attendance: current.attendance }),
         JSON.stringify({ id: studentId, name: name.trim(), roll_no, course, attendance: parseInt(attendance, 10) }),
         baseVersion, 'SYNCED']
      );
      return res.json({ 
        status: 'SYNCED', 
        student: { 
          id: studentId, 
          name: name.trim(), 
          roll_no, 
          course, 
          attendance: parseInt(attendance, 10), 
          version: newVersion 
        } 
      });

    } else {
      // ── Conflict ──
      const cr = await db.query(
        `INSERT INTO sync_changes (student_id, user_id, device_id, field, old_value, new_value, base_version, status)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING change_id`,
        [studentId, userId, deviceId, 'RECORD',
         JSON.stringify({ id: current.id, name: current.name, roll_no: current.roll_no, course: current.course, attendance: current.attendance }),
         JSON.stringify({ id: studentId, name: name.trim(), roll_no, course, attendance: parseInt(attendance, 10) }),
         baseVersion, 'CONFLICT']
      );
      await db.query(
        `INSERT INTO conflicts (change_id, student_id, server_version, incoming_version, server_value, incoming_value, status)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [cr.rows[0].change_id, studentId, current.version, parseInt(baseVersion, 10),
         JSON.stringify({ id: current.id, name: current.name, roll_no: current.roll_no, course: current.course, attendance: current.attendance }),
         JSON.stringify({ id: studentId, name: name.trim(), roll_no, course, attendance: parseInt(attendance, 10) }), 
         'OPEN']
      );
      return res.json({ status: 'CONFLICT', serverStudent: current });
    }
  } catch (err) {
    console.error('PUT /api/students/:id error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// DELETE /api/students/:id
app.delete('/api/students/:id', requireAuth, requireAdmin, async (req, res) => {
  const studentId = parseInt(req.params.id, 10);
  try {
    const { rows } = await db.query('SELECT * FROM students WHERE id = $1', [studentId]);
    if (rows.length === 0) return res.status(404).json({ error: 'Student not found' });
    await db.query('DELETE FROM students WHERE id = $1', [studentId]);

    // Mark any OPEN conflicts for this student as STUDENT_DELETED (preserve for audit history)
    await db.query(
      `UPDATE conflicts SET status = 'STUDENT_DELETED' WHERE student_id = $1 AND status = 'OPEN'`,
      [studentId]
    );

    await logAudit(req.user.id, 'ADMIN_DELETED_STUDENT', studentId, `Deleted student ID ${studentId} (${rows[0].name})`);

    // Reset sequence to 1 if deleting this student made the table completely empty
    await resetStudentSequenceIfEmpty();

    res.json({ status: 'DELETED', studentId });
  } catch (err) {
    console.error('DELETE /api/students/:id error:', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ═══════════════════════════════════════════════════════════
// START SERVER
// ═══════════════════════════════════════════════════════════
bootstrapDB()
  .then(() => {
    app.listen(PORT, () => console.log(`Server listening on port ${PORT}`));
  })
  .catch(err => {
    console.error('Bootstrap failed:', err);
    process.exit(1);
  });
