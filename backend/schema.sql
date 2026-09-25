-- schema.sql (v3 — Full Distributed Student Sync with Permanent Student Code & Auth)

-- Users table
CREATE TABLE IF NOT EXISTS users (
  id            SERIAL PRIMARY KEY,
  username      VARCHAR(50) UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role          VARCHAR(10) NOT NULL CHECK (role IN ('ADMIN','TEACHER')),
  status        VARCHAR(20) NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','DISABLED')),
  created_at    TIMESTAMP DEFAULT NOW()
);

-- Students table — internal serial ID and permanent student_code (e.g. STU-000001)
CREATE TABLE IF NOT EXISTS students (
  id           SERIAL PRIMARY KEY,
  student_code VARCHAR(20) UNIQUE NOT NULL,
  name         VARCHAR(100) NOT NULL,
  roll_no      VARCHAR(20),
  course       VARCHAR(100),
  attendance   INTEGER NOT NULL DEFAULT 0,
  version      INTEGER NOT NULL DEFAULT 1,
  updated_at   TIMESTAMP DEFAULT NOW()
);

-- Tracks every sync attempt (success or conflict)
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

-- Stores version-mismatch conflicts
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

-- Audit log for administrative events
CREATE TABLE IF NOT EXISTS audit_logs (
  id             SERIAL PRIMARY KEY,
  admin_id       INTEGER,
  action         VARCHAR(100) NOT NULL,
  target_user_id INTEGER,
  details        TEXT,
  created_at     TIMESTAMP DEFAULT NOW()
);

-- Sample initial data
INSERT INTO students (student_code, name, roll_no, course, attendance) VALUES
  ('STU-000001', 'Rahul Kumar', '24', 'B.Tech CSE', 85),
  ('STU-000002', 'Aman Singh',  '25', 'B.Tech CSE', 90)
ON CONFLICT (student_code) DO NOTHING;
