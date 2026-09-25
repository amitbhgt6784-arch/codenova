const { Pool } = require('pg');

// Neon's default connection string includes channel_binding=require, which
// the pg library does not understand and causes the SSL handshake to hang
// indefinitely. Strip it out before creating the pool.
const connectionString = process.env.DATABASE_URL
  ? process.env.DATABASE_URL.replace(/[&?]channel_binding=[^&]*/g, '').replace(/\?&/, '?').replace(/\?$/, '')
  : undefined;

const pool = new Pool({
  connectionString,
  // Enable SSL for any non-local database (required for Neon on Render)
  ssl: connectionString && !connectionString.includes('localhost') && !connectionString.includes('127.0.0.1')
    ? { rejectUnauthorized: false }
    : false,
  // Fail fast instead of hanging forever if the DB is unreachable
  connectionTimeoutMillis: 10000,
});

module.exports = {
  query: (text, params) => pool.query(text, params),
};
