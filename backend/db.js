const { Pool } = require('pg');

const connectionString = process.env.DATABASE_URL
  ? process.env.DATABASE_URL.replace(/[&?]channel_binding=[^&]*/g, '')
  : undefined;

const pool = new Pool({
  connectionString: connectionString,
  ssl: process.env.DATABASE_URL && !process.env.DATABASE_URL.includes('localhost') && !process.env.DATABASE_URL.includes('127.0.0.1')
    ? { rejectUnauthorized: false }
    : false
});

module.exports = {
  query: (text, params) => pool.query(text, params),
};
