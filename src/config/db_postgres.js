import pkg from 'pg';
const { Pool } = pkg;
import dotenv from 'dotenv';

dotenv.config();

console.log('🔍 Checking Database Configuration...');
console.log('DATABASE_URL:', process.env.DATABASE_URL ? '✅ Found' : '❌ Missing');

if (!process.env.DATABASE_URL) {
  console.error('❌ DATABASE_URL not found in .env file!');
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false
  },
  max: 10,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
});

// Connection event handlers
pool.on('connect', () => {
  console.log('✅ PostgreSQL connected to Supabase');
});

pool.on('error', (err) => {
  console.error('❌ Unexpected error on idle client', err);
  process.exit(-1);
});

// Query wrapper function
export const query = async (text, params) => {
  const start = Date.now();
  try {
    const res = await pool.query(text, params);
    const duration = Date.now() - start;
    console.log('📊 Query:', text.substring(0, 50) + '...', `(${duration}ms)`);
    return res;
  } catch (error) {
    console.error('❌ Query error:', error.message);
    console.error('Query:', text);
    throw error;
  }
};

// Test connection immediately
async function testConnection() {
  try {
    const res = await pool.query('SELECT NOW() as time, version() as version');
    console.log('✅ Database connected successfully!');
    console.log('🕐 Server time:', res.rows[0].time);
    console.log('📦 PostgreSQL:', res.rows[0].version.split(' ')[0]);
  } catch (error) {
    console.error('❌ Database connection failed:', error.message);
    console.error('\n📋 Troubleshooting:');
    console.error('1. Check DATABASE_URL in .env');
    console.error('2. Run: ipconfig /flushdns');
    console.error('3. Try using mobile hotspot');
    console.error('4. Check if password is correct: 2bOWdCu0G2voI8Sn\n');
    process.exit(1);
  }
}

testConnection();

export default pool;