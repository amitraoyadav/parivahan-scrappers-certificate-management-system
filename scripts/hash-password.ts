import readline from 'node:readline';
import { hashPassword } from '../src/server/crypto.js';

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

rl.question('Enter password to hash with salted scrypt (for Vercel Environment Variables): ', (answer) => {
  rl.close();
  const trimmed = answer.trim();
  if (trimmed.length < 8) {
    console.error('Password must be at least 8 characters.');
    process.exit(1);
  }
  const hashed = hashPassword(trimmed);
  console.log('\nSalted scrypt hash (safe to paste directly into Vercel Env Vars):\n');
  console.log(hashed);
  console.log('');
});
