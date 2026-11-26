import { createApiApp } from '../src/server/app.js';

// Stateless Vercel Serverless API Handler (zero local filesystem writes)
const app = createApiApp();

export default app;
