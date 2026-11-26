import 'dotenv/config';
import express from 'express';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { createServer as createViteServer } from 'vite';
import { createApiApp } from './src/server/app.js';

const PORT = Number(process.env.PORT) || 3000;
const isProd = process.env.NODE_ENV === 'production';

// Clean zero-WebSocket /@vite/client implementation used ONLY when DISABLE_HMR=true
// in Vite middleware mode, preventing Vite 8 from opening a dead WebSocket to port 24678.
const NO_HMR_VITE_CLIENT_MODULE = `
const sheetsMap = new Map();

export function updateStyle(id, content) {
  let style = sheetsMap.get(id);
  if (!style) {
    style = document.createElement('style');
    style.setAttribute('type', 'text/css');
    style.setAttribute('data-vite-dev-id', id);
    style.textContent = content;
    document.head.appendChild(style);
    sheetsMap.set(id, style);
  } else {
    style.textContent = content;
  }
}

export function removeStyle(id) {
  const style = sheetsMap.get(id);
  if (style) {
    document.head.removeChild(style);
    sheetsMap.delete(id);
  }
}

export function createHotContext() {
  return {
    data: {},
    accept() {},
    acceptExports() {},
    dispose() {},
    prune() {},
    decline() {},
    invalidate() {},
    on() {},
    off() {},
    send() {},
  };
}

export function injectQuery(url, queryToInject) {
  if (!url || (!url.startsWith('.') && !url.startsWith('/'))) return url;
  const [pathname, searchAndHash = ''] = url.split('?');
  const [search = '', hash = ''] = searchAndHash.split('#');
  return pathname + '?' + queryToInject + (search ? '&' + search : '') + (hash ? '#' + hash : '');
}

export class ErrorOverlay extends (typeof HTMLElement !== 'undefined' ? HTMLElement : class {}) {}
`;

async function startServer(): Promise<void> {
  const app = createApiApp();
  const httpServer = http.createServer(app);
  const rootDir = process.cwd();

  if (!isProd) {
    const hmrDisabled = process.env.DISABLE_HMR === 'true';

    if (hmrDisabled) {
      app.get('/@vite/client', (_req, res) => {
        res.setHeader('Content-Type', 'application/javascript; charset=utf-8');
        res.setHeader('Cache-Control', 'no-cache');
        res.send(NO_HMR_VITE_CLIENT_MODULE);
      });
    }

    const vite = await createViteServer({
      server: {
        middlewareMode: true,
        hmr: hmrDisabled ? false : { server: httpServer },
        watch: hmrDisabled ? null : undefined,
      },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(rootDir, 'dist');
    app.use(express.static(distDir, { index: false }));
    app.get('*', (_req, res) => {
      const indexHtml = path.join(distDir, 'index.html');
      if (fs.existsSync(indexHtml)) {
        res.sendFile(indexHtml);
      } else {
        res.status(404).send('Production build not found. Run npm run build first.');
      }
    });
  }

  httpServer.listen(PORT, '0.0.0.0', () => {
    console.log(`Parivahan Scrappers server listening on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
