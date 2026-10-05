// 灵活负荷资格闸 · 零依赖 HTTP 服务（网页 + 接口）。
//   调度员维护资格规则（定时生效/撤销/回滚）；聚合商批量申请 → 逐设备签名裁决；
//   逐项复核、批次冻结、脱敏清单下载、独立验签。
//
// 所有写命令进入内核单写队列，严格按到达顺序落账；状态为哈希链投影，重启后顺序与版本链不变。
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join, normalize, extname } from 'node:path';
import { GateChain } from './chain.js';
import { GateKeyStore } from './crypto.js';
import { GateEngine, redactedCsv } from './engine.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = join(__dirname, 'public');
const DATA_DIR = process.env.GATE_DIR || join(__dirname, '..', 'data', 'gate');
const LOG_FILE = process.env.GATE_LOG || join(DATA_DIR, 'gate.log');
const KEY_FILE = process.env.GATE_KEYS || join(DATA_DIR, 'gate-keys.json');
const PORT = Number(process.env.GATE_PORT || 8093);
const HOST = process.env.GATE_HOST || '127.0.0.1';

const mem = !!process.env.GATE_MEMORY;
const chain = new GateChain(mem ? null : LOG_FILE);
const keys = new GateKeyStore(mem ? null : KEY_FILE);
const engine = new GateEngine(chain, keys);
await engine.init();

const status0 = chain.verify();
if (!status0.writable) {
  console.error('⛔ 资格闸账本已隔离（只读）：', status0.reason);
} else if (status0.recovery?.kind === 'torn-tail-recovered') {
  console.warn('⚠️  检测到断电残尾，已归档续链：', status0.recovery.archivePath);
}

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
};

function send(res, status, body, headers = {}) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', ...headers });
  res.end(typeof body === 'string' ? body : JSON.stringify(body));
}

function readBody(req) {
  if (req.method === 'GET' || req.method === 'HEAD') return Promise.resolve({});
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (c) => {
      data += c;
      if (data.length > 5_000_000) reject(Object.assign(new Error('body too large'), { status: 413 }));
    });
    req.on('end', () => {
      if (!data.trim()) return resolve({});
      try {
        resolve(JSON.parse(data));
      } catch {
        reject(Object.assign(new Error('非法 JSON'), { status: 400 }));
      }
    });
    req.on('error', reject);
  });
}

async function serveStatic(req, res) {
  let path = decodeURIComponent(new URL(req.url, 'http://x').pathname);
  if (path === '/') path = '/index.html';
  const file = normalize(join(PUBLIC_DIR, path));
  if (!file.startsWith(PUBLIC_DIR)) return send(res, 403, { error: 'forbidden' });
  try {
    const buf = await readFile(file);
    res.writeHead(200, { 'Content-Type': MIME[extname(file)] || 'application/octet-stream' });
    res.end(buf);
  } catch {
    send(res, 404, { error: 'not found' });
  }
}

export function createRouter(deps = {}) {
  const eng = deps.engine || engine;
  return async function router(req, res) {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const path = url.pathname;
    try {
      if (req.method === 'GET' && !path.startsWith('/api')) return serveStatic(req, res);
      const body = await readBody(req);

      // ---------- 时钟 / 状态 ----------
      if (path === '/api/state' && req.method === 'GET') return send(res, 200, eng.stateView());
      if (path === '/api/sim/tick' && req.method === 'POST') {
        return send(res, 200, await eng.dispatch({ type: 'TICK', minutes: body.minutes ?? 15 }));
      }
      if (path === '/api/sim/reset' && req.method === 'POST') {
        return send(res, 200, await eng.dispatch({ type: 'RESET' }));
      }
      if (path === '/api/chain/verify' && req.method === 'GET') {
        return send(res, 200, eng.chain.verify());
      }
      if (path === '/api/keys' && req.method === 'GET') {
        return send(res, 200, { count: eng.keys.listPublic().length, keys: eng.keys.listPublic() });
      }
      if (path === '/api/keys/rotate' && req.method === 'POST') {
        return send(res, 201, await eng.dispatch({ type: 'ROTATE_GATE_KEY', by: body.by }));
      }
      if (path === '/api/log' && req.method === 'GET') {
        const type = url.searchParams.get('type');
        const limit = Number(url.searchParams.get('limit') || 200);
        let recs = eng.chain.all();
        if (type) recs = recs.filter((r) => r.type === type);
        recs = recs.slice(-limit);
        return send(res, 200, { count: recs.length, records: recs });
      }

      // ---------- 设备 / 事件 ----------
      if (path === '/api/devices' && req.method === 'GET') {
        return send(res, 200, { count: eng.listDevices().length, devices: eng.listDevices() });
      }
      if (path === '/api/devices' && req.method === 'POST') {
        return send(res, 201, await eng.dispatch({ type: 'REGISTER_DEVICE', ...body }));
      }
      const devSusp = path.match(/^\/api\/devices\/([^/]+)\/(suspend|resume)$/);
      if (devSusp && req.method === 'POST') {
        return send(res, 200, await eng.dispatch({
          type: devSusp[2] === 'suspend' ? 'SUSPEND_DEVICE' : 'RESUME_DEVICE',
          deviceId: decodeURIComponent(devSusp[1]),
          reason: body.reason,
          by: body.by,
        }));
      }
      if (path === '/api/events' && req.method === 'GET') {
        return send(res, 200, { count: eng.listEvents().length, events: eng.listEvents() });
      }
      if (path === '/api/events' && req.method === 'POST') {
        return send(res, 201, await eng.dispatch({ type: 'REGISTER_EVENT', ...body }));
      }

      // ---------- 规则维护 ----------
      if (path === '/api/rules' && req.method === 'GET') {
        return send(res, 200, { count: eng.listRules().length, rules: eng.listRules() });
      }
      if (path === '/api/rules' && req.method === 'POST') {
        const out = await eng.dispatch({ type: 'PUBLISH_RULE', ...body });
        return send(res, 201, out);
      }
      const ruleGet = path.match(/^\/api\/rules\/([^/]+)$/);
      if (ruleGet && req.method === 'GET') {
        return send(res, 200, eng.ruleView(decodeURIComponent(ruleGet[1])));
      }
      const ruleRevoke = path.match(/^\/api\/rules\/([^/]+)\/revoke$/);
      if (ruleRevoke && req.method === 'POST') {
        return send(res, 200, await eng.dispatch({
          type: 'REVOKE_RULE',
          ruleId: decodeURIComponent(ruleRevoke[1]),
          expectedVersion: body.expectedVersion,
          reason: body.reason,
          by: body.by,
        }));
      }
      const ruleRollback = path.match(/^\/api\/rules\/([^/]+)\/rollback$/);
      if (ruleRollback && req.method === 'POST') {
        return send(res, 200, await eng.dispatch({
          type: 'ROLLBACK_RULE',
          ruleId: decodeURIComponent(ruleRollback[1]),
          expectedVersion: body.expectedVersion,
          targetVersion: body.targetVersion,
          reason: body.reason,
          by: body.by,
        }));
      }

      // ---------- 试算（只读，不写链/不签名） ----------
      if (path === '/api/trial' && req.method === 'POST') {
        return send(res, 200, eng.trial(body));
      }

      // ---------- 申请 / 裁决 ----------
      if (path === '/api/applications' && req.method === 'GET') {
        return send(res, 200, { count: eng.listApps().length, applications: eng.listApps() });
      }
      if (path === '/api/applications' && req.method === 'POST') {
        const out = await eng.dispatch({ type: 'SUBMIT_APPLICATION', ...body });
        return send(res, out.idempotent ? 200 : 201, out);
      }
      const appGet = path.match(/^\/api\/applications\/([^/]+)$/);
      if (appGet && req.method === 'GET') {
        return send(res, 200, eng.appView(decodeURIComponent(appGet[1])));
      }
      const review = path.match(/^\/api\/applications\/([^/]+)\/items\/([^/]+)\/review$/);
      if (review && req.method === 'POST') {
        return send(res, 201, await eng.dispatch({
          type: 'REVIEW_ITEM',
          applicationNo: decodeURIComponent(review[1]),
          deviceId: decodeURIComponent(review[2]),
          reviewer: body.reviewer,
          disposition: body.disposition,
          note: body.note,
        }));
      }
      const freeze = path.match(/^\/api\/applications\/([^/]+)\/freeze$/);
      if (freeze && req.method === 'POST') {
        const out = await eng.dispatch({
          type: 'FREEZE_BATCH',
          applicationNo: decodeURIComponent(freeze[1]),
          by: body.by,
        });
        return send(res, out.idempotent ? 200 : 201, out);
      }
      const manifestGet = path.match(/^\/api\/applications\/([^/]+)\/manifest$/);
      if (manifestGet && req.method === 'GET') {
        const a = eng.requireApp(decodeURIComponent(manifestGet[1]));
        if (!a.frozen) {
          return send(res, 409, {
            error: '批次尚未冻结',
            code: 'BATCH_NOT_FROZEN',
          });
        }
        return send(res, 200, {
          applicationNo: a.applicationNo,
          ...eng.verifyManifest(a.applicationNo),
        });
      }
      const csvGet = path.match(/^\/api\/applications\/([^/]+)\/redacted\.csv$/);
      if (csvGet && req.method === 'GET') {
        const a = eng.requireApp(decodeURIComponent(csvGet[1]));
        if (!a.frozen) {
          return send(res, 409, {
            error: '只有冻结批次才能下载脱敏清单',
            code: 'BATCH_NOT_FROZEN',
          });
        }
        const csv = redactedCsv(a);
        res.writeHead(200, {
          'Content-Type': 'text/csv; charset=utf-8',
          'Content-Disposition':
            `attachment; filename="gate-${encodeURIComponent(a.applicationNo)}-redacted.csv"`,
          'Cache-Control': 'no-store',
        });
        return res.end(csv);
      }

      // ---------- 独立验签 ----------
      const verifyDecision = path.match(
        /^\/api\/applications\/([^/]+)\/items\/([^/]+)\/verify$/,
      );
      if (verifyDecision && req.method === 'GET') {
        return send(res, 200, eng.verifyDecision(
          decodeURIComponent(verifyDecision[1]),
          decodeURIComponent(verifyDecision[2]),
        ));
      }
      const verifyManifest = path.match(/^\/api\/applications\/([^/]+)\/manifest\/verify$/);
      if (verifyManifest && req.method === 'GET') {
        return send(res, 200, eng.verifyManifest(decodeURIComponent(verifyManifest[1])));
      }
      // 完全离线验签：调用方自带 canonical + signature + keyId（或公钥 PEM）。
      if (path === '/api/verify' && req.method === 'POST') {
        return send(res, 200, eng.verifyOffline(body));
      }

      return send(res, 404, { error: 'unknown route', path });
    } catch (err2) {
      return handleError(res, err2);
    }
  };
}

function handleError(res, e) {
  const status = e.status || 500;
  if (status === 500) console.error(e);
  const headers = status === 503 ? { 'Retry-After': '300', 'Cache-Control': 'no-store' } : {};
  send(res, status, {
    error: e.message,
    code: e.code || 'INTERNAL',
    details: e.details || {},
    ...(e.code === 'CHAIN_QUARANTINED' ? { recovery: e.recovery || chain.recovery } : {}),
  }, headers);
}

const server = createServer(await createRouter());

if (process.env.NODE_ENV !== 'test') {
  server.listen(PORT, HOST, () => {
    console.log(`灵活负荷资格闸已启动: http://${HOST}:${server.address().port}`);
    console.log(`账本: ${mem ? '(内存，不持久化)' : LOG_FILE}`);
    console.log(`签发密钥: ${mem ? '(内存)' : KEY_FILE}`);
  });
}

export { server, engine, chain, keys };
