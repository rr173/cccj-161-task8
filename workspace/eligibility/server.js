// 灵活负荷资格闸 · 零依赖 HTTP 服务（API + 运营台静态页面）。
//
// 独立进程（默认端口 8093），自有只增日志 data/eligibility.log 与签发密钥 sidecar
// data/eligibility-keys.json（复用编排内核的哈希链与 Ed25519 实现）。
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join, extname, normalize } from 'node:path';
import { EligibilityRegistry } from './registry.js';
import { EventStore } from '../src/store.js';
import { PackageKeyStore } from '../src/package-crypto.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = join(__dirname, 'public');
const LOG_FILE = process.env.GATE_LOG || join(__dirname, '..', 'data', 'eligibility.log');
const KEY_FILE = process.env.GATE_KEYS || join(dirname(LOG_FILE), 'eligibility-keys.json');

const store = new EventStore(process.env.GATE_MEMORY ? null : LOG_FILE);
const keys = new PackageKeyStore(process.env.GATE_MEMORY ? null : KEY_FILE);
await store.load();
const recoveryStatus = store.verify();
const gate = new EligibilityRegistry(store, { keys });
if (!recoveryStatus.writable) {
  console.error('⛔ 资格闸日志已只读隔离：', recoveryStatus.reason);
} else if (recoveryStatus.recovery?.kind === 'torn-tail-recovered') {
  console.warn('⚠️  资格闸日志检测到断电残尾，已归档并续链。');
}

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
};

function send(res, status, body, headers = {}) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', ...headers });
  res.end(typeof body === 'string' ? body : JSON.stringify(body));
}

async function readBody(req) {
  if (req.method === 'GET' || req.method === 'HEAD') return {};
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', (c) => {
      data += c;
      if (data.length > 2_000_000) reject(Object.assign(new Error('body too large'), { status: 413 }));
    });
    req.on('end', () => {
      if (!data.trim()) return resolve({});
      try { resolve(JSON.parse(data)); }
      catch { reject(Object.assign(new Error('非法 JSON'), { status: 400 })); }
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

const STATUS = {
  BAD_REQUEST: 400,
  DEVICE_EXISTS: 409, DEVICE_NOT_FOUND: 404,
  RULE_OVERLAP: 409, RULE_VERSION_CONFLICT: 409, RULE_NOT_FOUND: 404,
  RULE_VERSION_NOT_FOUND: 404, RULE_REVOKED: 409, RULE_ALREADY_REVOKED: 409,
  REQUEST_ID_CONFLICT: 409, BATCH_NOT_FOUND: 404, BATCH_NOT_FROZEN: 409,
  GATE_KEY_UNAVAILABLE: 503, LOG_QUARANTINED: 503, UNKNOWN_COMMAND: 400,
};

const server = createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  const path = url.pathname;
  try {
    if (req.method === 'GET' && !path.startsWith('/api')) return serveStatic(req, res);
    const body = await readBody(req);

    // ---- 仿真时钟 / 复位 ----
    if (path === '/api/state' && req.method === 'GET') return send(res, 200, gate.stateView());
    if (path === '/api/sim/tick' && req.method === 'POST') {
      const to = gate.now() + Number(body.minutes ?? 60) * 60000;
      const rec = store.append('SIM_TICK', { to }, to);
      gate.apply(rec);
      return send(res, 200, { now: gate.now(), nowIso: new Date(to).toISOString() });
    }
    if (path === '/api/sim/reset' && req.method === 'POST') {
      gate.reset();
      return send(res, 200, { reset: true, now: gate.now() });
    }
    if (path === '/api/chain/verify' && req.method === 'GET') {
      return send(res, 200, {
        ...store.verify(),
        ruleTip: gate.chainTip(),
      });
    }
    if (path === '/api/log' && req.method === 'GET') {
      const type = url.searchParams.get('type');
      const limit = Number(url.searchParams.get('limit') || 300);
      let recs = store.all();
      if (type) recs = recs.filter((r) => r.type === type);
      recs = recs.slice(-limit);
      return send(res, 200, { count: recs.length, records: recs });
    }

    // ---- 设备台账 ----
    if (path === '/api/devices' && req.method === 'POST') {
      return send(res, 201, gate.registerDevice(body, gate.now()));
    }
    const devSuspend = path.match(/^\/api\/devices\/([^/]+)\/suspend$/);
    if (devSuspend && req.method === 'POST') {
      return send(res, 200, gate.suspendDevice({
        deviceId: decodeURIComponent(devSuspend[1]), suspended: body.suspended, reason: body.reason,
      }, gate.now()));
    }

    // ---- 规则：发布 / 撤销 / 回滚 / 试算 / 查询 ----
    if (path === '/api/rules' && req.method === 'POST') {
      return send(res, 201, gate.publishRule(body, gate.now()));
    }
    if (path === '/api/rules' && req.method === 'GET') {
      const scope = url.searchParams.get('region')
        ? { region: url.searchParams.get('region'), deviceId: url.searchParams.get('deviceId') }
        : null;
      const lifecycle = url.searchParams.get('lifecycle');
      return send(res, 200, { count: gate.listRules({ scope, lifecycle }).length, rules: gate.listRules({ scope, lifecycle }) });
    }
    if (path === '/api/rules/trial' && req.method === 'POST') {
      return send(res, 200, gate.trial(body));
    }
    const ruleRevoke = path.match(/^\/api\/rules\/([^/]+)\/revoke$/);
    if (ruleRevoke && req.method === 'POST') {
      return send(res, 200, gate.revokeRule({
        ruleId: decodeURIComponent(ruleRevoke[1]),
        reason: body.reason, effectiveFrom: body.effectiveFrom, expectedVersion: body.expectedVersion,
      }, gate.now()));
    }
    const ruleRollback = path.match(/^\/api\/rules\/rollback$/);
    if (ruleRollback && req.method === 'POST') {
      return send(res, 201, gate.rollbackRule(body, gate.now()));
    }
    const ruleGet = path.match(/^\/api\/rules\/([^/]+)$/);
    if (ruleGet && req.method === 'GET') {
      const view = gate.ruleView(decodeURIComponent(ruleGet[1]));
      if (!view) return send(res, 404, { error: '规则不存在', code: 'RULE_NOT_FOUND' });
      return send(res, 200, view);
    }
    const ruleVer = path.match(/^\/api\/rule-versions\/(\d+)$/);
    if (ruleVer && req.method === 'GET') {
      const view = gate.ruleVersionView(Number(ruleVer[1]));
      if (!view) return send(res, 404, { error: '规则版本不存在', code: 'RULE_VERSION_NOT_FOUND' });
      return send(res, 200, view);
    }

    // ---- 批量申请 / 批次 ----
    if (path === '/api/applications' && req.method === 'POST') {
      const out = gate.decideBatch(body, gate.now());
      return send(res, out.idempotent ? 200 : 201, out);
    }
    if (path === '/api/batches' && req.method === 'GET') {
      const list = gate.listBatches({
        aggregatorId: url.searchParams.get('aggregatorId'),
        status: url.searchParams.get('status'),
      });
      return send(res, 200, { count: list.length, batches: list });
    }
    const batchGet = path.match(/^\/api\/batches\/([^/]+)$/);
    if (batchGet && req.method === 'GET') {
      const view = gate.batchView(decodeURIComponent(batchGet[1]));
      if (!view) return send(res, 404, { error: '批次不存在', code: 'BATCH_NOT_FOUND' });
      return send(res, 200, view);
    }
    const batchFreeze = path.match(/^\/api\/batches\/([^/]+)\/freeze$/);
    if (batchFreeze && req.method === 'POST') {
      const out = gate.freezeBatch({ batchId: decodeURIComponent(batchFreeze[1]), by: body.by }, gate.now());
      return send(res, 200, out);
    }
    const batchVerify = path.match(/^\/api\/batches\/([^/]+)\/verify$/);
    if (batchVerify && req.method === 'GET') {
      const out = gate.verifyBatch(decodeURIComponent(batchVerify[1]));
      if (!out) return send(res, 404, { error: '批次不存在', code: 'BATCH_NOT_FOUND' });
      return send(res, 200, out);
    }
    const batchCsv = path.match(/^\/api\/batches\/([^/]+)\/redacted\.csv$/);
    if (batchCsv && req.method === 'GET') {
      const csv = gate.redactedCsv(decodeURIComponent(batchCsv[1]));
      if (csv === null) return send(res, 404, { error: '批次不存在', code: 'BATCH_NOT_FOUND' });
      res.writeHead(200, {
        'Content-Type': 'text/csv; charset=utf-8',
        'Content-Disposition': `attachment; filename="batch-${decodeURIComponent(batchCsv[1])}-redacted.csv"`,
      });
      return res.end(csv);
    }

    return send(res, 404, { error: 'unknown route', path });
  } catch (err) {
    const status = err.status || STATUS[err.code] || 500;
    if (status === 500) console.error(err);
    const headers = status === 503 ? { 'Retry-After': '300', 'Cache-Control': 'no-store' } : {};
    send(res, status, {
      ...(err.code === 'LOG_QUARANTINED' ? err.recovery : {}),
      error: err.message,
      code: err.code || 'INTERNAL',
      details: err.details || {},
    }, headers);
  }
});

const PORT = Number(process.env.PORT || 8093);
server.listen(PORT, () => {
  const actual = server.address().port;
  console.log(`灵活负荷资格闸已启动: http://localhost:${actual}`);
  console.log(`资格闸日志: ${process.env.GATE_MEMORY ? '(内存，不持久化)' : LOG_FILE}`);
});

export { server, gate };
