// 证据归档服务（独立进程，零依赖 Node ≥20）：网页 + HTTP 接口。
//   导入带签名的离线证据包 → 规范化哈希/Ed25519 验签/哈希链校验 → 按 packageId 归档
//   → 生成可阅读、可下载（JSON/TXT/HTML）的脱敏核验报告。
//
// 密钥纪律（页面与日志绝不泄露）：
//   - upload secret：仅经 X-Upload-Secret 请求头校验（常量时间比较），
//     任何响应/日志/导出只出现为 ***REDACTED***，且永不回显；
//   - 网关私钥：服务从不持有；注册 API 只收公钥 PEM；
//   - 拒绝信封落盘 0600，读取出口一律 redact。
import { createServer } from 'node:http';
import { readFile, appendFile, mkdir } from 'node:fs/promises';
import { mkdirSync, chmodSync, unlinkSync, rmdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, normalize, extname } from 'node:path';
import { ArchiveManager } from './archive.js';
import { buildReport, exportRedactedJSON, renderText, renderHTMLFragment } from './report.js';
import {
  GatewayRegistry, loadOrCreateUploadSecret, safeEqual, generateGatewayKeyPair,
} from './crypto.js';
import { redact, safeLog } from './hashing.js';
import { LifecycleStore } from './lifecycle.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = join(__dirname, 'public');
const DATA_DIR = process.env.EVIDENCE_DIR || join(__dirname, '..', 'data', 'evidence');
const PORT = Number(process.env.EVIDENCE_PORT || 8092);
const HOST = process.env.EVIDENCE_HOST || '127.0.0.1';

export class EvidenceLogger {
  // file 为 null 时仅 stdout。写入前统一过 safeLog 白名单 + 密钥字面量打码。
  constructor(file, { secret = '' } = {}) {
    this.file = file;
    this.secret = secret;
    if (file) {
      mkdirSync(dirname(file), { recursive: true, mode: 0o700 });
      try { chmodSync(file, 0o600); } catch { /* 文件尚不存在时忽略 */ }
    }
  }

  log(fields) {
    const clean = safeLog({ at: new Date().toISOString(), ...fields }, this.secret ? [this.secret] : []);
    const line = JSON.stringify(clean);
    process.stdout.write(line + '\n');
    if (this.file) appendFile(this.file, line + '\n', { mode: 0o600 }).catch(() => {});
  }
}

export async function createApp(deps = {}) {
  await mkdir(DATA_DIR, { recursive: true });
  const dataDir = deps.dataDir ?? DATA_DIR;
  await mkdir(dataDir, { recursive: true });
  const manager = deps.manager ?? new ArchiveManager(dataDir);
  const registry = deps.registry ?? new GatewayRegistry(join(dataDir, 'gateways.json'));
  const secretInfo = deps.secretInfo ?? loadOrCreateUploadSecret(
    join(dataDir, 'upload-secret.json'), process.env.EVIDENCE_UPLOAD_SECRET);
  const uploadSecret = deps.uploadSecret ?? secretInfo.secret;
  const logger = deps.logger ?? new EvidenceLogger(join(dataDir, 'audit-server.log'), { secret: uploadSecret });

  // ---------- 证据保全与到期销毁 ----------
  const lifecycle = deps.lifecycle ?? new LifecycleStore(dataDir, { now: deps.now });
  lifecycle.setHooks({
    // 提交点快照：只取报告摘要/链尖/计数（绝不含原始证据）。
    snapshot(packageId) {
      const archive = manager.open(packageId);
      const report = buildReport(archive);
      return {
        reportDigest: report.reportDigest,
        chainTips: {
          ledger: { seq: archive.ledger.seq, hash: archive.ledger.tipHash },
          quarantine: { seq: archive.quarantine.seq, hash: archive.quarantine.tipHash },
          audit: { seq: archive.audit.seq, hash: archive.audit.tipHash },
        },
        counts: {
          acceptedRecords: report.acceptedRecordCount,
          conflicts: report.conflictCount,
          imports: report.imports.length,
        },
      };
    },
    // 业务索引（内存投影）随提交失效。
    evict(packageId) {
      manager.cache.delete(packageId);
    },
    listPackages: () => manager.list(),
    packageExists: (packageId) => manager.list().includes(packageId),
  });
  // 启动恢复：中断的销毁继续到唯一结果（尚未开始/正在提交/已完成可区分）。
  const resumed = lifecycle.recover();
  for (const r of resumed) {
    logger.log({ level: 'info', msg: 'destruction-resumed', packageId: r.packageId, status: `${r.from}->${r.to}` });
  }

  const MIME = {
    '.html': 'text/html; charset=utf-8',
    '.js': 'text/javascript; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.json': 'application/json; charset=utf-8',
    '.svg': 'image/svg+xml',
    '.txt': 'text/plain; charset=utf-8',
  };

  function send(res, status, body, headers = {}) {
    res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', ...headers });
    res.end(typeof body === 'string' ? body : JSON.stringify(body));
  }

  function requireSecret(req) {
    const got = req.headers['x-upload-secret'];
    // 无 header / 值错误一律 401；响应不回显任何提交内容。
    if (typeof got !== 'string' || !safeEqual(got, uploadSecret)) {
      throw Object.assign(new Error('缺少或无效的 X-Upload-Secret'), { code: 'UNAUTHORIZED', status: 401 });
    }
  }

  function readBody(req) {
    if (req.method === 'GET' || req.method === 'HEAD') return Promise.resolve({});
    return new Promise((resolve, reject) => {
      let data = '';
      req.on('data', (c) => {
        data += c;
        if (data.length > 5_000_000) reject(Object.assign(new Error('证据包过大（上限 5MB）'), { status: 413, code: 'BODY_TOO_LARGE' }));
      });
      req.on('end', () => {
        if (!data.trim()) return resolve({});
        try { resolve(JSON.parse(data)); }
        catch { reject(Object.assign(new Error('非法 JSON'), { status: 400, code: 'BAD_JSON' })); }
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

  // 已越过销毁提交点的包：所有证据读接口统一 410（看不到部分删除）。
  function assertEvidenceReadable(packageId) {
    if (lifecycle.isDestroyed(packageId)) {
      const st = lifecycle.destructionStatus(packageId);
      throw Object.assign(new Error(`作业包 ${packageId} 的证据已销毁（回执 ${st.receiptId}）`), {
        code: 'PACKAGE_DESTROYED',
        status: 410,
        details: {
          receiptId: st.receiptId,
          destroyedAt: st.committedAt ?? st.at,
          receipt: `/api/destructions/${st.receiptId}`,
        },
      });
    }
  }

  function packageView(packageId) {
    assertEvidenceReadable(packageId);
    const archive = manager.open(packageId);
    const report = buildReport(archive);
    return report;
  }

  // 进程级重启等价物：丢弃所有缓存的归档对象，从磁盘重放重建。
  function restartFromDisk() {
    manager.cache.clear();
    return lifecycle.reload(); // 生命周期链同样重放 + 恢复中断的销毁
  }

  const server = createServer(async (req, res) => {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    const path = url.pathname;
    const at = new Date().toISOString();
    try {
      if (req.method === 'GET' && !path.startsWith('/api')) return await serveStatic(req, res);

      const body = await readBody(req);

      // ---------- 网关公钥注册 ----------
      if (path === '/api/gateways' && req.method === 'GET') {
        return send(res, 200, { gateways: registry.list() });
      }
      if (path === '/api/gateways' && req.method === 'POST') {
        requireSecret(req);
        const { gatewayId, keyId, publicKeyPem, note } = body;
        if (!gatewayId || !keyId || !publicKeyPem || typeof publicKeyPem !== 'string') {
          throw Object.assign(new Error('gatewayId/keyId/publicKeyPem 必填'), { code: 'ENVELOPE_MALFORMED', status: 400 });
        }
        if (!publicKeyPem.includes('BEGIN PUBLIC KEY')) {
          throw Object.assign(new Error('只接受 SPKI PEM 公钥，绝不接受私钥'), { code: 'PRIVATE_KEY_REJECTED', status: 400 });
        }
        const g = registry.register({
          gatewayId: String(gatewayId), keyId: String(keyId),
          publicKeyPem: String(publicKeyPem), createdAt: at, note: note ? String(note) : null,
        });
        logger.log({ level: 'info', msg: 'gateway-registered', gatewayId: g.gatewayId, keyId: g.keyId });
        return send(res, 201, { gatewayId: g.gatewayId, keyId: g.keyId, createdAt: g.createdAt });
      }

      // ---------- 包列表 / 状态 ----------
      if (path === '/api/packages' && req.method === 'GET') {
        const ids = manager.list().filter((id) => !lifecycle.isDestroyed(id));
        const items = ids.map((id) => {
          const r = packageView(id);
          const lc = lifecycle.packageLifecycleView(id);
          return {
            packageId: id,
            reportDigest: r.reportDigest,
            currentFence: r.currentFence,
            currentProgress: r.currentProgress,
            acceptedRecordCount: r.acceptedRecordCount,
            conflictCount: r.conflictCount,
            fenceCount: r.fenceCount,
            retention: lc.retention ? { retainUntil: lc.retention.retainUntil, expired: lc.retention.expired } : null,
            activeHoldCount: lc.activeHoldCount,
            destructionStatus: lc.destruction.status,
            eligibleForDestruction: lc.eligible,
          };
        });
        return send(res, 200, { packages: items });
      }

      const importPath = path.match(/^\/api\/packages\/([^/]+)\/import$/);
      if (importPath && req.method === 'POST') {
        requireSecret(req);
        const packageId = decodeURIComponent(importPath[1]);
        assertEvidenceReadable(packageId); // 已销毁：410，绝不重建目录
        const archive = manager.open(packageId);
        try {
          const out = archive.importEnvelope(body, { registry, nowIso: at });
          logger.log({
            level: 'info',
            msg: out.duplicate ? 'evidence-duplicate' : 'evidence-imported',
            packageId, gatewayId: body?.gatewayId,
            duplicate: out.duplicate, result: out.duplicate ? out.disposition : out.result,
            records: out.duplicate ? undefined : out.disposition?.recordsAccepted,
            conflict: out.duplicate ? out.disposition?.recordsConflicted : out.disposition?.recordsConflicted,
            envelopeHash: out.envelopeHash, importId: out.duplicate ? out.importId : out.importId,
          });
          return send(res, out.duplicate ? 200 : (out.result === 'CONFLICTS' ? 200 : 201), out);
        } catch (err) {
          // 已通过信封哈希复算、但后续被拒的信封留底（0600，仅审计，不进入证据链）。
          let storedReject = null;
          if (body && typeof body === 'object' && err.status === 422) {
            try { storedReject = archive.persistRejected(manager.rejectedDir, body, err.code, err.message, at); } catch { /* 忽略留底失败 */ }
          }
          logger.log({
            level: 'warn', msg: 'evidence-rejected', packageId,
            gatewayId: body?.gatewayId, code: err.code, reason: err.message,
            envelopeHash: typeof body?.envelopeHash === 'string' ? body.envelopeHash : undefined,
          });
          return send(res, err.status || 422, {
            error: err.message, code: err.code, details: redact(err.details || {}, [uploadSecret]),
            ...(storedReject ? { rejectedSaved: true } : {}),
          });
        }
      }

      // ---------- 报告与导出 ----------
      const reportMatch = path.match(/^\/api\/packages\/([^/]+)\/report$/);
      if (reportMatch && req.method === 'GET') {
        const r = packageView(decodeURIComponent(reportMatch[1]));
        return send(res, 200, exportRedactedJSON(r, [uploadSecret]));
      }
      const exportMatch = path.match(/^\/api\/packages\/([^/]+)\/report\.(json|txt|html)$/);
      if (exportMatch && req.method === 'GET') {
        const r = packageView(decodeURIComponent(exportMatch[1]));
        const fmt = exportMatch[2];
        if (fmt === 'json') {
          return send(res, 200, JSON.stringify(exportRedactedJSON(r, [uploadSecret]), null, 2), {
            'Content-Disposition': `attachment; filename="report-${r.packageId}.json"`,
            'Content-Type': 'application/json; charset=utf-8',
          });
        }
        if (fmt === 'txt') {
          return send(res, 200, renderText(exportRedactedJSON(r, [uploadSecret])), {
            'Content-Disposition': `attachment; filename="report-${r.packageId}.txt"`,
            'Content-Type': 'text/plain; charset=utf-8',
          });
        }
        return send(res, 200, renderHTMLFragment(exportRedactedJSON(r, [uploadSecret])), { 'Content-Type': 'text/html; charset=utf-8' });
      }

      const timelineMatch = path.match(/^\/api\/packages\/([^/]+)\/timeline$/);
      if (timelineMatch && req.method === 'GET') {
        const r = packageView(decodeURIComponent(timelineMatch[1]));
        return send(res, 200, redact({ packageId: r.packageId, timeline: r.timeline }, [uploadSecret]));
      }
      const conflictMatch = path.match(/^\/api\/packages\/([^/]+)\/conflicts$/);
      if (conflictMatch && req.method === 'GET') {
        const r = packageView(decodeURIComponent(conflictMatch[1]));
        return send(res, 200, redact({ packageId: r.packageId, conflicts: r.conflicts }, [uploadSecret]));
      }
      const oldFenceMatch = path.match(/^\/api\/packages\/([^/]+)\/fences\/(\d+)$/);
      if (oldFenceMatch && req.method === 'GET') {
        // 旧围栏证据仍可查询（按版本），响应标注它不是当前围栏/当前进度。
        const r = packageView(decodeURIComponent(oldFenceMatch[1]));
        const v = Number(oldFenceMatch[2]);
        const f = r.fences.find((x) => x.version === v);
        if (!f) throw Object.assign(new Error(`围栏版本 v${v} 不存在`), { code: 'FENCE_UNKNOWN', status: 404 });
        const segs = r.timeline.filter((t) => t.fenceVersion === v && t.type === 'SEGMENT_ACCEPTED');
        return send(res, 200, redact({
          packageId: r.packageId,
          fence: f,
          segments: segs,
          isCurrentFence: f.isCurrent,
          note: f.isCurrent ? '当前围栏' : '旧围栏证据：可查询，但不得作为当前进度',
        }, [uploadSecret]));
      }

      // ---------- 哈希链核验 ----------
      if (path === '/api/chain/verify' && req.method === 'GET') {
        const out = {};
        for (const id of manager.list()) {
          if (lifecycle.isDestroyed(id)) {
            const st = lifecycle.destructionStatus(id);
            out[id] = { destroyed: true, receiptId: st.receiptId };
            continue;
          }
          out[id] = manager.open(id).verify();
        }
        return send(res, 200, { packages: out, lifecycle: lifecycle.chain.verify() });
      }
      const verifyPkg = path.match(/^\/api\/packages\/([^/]+)\/verify$/);
      if (verifyPkg && req.method === 'GET') {
        const packageId = decodeURIComponent(verifyPkg[1]);
        assertEvidenceReadable(packageId);
        return send(res, 200, manager.open(packageId).verify());
      }

      // ---------- 导入裁决审计（脱敏）----------
      const importsMatch = path.match(/^\/api\/packages\/([^/]+)\/imports$/);
      if (importsMatch && req.method === 'GET') {
        const r = packageView(decodeURIComponent(importsMatch[1]));
        return send(res, 200, redact({ packageId: r.packageId, imports: r.imports }, [uploadSecret]));
      }

      // ---------- 证据保全与到期销毁 ----------
      // 保留期限（运营）
      const retentionMatch = path.match(/^\/api\/packages\/([^/]+)\/retention$/);
      if (retentionMatch && req.method === 'POST') {
        requireSecret(req);
        const packageId = decodeURIComponent(retentionMatch[1]);
        const out = lifecycle.setRetention(packageId, body);
        logger.log({
          level: 'info', msg: out.replay ? 'retention-replayed' : 'retention-set',
          packageId, setBy: body?.setBy, retainUntil: out.result.retainUntil,
        });
        return send(res, out.replay ? 200 : 201, { ...out.result, replay: out.replay });
      }

      // 单包生命周期视图（期限/保全/销毁状态/资格，可核对）
      const lifecycleMatch = path.match(/^\/api\/packages\/([^/]+)\/lifecycle$/);
      if (lifecycleMatch && req.method === 'GET') {
        const packageId = decodeURIComponent(lifecycleMatch[1]);
        return send(res, 200, redact(lifecycle.packageLifecycleView(packageId), [uploadSecret]));
      }

      // 保全列表（销毁后仍可查——生命周期事实在全局链上）
      const holdsListMatch = path.match(/^\/api\/packages\/([^/]+)\/holds$/);
      if (holdsListMatch && req.method === 'GET') {
        const packageId = decodeURIComponent(holdsListMatch[1]);
        const view = lifecycle.packageLifecycleView(packageId);
        return send(res, 200, redact({
          packageId, holds: view.holds, activeHoldCount: view.activeHoldCount,
        }, [uploadSecret]));
      }

      // 发起保全（审计；期限内；requestId 幂等）
      const holdCreateMatch = path.match(/^\/api\/packages\/([^/]+)\/holds$/);
      if (holdCreateMatch && req.method === 'POST') {
        requireSecret(req);
        const packageId = decodeURIComponent(holdCreateMatch[1]);
        const out = lifecycle.createHold(packageId, body);
        logger.log({
          level: 'info', msg: out.replay ? 'hold-replayed' : 'hold-created',
          packageId, holdId: out.result.holdId, caseNo: out.result.caseNo, auditor: out.result.auditor,
        });
        return send(res, out.replay ? 200 : 201, { ...out.result, replay: out.replay });
      }

      // 解除保全（案件号必须匹配；并发解除安全失败）
      const releaseMatch = path.match(/^\/api\/packages\/([^/]+)\/holds\/([^/]+)\/release$/);
      if (releaseMatch && req.method === 'POST') {
        requireSecret(req);
        const packageId = decodeURIComponent(releaseMatch[1]);
        const holdId = decodeURIComponent(releaseMatch[2]);
        const out = lifecycle.releaseHold(packageId, holdId, body);
        logger.log({
          level: 'info', msg: out.replay ? 'hold-release-replayed' : 'hold-released',
          packageId, holdId, caseNo: out.result.caseNo,
        });
        return send(res, 200, { ...out.result, replay: out.replay });
      }

      // 销毁状态（尚未开始/正在提交/失败/已完成 + 回执）
      const dstStatusMatch = path.match(/^\/api\/packages\/([^/]+)\/destruction$/);
      if (dstStatusMatch && req.method === 'GET') {
        const packageId = decodeURIComponent(dstStatusMatch[1]);
        const status = lifecycle.destructionStatus(packageId);
        const receipt = lifecycle.receiptForPackage(packageId);
        return send(res, 200, redact({ packageId, ...status, receipt: receipt || null }, [uploadSecret]));
      }

      // 立即执行销毁（两阶段提交；资格闸与提交同一同步区）
      const destroyMatch = path.match(/^\/api\/packages\/([^/]+)\/destroy$/);
      if (destroyMatch && req.method === 'POST') {
        requireSecret(req);
        const packageId = decodeURIComponent(destroyMatch[1]);
        const { requestedBy, reason, _demoFailDelete } = body || {};
        if (!requestedBy || typeof requestedBy !== 'string') {
          throw Object.assign(new Error('requestedBy 必填（销毁执行人）'), { code: 'FIELD_REQUIRED', status: 400 });
        }
        let deleter;
        if (_demoFailDelete) {
          if (process.env.EVIDENCE_DEMO !== '1') {
            throw Object.assign(new Error('演示接口未开启（EVIDENCE_DEMO=1）'), { code: 'DEMO_DISABLED', status: 403 });
          }
          // 演示存储删除失败：首个文件删除即抛错，其余照常（用于演练失败后恢复）。
          let failed = false;
          deleter = {
            unlink(abs) {
              if (!failed) { failed = true; throw Object.assign(new Error('模拟存储删除失败（EPERM）'), { code: 'EPERM' }); }
              try { unlinkSync(abs); } catch (e) { if (e.code !== 'ENOENT') throw e; }
            },
            rmdir(abs) {
              try { rmdirSync(abs); } catch (e) { if (e.code !== 'ENOENT') throw e; }
            },
          };
        }
        const out = lifecycle.executeDestruction(packageId, { requestedBy, reason, deleter });
        logger.log({
          level: 'info', msg: out.duplicate ? 'destruction-replayed' : 'destruction-committed',
          packageId, receiptId: out.receipt.receiptId, requestedBy, status: out.status,
        });
        return send(res, 200, redact({
          packageId, duplicate: out.duplicate, status: out.status, receipt: out.receipt,
        }, [uploadSecret]));
      }

      // 失败后恢复：重试物理删除（不产生第二份回执）
      const retryMatch = path.match(/^\/api\/packages\/([^/]+)\/destruction\/retry$/);
      if (retryMatch && req.method === 'POST') {
        requireSecret(req);
        const packageId = decodeURIComponent(retryMatch[1]);
        const out = lifecycle.retryDestruction(packageId);
        logger.log({
          level: 'info', msg: 'destruction-retried', packageId,
          receiptId: out.receipt.receiptId, status: out.status,
        });
        return send(res, 200, redact({
          packageId, duplicate: out.duplicate, status: out.status, receipt: out.receipt,
        }, [uploadSecret]));
      }

      // 待销毁列表（合格 / 被保全阻塞 / 在途）
      if (path === '/api/destructions/pending' && req.method === 'GET') {
        return send(res, 200, redact(lifecycle.pendingDestruction(), [uploadSecret]));
      }

      // 销毁签名公钥（任何人可独立验签）
      if (path === '/api/destructions/key' && req.method === 'GET') {
        return send(res, 200, {
          keyId: lifecycle.signer.keyId,
          publicKeyPem: lifecycle.signer.publicKeyPem,
          algorithm: 'Ed25519',
          note: 'receiptHash = sha256(canonicalJSON(回执去掉 signature/keyId/receiptHash))；signature 为对该 hex 文本的 Ed25519 签名',
        });
      }

      // 到期任务：清扫全部合格包
      if (path === '/api/destructions/sweep' && req.method === 'POST') {
        requireSecret(req);
        const out = lifecycle.sweep({ requestedBy: body?.requestedBy || 'expiry-sweep' });
        logger.log({
          level: 'info', msg: 'destruction-swept',
          destroyed: out.destroyed.length, blocked: out.skipped.length, count: out.errors.length,
        });
        return send(res, 200, redact(out, [uploadSecret]));
      }

      // 全部销毁回执
      if (path === '/api/destructions' && req.method === 'GET') {
        return send(res, 200, { receipts: redact(lifecycle.listReceipts(), [uploadSecret]) });
      }

      // 单份回执 / 验签
      const receiptMatch = path.match(/^\/api\/destructions\/([^/]+)$/);
      if (receiptMatch && req.method === 'GET') {
        const receipt = lifecycle.receiptOf(decodeURIComponent(receiptMatch[1]));
        if (!receipt) {
          throw Object.assign(new Error('销毁回执不存在'), { code: 'RECEIPT_UNKNOWN', status: 404 });
        }
        return send(res, 200, redact(receipt, [uploadSecret]));
      }
      const receiptVerifyMatch = path.match(/^\/api\/destructions\/([^/]+)\/verify$/);
      if (receiptVerifyMatch && req.method === 'GET') {
        const out = lifecycle.verifyReceipt(decodeURIComponent(receiptVerifyMatch[1]));
        if (!out) {
          throw Object.assign(new Error('销毁回执不存在'), { code: 'RECEIPT_UNKNOWN', status: 404 });
        }
        return send(res, 200, redact(out, [uploadSecret]));
      }

      // ---------- 运营：从磁盘重放重建（等价进程重启）----------
      if (path === '/api/admin/restart' && req.method === 'POST') {
        requireSecret(req);
        restartFromDisk();
        logger.log({ level: 'info', msg: 'replay-restart' });
        return send(res, 200, { restarted: true, packages: manager.list() });
      }

      // ---------- 演示辅助：生成网关密钥对（仅在显式开启时；服务端不保存私钥）----------
      if (path === '/api/demo/keypair' && req.method === 'POST') {
        if (process.env.EVIDENCE_DEMO !== '1') {
          throw Object.assign(new Error('演示接口未开启（EVIDENCE_DEMO=1）'), { code: 'DEMO_DISABLED', status: 403 });
        }
        const pair = generateGatewayKeyPair();
        return send(res, 201, pair);
      }

      return send(res, 404, { error: 'unknown route', path });
    } catch (err) {
      const status = err.status || (err.code === 'CHAIN_QUARANTINED' ? 503 : 500);
      if (status === 500) {
        logger.log({ level: 'error', msg: 'internal-error', code: err.code, reason: String(err.message).slice(0, 160) });
      }
      send(res, status, {
        error: status === 500 ? 'internal error' : err.message,
        code: err.code || 'INTERNAL',
        details: redact(err.details || {}, [uploadSecret]),
      }, status === 503 ? { 'Retry-After': '300', 'Cache-Control': 'no-store' } : {});
    }
  });

  // 到期任务：周期清扫【期限已到 且 无有效保全】的包（EVIDENCE_SWEEP_MS=0 关闭，测试用手动触发）。
  const sweepMs = deps.sweepIntervalMs ?? Number(process.env.EVIDENCE_SWEEP_MS ?? 60000);
  let sweepTimer = null;
  if (sweepMs > 0) {
    sweepTimer = setInterval(() => {
      try {
        const out = lifecycle.sweep();
        if (out.destroyed.length || out.errors.length) {
          logger.log({
            level: 'info', msg: 'destruction-swept',
            destroyed: out.destroyed.length, count: out.errors.length,
          });
        }
      } catch (e) {
        logger.log({ level: 'error', msg: 'destruction-sweep-error', code: e.code, reason: String(e.message).slice(0, 160) });
      }
    }, sweepMs);
    sweepTimer.unref();
  }

  return {
    server, manager, registry, lifecycle,
    get uploadSecret() { return uploadSecret; },
    restartFromDisk,
    start() {
      return new Promise((resolve) => {
        server.listen(deps.port ?? PORT, HOST, () => resolve(server.address().port));
      });
    },
    stop() {
      if (sweepTimer) clearInterval(sweepTimer);
      return new Promise((r) => server.close(r));
    },
  };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const app = await createApp();
  const actualPort = await app.start();
  console.log(`证据归档与冲突核验服务已启动: http://localhost:${actualPort}/`);
  console.log(`证据目录: ${DATA_DIR}`);
  console.log(`导入鉴权: X-Upload-Secret 请求头（读取 sidecar: ${join(DATA_DIR, 'upload-secret.json')}，权限 0600）`);
}
