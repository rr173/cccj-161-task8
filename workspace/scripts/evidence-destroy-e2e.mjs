// 证据保全与到期销毁端到端场景（真实 HTTP，零依赖）：
//   期限设置（幂等/409）→ 保全发起/解除（案件号/并发解除）→ 多保全阻塞销毁
//   → 两阶段提交销毁（覆盖链文件/冲突材料/凭据旁车/业务索引）→ 读接口统一 410
//   → 签名回执验签 → 重复执行不生成第二份回执 → 到期任务 → 存储删除失败与恢复
//   → 真实进程重启：PREPARED/COMMITTED 中断态恢复到唯一结果。
//
// 用法：
//   node scripts/evidence-destroy-e2e.mjs              自动拉起临时服务，演完即停（含真实进程重启）
//   BASE=http://localhost:8092 node scripts/evidence-destroy-e2e.mjs --external   对已运行的服务测试
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync, existsSync, writeFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { once } from 'node:events';

const SELF_URL = new URL('../evidence/pack.js', import.meta.url);
const { buildEnvelope, manifestHashOf, R, generateGatewayKeyPair } = await import(SELF_URL.href);
const { LifecycleStore } = await import('../evidence/lifecycle.js');
const { ArchiveManager } = await import('../evidence/archive.js');
const { buildReport } = await import('../evidence/report.js');

let BASE = process.env.BASE || '';
const external = process.argv.includes('--external');
const SECRET = 'e2e-destroy-secret-' + 'b'.repeat(20);
let child = null;
let tmpDir = null;
function cleanupProcess() {
  try { child?.kill('SIGKILL'); } catch { /* ignore */ }
}
process.on('exit', cleanupProcess);
process.on('SIGINT', () => { cleanupProcess(); process.exit(130); });
process.on('SIGTERM', () => { cleanupProcess(); process.exit(143); });
let pass = 0, fail = 0;
function check(name, cond, extra = '') {
  if (cond) { pass++; console.log('  ✅', name, extra); }
  else { fail++; console.log('  ❌', name, extra); }
}
function eq(name, a, b) { check(name, a === b, `${JSON.stringify(a)} ${a === b ? '==' : '!='} ${JSON.stringify(b)}`); }

async function api(path, { method, body, secret = SECRET, headers = {} } = {}) {
  const method0 = method || (body === undefined ? 'GET' : 'POST');
  const h = {};
  if (body !== undefined) h['Content-Type'] = 'application/json';
  if (secret !== null) h['X-Upload-Secret'] = secret;
  Object.assign(h, headers);
  const res = await fetch(BASE + path, { method: method0, headers: h, body: body === undefined ? undefined : JSON.stringify(body) });
  const text = await res.text();
  let data; try { data = JSON.parse(text); } catch { data = text; }
  if (!res.ok) throw Object.assign(new Error(typeof data === 'object' ? data.error : text), {
    status: res.status, code: data?.code, details: data?.details, raw: data,
  });
  return data;
}
async function expectCode(name, fn, code, status) {
  try { await fn(); check(name, false, '未拒绝'); }
  catch (e) {
    const ok = e.code === code && (status === undefined || e.status === status);
    check(name, ok, `${e.code || e.status}（期望 ${code}${status ? '/' + status : ''}）`);
  }
}

async function startServer() {
  if (!tmpDir) tmpDir = mkdtempSync(join(tmpdir(), 'evidence-destroy-e2e-'));
  child = spawn(process.execPath, ['evidence/server.js'], {
    env: {
      ...process.env, EVIDENCE_DIR: tmpDir, EVIDENCE_PORT: '0', EVIDENCE_HOST: '127.0.0.1',
      EVIDENCE_UPLOAD_SECRET: SECRET, EVIDENCE_DEMO: '1', EVIDENCE_SWEEP_MS: '0',
    },
    stdio: ['ignore', 'pipe', 'inherit'],
  });
  let buf = '';
  const port = await new Promise((resolve, reject) => {
    child.stdout.on('data', (d) => {
      buf += d.toString();
      const m = buf.match(/http:\/\/localhost:(\d+)\//);
      if (m) resolve(Number(m[1]));
    });
    child.on('exit', (code) => reject(new Error('服务提前退出 code=' + code)));
    setTimeout(() => reject(new Error('服务启动超时')), 5000);
  });
  BASE = `http://127.0.0.1:${port}`;
  await new Promise((r) => setTimeout(r, 50));
}
async function stopServer() {
  if (!child) return;
  child.kill('SIGTERM');
  await Promise.race([
    once(child, 'exit').catch(() => {}),
    new Promise((r) => setTimeout(r, 1500)),
  ]);
  if (child.exitCode === null && child.signalCode === null) {
    try { child.kill('SIGKILL'); } catch { /* 已退出 */ }
    await once(child, 'exit').catch(() => {});
  }
  child = null;
}
async function restartServer() {
  await stopServer();
  await startServer();
}

// ---------- 素材 ----------
const gwA = generateGatewayKeyPair();
const gwB = generateGatewayKeyPair();
const KID = 'gw-key-1';
const T = '2026-10-01T08:00:00Z';
const P1 = 'PKG-D1'; // 主流程：期限+双保全+销毁
const P2 = 'PKG-D2'; // 到期任务：合格
const P3 = 'PKG-D3'; // 到期任务：未到期
const P4 = 'PKG-D4'; // 到期任务：保全阻塞
const P5 = 'PKG-D5'; // 存储删除失败与恢复
const P6 = 'PKG-D6'; // 崩溃于提交前（PREPARED）
const P7 = 'PKG-D7'; // 崩溃于删除中（COMMITTED）

function env(packageId, gateway, keyId, priv, records) {
  return buildEnvelope({ packageId, gatewayId: gateway, keyId, records, privateKeyPem: priv });
}
async function importEvidence(packageId) {
  const manifest = { entries: [{ seq: 0, deviceId: 'DEV-1' }, { seq: 1, deviceId: 'DEV-2' }], issuedAt: T, validUntil: null };
  const r = await api(`/api/packages/${packageId}/import`, {
    body: env(packageId, 'gw-A', KID, gwA.privateKeyPem, [
      R.manifest(T, manifest, manifestHashOf(manifest)),
      R.fence(T, 'fence-A', 1, 'CREATED'),
      R.segment(T, 'fence-A', 1, 1, [{ seq: 0, deviceId: 'DEV-1', outcome: 'EXECUTED' }]),
    ]),
  });
  eq(`${packageId} 证据导入`, r.result, 'ACCEPTED');
  return r;
}
const pastIso = () => new Date(Date.now() - 5000).toISOString();
const futureIso = () => new Date(Date.now() + 3600_000).toISOString();

console.log('① 服务启动 / 网关登记 / 证据导入（含冲突材料与凭据旁车）');
if (!external) await startServer();
else BASE = BASE || 'http://localhost:8092';

await api('/api/gateways', { body: { gatewayId: 'gw-A', keyId: KID, publicKeyPem: gwA.publicKeyPem } });
await api('/api/gateways', { body: { gatewayId: 'gw-B', keyId: KID, publicKeyPem: gwB.publicKeyPem } });
await importEvidence(P1);
// 冲突材料：同分段异内容 → quarantine
const conflictRes = await api(`/api/packages/${P1}/import`, {
  body: env(P1, 'gw-B', KID, gwB.privateKeyPem, [
    R.segment('2026-10-01T09:00:00Z', 'fence-A', 1, 1, [{ seq: 0, deviceId: 'DEV-1', outcome: 'FAILED' }]),
  ]),
});
eq('冲突材料入账', conflictRes.result, 'CONFLICTS');
// 被拒留底：未知网关信封 → rejected/
await expectCode('未知网关被拒（产生 rejected 留底）', () =>
  api(`/api/packages/${P1}/import`, { body: env(P1, 'gw-X', 'k', gwA.privateKeyPem, [
    R.segment(T, 'fence-A', 1, 9, [{ seq: 1, deviceId: 'DEV-2', outcome: 'EXECUTED' }]),
  ]) }), 'GATEWAY_UNKNOWN', 422);
// 凭据旁车：直接落盘到包目录（演练销毁覆盖）
if (!external) {
  writeFileSync(join(tmpDir, 'packages', P1, 'gateway-upload.keys.json'),
    JSON.stringify({ fence: 1, uploadSecret: 'gw-sidecar-secret' }) + '\n', { mode: 0o600 });
}
for (const p of [P2, P3, P4, P5, P6, P7]) await importEvidence(p);

console.log('② 保留期限与保全（幂等 / 409 / 案件号 / 并发解除）');
await expectCode('未设期限销毁 → RETENTION_NOT_SET', () =>
  api(`/api/packages/${P1}/destroy`, { body: { requestedBy: 'ops-1' } }), 'RETENTION_NOT_SET', 409);
const ret1 = await api(`/api/packages/${P1}/retention`, {
  body: { requestId: 'ret-1', retainUntil: futureIso(), setBy: 'ops-1', reason: '年度保留策略' },
});
eq('设置期限 201 且规范化', Boolean(ret1.retainUntil), true);
const retReplay = await api(`/api/packages/${P1}/retention`, {
  body: { requestId: 'ret-1', retainUntil: ret1.retainUntil, setBy: 'ops-1', reason: '年度保留策略' },
});
check('期限同请求重放返原结果', retReplay.replay === true && retReplay.setAt === ret1.setAt);
await expectCode('期限同号异文 → 409 REQUEST_ID_CONFLICT', () =>
  api(`/api/packages/${P1}/retention`, {
    body: { requestId: 'ret-1', retainUntil: futureIso(), setBy: 'ops-2' },
  }), 'REQUEST_ID_CONFLICT', 409);
await expectCode('未到期销毁 → RETENTION_NOT_EXPIRED', () =>
  api(`/api/packages/${P1}/destroy`, { body: { requestedBy: 'ops-1' } }), 'RETENTION_NOT_EXPIRED', 409);

const hold1 = await api(`/api/packages/${P1}/holds`, {
  body: { requestId: 'hold-1', caseNo: 'CASE-2026-001', reason: '监管稽查', auditor: 'auditor-1' },
});
eq('保全 1 签发', hold1.holdId, `${P1}-H1`);
const hold1Replay = await api(`/api/packages/${P1}/holds`, {
  body: { requestId: 'hold-1', caseNo: 'CASE-2026-001', reason: '监管稽查', auditor: 'auditor-1' },
});
check('保全同请求重放返原结果', hold1Replay.replay === true && hold1Replay.holdId === hold1.holdId
  && hold1Replay.createdAt === hold1.createdAt);
await expectCode('保全同号异文 → 409 REQUEST_ID_CONFLICT', () =>
  api(`/api/packages/${P1}/holds`, {
    body: { requestId: 'hold-1', caseNo: 'CASE-OTHER', reason: 'x', auditor: 'auditor-1' },
  }), 'REQUEST_ID_CONFLICT', 409);
await expectCode('同案件号重复保全 → 409 HOLD_CASE_ACTIVE', () =>
  api(`/api/packages/${P1}/holds`, {
    body: { requestId: 'hold-2', caseNo: 'CASE-2026-001', reason: 'x', auditor: 'auditor-2' },
  }), 'HOLD_CASE_ACTIVE', 409);
const hold2 = await api(`/api/packages/${P1}/holds`, {
  body: { requestId: 'hold-3', caseNo: 'CASE-2026-002', reason: '民事诉讼', auditor: 'auditor-2' },
});
eq('多保全并存（第二个签发）', hold2.holdId, `${P1}-H2`);

await expectCode('保全中销毁 → 409 DESTRUCTION_BLOCKED_HOLDS', () =>
  api(`/api/packages/${P1}/destroy`, { body: { requestedBy: 'ops-1' } }), 'DESTRUCTION_BLOCKED_HOLDS', 409);
const blockedView = await api(`/api/packages/${P1}/lifecycle`);
eq('生命周期视图：有效保全数 2', blockedView.activeHoldCount, 2);
check('生命周期视图：阻塞原因含 HOLDS_ACTIVE', blockedView.blockers.includes('HOLDS_ACTIVE')
  && blockedView.blockers.includes('RETENTION_NOT_EXPIRED'));
const pending1 = await api('/api/destructions/pending');
check('待销毁列表暂不含未到期包', !pending1.eligible.some((x) => x.packageId === P1));

await expectCode('错误案件号解除 → 409 CASE_NO_MISMATCH', () =>
  api(`/api/packages/${P1}/holds/${hold1.holdId}/release`, {
    body: { requestId: 'rel-1', caseNo: 'CASE-WRONG' },
  }), 'CASE_NO_MISMATCH', 409);
const rel1 = await api(`/api/packages/${P1}/holds/${hold1.holdId}/release`, {
  body: { requestId: 'rel-1', caseNo: 'CASE-2026-001', releasedBy: 'auditor-1' },
});
eq('解除保全 1', rel1.status, 'RELEASED');
const rel1Replay = await api(`/api/packages/${P1}/holds/${hold1.holdId}/release`, {
  body: { requestId: 'rel-1', caseNo: 'CASE-2026-001', releasedBy: 'auditor-1' },
});
check('解除同请求重放返原结果', rel1Replay.replay === true && rel1Replay.releasedAt === rel1.releasedAt);
await expectCode('并发解除（另一请求号）→ 409 HOLD_ALREADY_RELEASED', () =>
  api(`/api/packages/${P1}/holds/${hold1.holdId}/release`, {
    body: { requestId: 'rel-2', caseNo: 'CASE-2026-001' },
  }), 'HOLD_ALREADY_RELEASED', 409);
await expectCode('仍有一个保全 → 销毁仍被阻', () =>
  api(`/api/packages/${P1}/destroy`, { body: { requestedBy: 'ops-1' } }), 'DESTRUCTION_BLOCKED_HOLDS', 409);
await api(`/api/packages/${P1}/holds/${hold2.holdId}/release`, {
  body: { requestId: 'rel-3', caseNo: 'CASE-2026-002', releasedBy: 'auditor-2' },
});
// 全部解除后把期限改到过去（新请求号）
await api(`/api/packages/${P1}/retention`, {
  body: { requestId: 'ret-2', retainUntil: pastIso(), setBy: 'ops-1', reason: '案件结案，期限届满' },
});
const pending2 = await api('/api/destructions/pending');
check('全部解除+到期后进入待销毁合格列表', pending2.eligible.some((x) => x.packageId === P1));

console.log('③ 两阶段提交销毁：覆盖四类对象，读接口统一 410，回执唯一可验');
const reportBefore = await api(`/api/packages/${P1}/report`);
const digestBefore = reportBefore.reportDigest;
check('销毁前读=完整旧状态', reportBefore.timeline.length > 0 && reportBefore.conflicts.length === 1);
const dst = await api(`/api/packages/${P1}/destroy`, { body: { requestedBy: 'ops-1', reason: '期限届满' } });
eq('销毁完成', dst.status, 'COMPLETED');
const receipt = dst.receipt;
check('回执 ID 形态', /^dst_[0-9a-f]{24}$/.test(receipt.receiptId), receipt.receiptId);
eq('回执锚定最终报告摘要', receipt.evidenceSummary.reportDigest, digestBefore);
const cats = new Set(receipt.files.map((f) => f.category));
check('覆盖链文件', cats.has('chain') && receipt.removed.chains === 2);
check('覆盖冲突材料', cats.has('conflict') && receipt.removed.conflictMaterials >= 2);
check('覆盖凭据旁车', cats.has('credential') && receipt.removed.credentialSidecars === 1);
eq('业务索引随提交失效', receipt.removed.businessIndexes.inMemoryProjections, 'evicted-on-commit');
eq('回执记录两个已解除保全', receipt.holds.length, 2);
check('回执不含原始证据', !JSON.stringify(receipt).includes('DEV-1')
  && !JSON.stringify(receipt).includes('EXECUTED')
  && !JSON.stringify(receipt).includes('gw-sidecar-secret'));

for (const [name, path] of [
  ['报告', 'report'], ['时间线', 'timeline'], ['冲突', 'conflicts'],
  ['裁决历史', 'imports'], ['链核验', 'verify'],
]) {
  await expectCode(`销毁后${name} → 410 PACKAGE_DESTROYED`, () =>
    api(`/api/packages/${P1}/${path}`, { secret: null }), 'PACKAGE_DESTROYED', 410);
}
const listAfter = await api('/api/packages');
check('包列表不再含已销毁包', !listAfter.packages.some((p) => p.packageId === P1));
if (!external) {
  check('包目录已物理删除', !existsSync(join(tmpDir, 'packages', P1)));
  check('凭据旁车已删除', !existsSync(join(tmpDir, 'packages', P1, 'gateway-upload.keys.json')));
  check('被拒留底已删除', !readdirSync(join(tmpDir, 'rejected')).some((f) => f.includes(P1)));
}
const dst2 = await api(`/api/packages/${P1}/destroy`, { body: { requestedBy: 'ops-1' } });
check('重复销毁返同一回执', dst2.duplicate === true && dst2.receipt.receiptId === receipt.receiptId);
const receipts1 = await api('/api/destructions');
eq('回执列表中该包仅一份', receipts1.receipts.filter((r) => r.packageId === P1).length, 1);
const verify1 = await api(`/api/destructions/${receipt.receiptId}/verify`);
check('回执验签全绿', verify1.ok === true && Object.values(verify1.checks).every(Boolean));
const pubKey = await api('/api/destructions/key');
eq('验签公钥与回执 keyId 一致', pubKey.keyId, receipt.keyId);
await expectCode('销毁后导入 → 410（不重建目录）', () =>
  api(`/api/packages/${P1}/import`, {
    body: env(P1, 'gw-A', KID, gwA.privateKeyPem, [
      R.segment(T, 'fence-A', 1, 2, [{ seq: 1, deviceId: 'DEV-2', outcome: 'EXECUTED' }]),
    ]),
  }), 'PACKAGE_DESTROYED', 410);
if (!external) check('导入被拒后目录未重建', !existsSync(join(tmpDir, 'packages', P1)));
await expectCode('销毁后设期限 → 410', () =>
  api(`/api/packages/${P1}/retention`, {
    body: { requestId: 'ret-9', retainUntil: futureIso(), setBy: 'ops-1' },
  }), 'PACKAGE_DESTROYED', 410);
await expectCode('销毁后发起保全 → 410', () =>
  api(`/api/packages/${P1}/holds`, {
    body: { requestId: 'hold-9', caseNo: 'CASE-X', reason: 'x', auditor: 'a' },
  }), 'PACKAGE_DESTROYED', 410);
const dstStatus = await api(`/api/packages/${P1}/destruction`);
eq('销毁状态可查（COMPLETED）', dstStatus.status, 'COMPLETED');
eq('销毁状态含回执', dstStatus.receipt.receiptId, receipt.receiptId);
const holdsAfter = await api(`/api/packages/${P1}/holds`);
eq('销毁后保全历史仍可核对', holdsAfter.holds.length, 2);

console.log('④ 到期任务：只销毁合格包，跳过原因可核对');
await api(`/api/packages/${P2}/retention`, { body: { requestId: 'r-p2', retainUntil: pastIso(), setBy: 'ops-1' } });
await api(`/api/packages/${P3}/retention`, { body: { requestId: 'r-p3', retainUntil: futureIso(), setBy: 'ops-1' } });
await api(`/api/packages/${P4}/retention`, { body: { requestId: 'r-p4', retainUntil: futureIso(), setBy: 'ops-1' } });
await api(`/api/packages/${P4}/holds`, {
  body: { requestId: 'h-p4', caseNo: 'CASE-P4', reason: '保全中', auditor: 'auditor-1' },
});
// P4 期限改到过去（保全仍在）
await api(`/api/packages/${P4}/retention`, { body: { requestId: 'r-p4b', retainUntil: pastIso(), setBy: 'ops-1' } });
const sweep = await api('/api/destructions/sweep', { body: { requestedBy: 'expiry-sweep' } });
check('到期任务销毁合格包 P2', sweep.destroyed.some((x) => x.packageId === P2));
const skipBy = Object.fromEntries(sweep.skipped.map((s) => [s.packageId, s.reason]));
eq('未到期跳过', skipBy[P3], 'RETENTION_NOT_EXPIRED');
eq('保全中跳过', skipBy[P4], 'HOLDS_ACTIVE');
check('保全中的包未被误删', (await api(`/api/packages/${P4}/report`)).packageId === P4);
check('未到期包未被误删', (await api(`/api/packages/${P3}/report`)).packageId === P3);
await expectCode('被销毁的 P2 报告 → 410', () =>
  api(`/api/packages/${P2}/report`, { secret: null }), 'PACKAGE_DESTROYED', 410);

console.log('⑤ 存储删除失败 → FAILED 可核对 → 重试恢复（不产生第二份回执）');
await api(`/api/packages/${P5}/retention`, { body: { requestId: 'r-p5', retainUntil: pastIso(), setBy: 'ops-1' } });
await expectCode('存储删除失败 → 500 STORAGE_DELETE_FAILED', () =>
  api(`/api/packages/${P5}/destroy`, { body: { requestedBy: 'ops-1', _demoFailDelete: true } }),
  'STORAGE_DELETE_FAILED', 500);
const failedStatus = await api(`/api/packages/${P5}/destruction`);
eq('失败状态可核对（FAILED）', failedStatus.status, 'FAILED');
check('失败状态含剩余文件清单', failedStatus.remainingFiles.length >= 1,
  failedStatus.remainingFiles.join(','));
if (!external) check('失败时包目录仍在（部分未删）', existsSync(join(tmpDir, 'packages', P5)));
await expectCode('已提交即读=已销毁（即使删除失败）', () =>
  api(`/api/packages/${P5}/report`, { secret: null }), 'PACKAGE_DESTROYED', 410);
const retried = await api(`/api/packages/${P5}/destruction/retry`, { body: {} });
eq('重试后完成', retried.status, 'COMPLETED');
const receiptsAfterRetry = await api('/api/destructions');
eq('重试不产生第二份回执',
  receiptsAfterRetry.receipts.filter((r) => r.packageId === P5).length, 1);
eq('重试回执与失败时一致', retried.receipt.receiptId, failedStatus.receiptId);
if (!external) check('重试后目录清空', !existsSync(join(tmpDir, 'packages', P5)));
const retryAgain = await api(`/api/packages/${P5}/destruction/retry`, { body: {} });
check('完成后重试幂等', retryAgain.duplicate === true);

console.log('⑥ 真实进程重启：中断态恢复（PREPARED / COMMITTED）与回执持久');
await api(`/api/packages/${P6}/retention`, { body: { requestId: 'r-p6', retainUntil: pastIso(), setBy: 'ops-1' } });
await api(`/api/packages/${P7}/retention`, { body: { requestId: 'r-p7', retainUntil: pastIso(), setBy: 'ops-1' } });
const receiptsBeforeRestart = (await api('/api/destructions')).receipts.length;
if (!external) {
  await stopServer();
  // 离线推进 P6 到 PREPARED（模拟提交前断电）
  const offline1 = new LifecycleStore(tmpDir, {});
  offline1.prepareDestruction(P6);
  eq('P6 注入 PREPARED 态', offline1.destructionStatus(P6).status, 'PREPARED');
  // 离线推进 P7 到 COMMITTED（模拟删除中断电）；快照钩子与在线一致
  const offline2 = new LifecycleStore(tmpDir, {});
  offline2.setHooks({
    snapshot(packageId) {
      const manager = new ArchiveManager(tmpDir);
      const archive = manager.open(packageId);
      const report = buildReport(archive);
      return {
        reportDigest: report.reportDigest,
        chainTips: {
          ledger: { seq: archive.ledger.seq, hash: archive.ledger.tipHash },
          quarantine: { seq: archive.quarantine.seq, hash: archive.quarantine.tipHash },
          audit: { seq: archive.audit.seq, hash: archive.audit.tipHash },
        },
        counts: { acceptedRecords: report.acceptedRecordCount, conflicts: report.conflictCount, imports: report.imports.length },
      };
    },
  });
  offline2.prepareDestruction(P7);
  const committedP7 = offline2.commitDestruction(P7, { requestedBy: 'crash-sim' });
  eq('P7 注入 COMMITTED 态', offline2.destructionStatus(P7).status, 'COMMITTED');
  check('P7 文件尚未删除（提交后删除中断）', existsSync(join(tmpDir, 'packages', P7, 'ledger.jsonl')));
  await startServer(); // 启动即 recover()
  const st6 = await api(`/api/packages/${P6}/destruction`);
  eq('P6 恢复后完成', st6.status, 'COMPLETED');
  const st7 = await api(`/api/packages/${P7}/destruction`);
  eq('P7 恢复后完成', st7.status, 'COMPLETED');
  eq('P7 回执与崩溃前一致（唯一结果）', st7.receipt.receiptId, committedP7.receiptId);
  check('P6/P7 目录已删除', !existsSync(join(tmpDir, 'packages', P6)) && !existsSync(join(tmpDir, 'packages', P7)));
  const receiptsNow = await api('/api/destructions');
  eq('恢复只新增两份回执（无重复）', receiptsNow.receipts.length, receiptsBeforeRestart + 2);
  eq('每包回执唯一',
    new Set(receiptsNow.receipts.map((r) => r.packageId)).size, receiptsNow.receipts.length);
  // 重启后历史回执仍可验签
  const verifyP1 = await api(`/api/destructions/${receipt.receiptId}/verify`);
  check('重启后 P1 回执验签仍有效', verifyP1.ok === true);
  // 重启后保全/期限投影一致
  const lcP4 = await api(`/api/packages/${P4}/lifecycle`);
  eq('重启后 P4 保全仍在', lcP4.activeHoldCount, 1);
  await expectCode('重启后 P1 读仍 410', () =>
    api(`/api/packages/${P1}/report`, { secret: null }), 'PACKAGE_DESTROYED', 410);
} else {
  await api('/api/admin/restart');
  const verifyP1 = await api(`/api/destructions/${receipt.receiptId}/verify`);
  check('重放后 P1 回执验签仍有效', verifyP1.ok === true);
}

console.log('⑦ 页面与链核验');
const home = await fetch(`${BASE}/`).then((r) => r.text());
check('页面包含保全与销毁面板', home.includes('保全') && home.includes('销毁'));
const chainAll = await api('/api/chain/verify');
check('全局链核验含生命周期链', chainAll.lifecycle && chainAll.lifecycle.ok === true);
check('已销毁包不参与证据链核验', !chainAll.packages[P1] || chainAll.packages[P1].destroyed === true);

if (!external) {
  await stopServer();
  rmSync(tmpDir, { recursive: true, force: true });
}

console.log(`\n结果：${pass} 通过 / ${fail} 失败`);
if (fail) process.exitCode = 1;
