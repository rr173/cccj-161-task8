// 证据保全与到期销毁单测：
//   保留期限 / 保全（幂等·409·案件号·并发解除）/ 两阶段提交销毁（覆盖四类对象）/
//   签名回执（唯一·可验·不含原始证据）/ 崩溃恢复（PREPARED、COMMITTED 中断）/
//   存储删除失败与重试 / 到期任务 / 重启重放 / 链隔离。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  mkdtempSync, rmSync, existsSync, writeFileSync, mkdirSync, readFileSync, readdirSync,
  unlinkSync, rmdirSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { LifecycleStore, RECEIPT_SCHEMA } from '../evidence/lifecycle.js';
import { ArchiveManager } from '../evidence/archive.js';
import { GatewayRegistry } from '../evidence/crypto.js';
import { buildEnvelope, R, manifestHashOf, generateGatewayKeyPair } from '../evidence/pack.js';
import { buildReport } from '../evidence/report.js';
import { canonicalJSON, sha256Hex } from '../evidence/hashing.js';

const T0 = Date.parse('2026-10-01T00:00:00Z');
const DAY = 24 * 3600 * 1000;

function tmp() {
  return mkdtempSync(join(tmpdir(), 'ev-lc-'));
}

// 每个测试目录共享一个网关身份（重复登记不同公钥会被注册表拒绝）。
const worlds = new Map();
function world(dir) {
  if (!worlds.has(dir)) {
    const gw = generateGatewayKeyPair();
    const registry = new GatewayRegistry(join(dir, 'gateways.json'));
    if (!registry.has('gw-A')) {
      registry.register({ gatewayId: 'gw-A', keyId: 'k1', publicKeyPem: gw.publicKeyPem, createdAt: '2026-10-01T08:00:00Z' });
    }
    worlds.set(dir, { gw, registry, manager: new ArchiveManager(dir) });
  }
  return worlds.get(dir);
}

// 造一个带证据（含冲突材料）+ 凭据旁车 + 被拒留底的作业包。
function makePkg(dir, packageId, { withConflict = true, withSidecar = true, withRejected = true } = {}) {
  const w = world(dir);
  const a = w.manager.open(packageId);
  const T = '2026-10-01T08:00:00Z';
  const manifest = { entries: [{ seq: 0, deviceId: 'D-1' }, { seq: 1, deviceId: 'D-2' }], issuedAt: T, validUntil: null };
  a.importEnvelope(buildEnvelope({
    packageId, gatewayId: 'gw-A', keyId: 'k1', privateKeyPem: w.gw.privateKeyPem,
    records: [
      R.manifest(T, manifest, manifestHashOf(manifest)),
      R.fence(T, 'f1', 1, 'CREATED'),
      R.segment(T, 'f1', 1, 1, [{ seq: 0, deviceId: 'D-1', outcome: 'EXECUTED' }]),
    ],
  }), { registry: w.registry, nowIso: T });
  if (withConflict) {
    a.importEnvelope(buildEnvelope({
      packageId, gatewayId: 'gw-A', keyId: 'k1', privateKeyPem: w.gw.privateKeyPem,
      records: [R.segment(T, 'f1', 1, 1, [{ seq: 0, deviceId: 'D-1', outcome: 'FAILED' }])],
    }), { registry: w.registry, nowIso: T });
  }
  if (withSidecar) {
    // 凭据旁车：网关上传密钥材料随包存放（销毁必须覆盖）。
    writeFileSync(join(dir, 'packages', packageId, 'gateway-upload.keys.json'),
      JSON.stringify({ fence: 1, uploadSecret: 'gw-secret-material' }) + '\n', { mode: 0o600 });
  }
  if (withRejected) {
    const rejDir = join(dir, 'rejected');
    mkdirSync(rejDir, { recursive: true });
    writeFileSync(join(rejDir, `2026-10-01T09-00-00-000Z-${packageId}.json`),
      JSON.stringify({ at: T, targetPackageId: packageId, code: 'SIGNATURE_INVALID', message: 'x', envelope: null }) + '\n',
      { mode: 0o600 });
  }
  return { manager: w.manager, archive: a };
}

function makeStore(dir, nowMs, hooks = {}) {
  let clock = nowMs;
  const store = new LifecycleStore(dir, {
    now: () => new Date(clock),
    ...hooks,
  });
  store.setHooks({
    snapshot(packageId) {
      const manager = new ArchiveManager(dir);
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
    evict() {},
    ...hooks,
  });
  return {
    store,
    setClock(ms) { clock = ms; },
    advance(ms) { clock += ms; },
  };
}

test('保留期限：设置/重放幂等/同号不同内容 409', () => {
  const dir = tmp();
  try {
    makePkg(dir, 'P1');
    const { store } = makeStore(dir, T0);
    const r1 = store.setRetention('P1', { requestId: 'ret-1', retainUntil: '2026-10-10T00:00:00Z', setBy: 'ops-1' });
    assert.equal(r1.replay, false);
    assert.equal(r1.result.retainUntil, '2026-10-10T00:00:00.000Z');
    // 同一请求再次提交 → 原结果
    const r2 = store.setRetention('P1', { requestId: 'ret-1', retainUntil: '2026-10-10T00:00:00Z', setBy: 'ops-1' });
    assert.equal(r2.replay, true);
    assert.deepEqual(r2.result, r1.result);
    // 同号不同内容 → 409
    assert.throws(() => store.setRetention('P1', { requestId: 'ret-1', retainUntil: '2026-11-10T00:00:00Z', setBy: 'ops-1' }),
      { code: 'REQUEST_ID_CONFLICT', status: 409 });
    // 新 requestId 可更新期限
    const r3 = store.setRetention('P1', { requestId: 'ret-2', retainUntil: '2026-12-01T00:00:00Z', setBy: 'ops-1' });
    assert.equal(r3.result.retainUntil, '2026-12-01T00:00:00.000Z');
    assert.equal(store.retention.get('P1').retainUntil, '2026-12-01T00:00:00.000Z');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('保留期限：非法输入与未知包被拒', () => {
  const dir = tmp();
  try {
    makePkg(dir, 'P1');
    const { store } = makeStore(dir, T0);
    assert.throws(() => store.setRetention('P1', { requestId: 'r1', retainUntil: 'not-a-date', setBy: 'ops' }),
      { code: 'RETENTION_INVALID' });
    assert.throws(() => store.setRetention('P1', { requestId: 'r1', retainUntil: '2026-10-10T00:00:00Z' }),
      { code: 'FIELD_REQUIRED' });
    assert.throws(() => store.setRetention('P1', { retainUntil: '2026-10-10T00:00:00Z', setBy: 'ops' }),
      { code: 'FIELD_REQUIRED' });
    assert.throws(() => store.setRetention('NOPE', { requestId: 'r9', retainUntil: '2026-10-10T00:00:00Z', setBy: 'ops' }),
      { code: 'PACKAGE_UNKNOWN', status: 404 });
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('销毁资格：未设期限 / 未到期分别拒绝', () => {
  const dir = tmp();
  try {
    makePkg(dir, 'P1');
    makePkg(dir, 'P2');
    const { store } = makeStore(dir, T0);
    assert.throws(() => store.executeDestruction('P1', { requestedBy: 'ops' }),
      { code: 'RETENTION_NOT_SET', status: 409 });
    store.setRetention('P2', { requestId: 'r1', retainUntil: new Date(T0 + 10 * DAY).toISOString(), setBy: 'ops' });
    assert.throws(() => store.executeDestruction('P2', { requestedBy: 'ops' }),
      { code: 'RETENTION_NOT_EXPIRED', status: 409 });
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('保全：期限内可发起；过期后发起被拒（RETENTION_EXPIRED）', () => {
  const dir = tmp();
  try {
    makePkg(dir, 'P1');
    const { store, setClock } = makeStore(dir, T0);
    store.setRetention('P1', { requestId: 'r1', retainUntil: new Date(T0 + DAY).toISOString(), setBy: 'ops' });
    const h = store.createHold('P1', { requestId: 'h1', caseNo: 'CASE-001', reason: '监管调查', auditor: 'aud-1' });
    assert.equal(h.result.status, 'ACTIVE');
    assert.equal(h.result.holdId, 'P1-H1');
    setClock(T0 + 2 * DAY); // 已过保留期限
    assert.throws(() => store.createHold('P1', { requestId: 'h2', caseNo: 'CASE-002', reason: 'x', auditor: 'aud-1' }),
      { code: 'RETENTION_EXPIRED', status: 409 });
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('保全：必填校验 + 幂等（同号同文返原结果，同号异文 409）', () => {
  const dir = tmp();
  try {
    makePkg(dir, 'P1');
    const { store } = makeStore(dir, T0);
    assert.throws(() => store.createHold('P1', { requestId: 'h1', reason: 'x', auditor: 'a' }), { code: 'FIELD_REQUIRED' });
    assert.throws(() => store.createHold('P1', { requestId: 'h1', caseNo: 'C', auditor: 'a' }), { code: 'FIELD_REQUIRED' });
    assert.throws(() => store.createHold('P1', { requestId: 'h1', caseNo: 'C', reason: 'x' }), { code: 'FIELD_REQUIRED' });
    const h1 = store.createHold('P1', { requestId: 'h1', caseNo: 'CASE-1', reason: 'r', auditor: 'aud' });
    const h2 = store.createHold('P1', { requestId: 'h1', caseNo: 'CASE-1', reason: 'r', auditor: 'aud' });
    assert.equal(h2.replay, true);
    assert.deepEqual(h2.result, h1.result);
    assert.equal(store.activeHolds('P1').length, 1); // 未新增
    assert.throws(() => store.createHold('P1', { requestId: 'h1', caseNo: 'CASE-OTHER', reason: 'r', auditor: 'aud' }),
      { code: 'REQUEST_ID_CONFLICT', status: 409 });
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('保全：同案件号有效保全唯一；解除后同案件号可再保全', () => {
  const dir = tmp();
  try {
    makePkg(dir, 'P1');
    const { store } = makeStore(dir, T0);
    store.createHold('P1', { requestId: 'h1', caseNo: 'CASE-1', reason: 'r', auditor: 'aud' });
    assert.throws(() => store.createHold('P1', { requestId: 'h2', caseNo: 'CASE-1', reason: 'r2', auditor: 'aud2' }),
      { code: 'HOLD_CASE_ACTIVE', status: 409 });
    store.releaseHold('P1', 'P1-H1', { requestId: 'rel-1', caseNo: 'CASE-1' });
    const h = store.createHold('P1', { requestId: 'h3', caseNo: 'CASE-1', reason: '重新立案', auditor: 'aud' });
    assert.equal(h.result.holdId, 'P1-H2');
    assert.equal(store.activeHolds('P1').length, 1);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('多保全并存：全部解除且期限已到才允许销毁', () => {
  const dir = tmp();
  try {
    makePkg(dir, 'P1');
    const { store, setClock } = makeStore(dir, T0);
    store.setRetention('P1', { requestId: 'r1', retainUntil: new Date(T0 + DAY).toISOString(), setBy: 'ops' });
    store.createHold('P1', { requestId: 'h1', caseNo: 'CASE-1', reason: 'r', auditor: 'aud' });
    store.createHold('P1', { requestId: 'h2', caseNo: 'CASE-2', reason: 'r', auditor: 'aud' });
    setClock(T0 + 2 * DAY); // 期限已到
    try {
      store.executeDestruction('P1', { requestedBy: 'ops' });
      assert.fail('应被保全阻塞');
    } catch (e) {
      assert.equal(e.code, 'DESTRUCTION_BLOCKED_HOLDS');
      assert.equal(e.details.activeHolds.length, 2);
      assert.deepEqual(e.details.activeHolds.map((x) => x.caseNo).sort(), ['CASE-1', 'CASE-2']);
    }
    // 解除一个仍不可销毁
    store.releaseHold('P1', 'P1-H1', { requestId: 'rel-1', caseNo: 'CASE-1' });
    assert.throws(() => store.executeDestruction('P1', { requestedBy: 'ops' }),
      { code: 'DESTRUCTION_BLOCKED_HOLDS' });
    // 全部解除 → 允许销毁
    store.releaseHold('P1', 'P1-H2', { requestId: 'rel-2', caseNo: 'CASE-2' });
    const out = store.executeDestruction('P1', { requestedBy: 'ops' });
    assert.equal(out.status, 'COMPLETED');
    assert.equal(out.receipt.holds.length, 2);
    assert.ok(out.receipt.holds.every((h) => h.status === 'RELEASED'));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('解除：错误案件号 409；未知保全 404；并发解除安全失败', () => {
  const dir = tmp();
  try {
    makePkg(dir, 'P1');
    const { store } = makeStore(dir, T0);
    store.createHold('P1', { requestId: 'h1', caseNo: 'CASE-1', reason: 'r', auditor: 'aud' });
    assert.throws(() => store.releaseHold('P1', 'P1-H1', { requestId: 'rel-1', caseNo: 'WRONG-CASE' }),
      { code: 'CASE_NO_MISMATCH', status: 409 });
    assert.throws(() => store.releaseHold('P1', 'P1-H99', { requestId: 'rel-x', caseNo: 'CASE-1' }),
      { code: 'HOLD_UNKNOWN', status: 404 });
    // 并发解除：两个不同请求号同时解除同一保全 → 一个成功，一个 HOLD_ALREADY_RELEASED
    const ok = store.releaseHold('P1', 'P1-H1', { requestId: 'rel-1', caseNo: 'CASE-1' });
    assert.equal(ok.result.status, 'RELEASED');
    assert.throws(() => store.releaseHold('P1', 'P1-H1', { requestId: 'rel-2', caseNo: 'CASE-1' }),
      { code: 'HOLD_ALREADY_RELEASED', status: 409 });
    // 同一请求号重放 → 原结果（幂等，不报错）
    const replay = store.releaseHold('P1', 'P1-H1', { requestId: 'rel-1', caseNo: 'CASE-1' });
    assert.equal(replay.replay, true);
    assert.deepEqual(replay.result, ok.result);
    // 已解除的保全仍有效保全数为 0
    assert.equal(store.activeHolds('P1').length, 0);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('销毁覆盖四类对象：业务索引/链文件/冲突材料/凭据旁车（+残尾/被拒留底）', () => {
  const dir = tmp();
  try {
    makePkg(dir, 'P1');
    // 残尾旁证
    writeFileSync(join(dir, 'packages', 'P1', 'torn-ledger-2026-10-01-x.log'), '{"seq":9,');
    const { store } = makeStore(dir, T0);
    store.setRetention('P1', { requestId: 'r1', retainUntil: new Date(T0 - 1000).toISOString(), setBy: 'ops' });
    const pkgDir = join(dir, 'packages', 'P1');
    assert.ok(existsSync(join(pkgDir, 'ledger.jsonl')));
    assert.ok(existsSync(join(pkgDir, 'quarantine.jsonl')));
    assert.ok(existsSync(join(pkgDir, 'gateway-upload.keys.json')));
    const out = store.executeDestruction('P1', { requestedBy: 'ops' });
    const { receipt } = out;
    // 回执覆盖分类
    const cats = receipt.files.map((f) => f.category);
    assert.ok(cats.includes('chain'), '链文件');
    assert.ok(cats.includes('conflict'), '冲突材料');
    assert.ok(cats.includes('credential'), '凭据旁车');
    assert.ok(cats.includes('torn-tail'), '残尾旁证');
    assert.equal(receipt.removed.chains, 2); // ledger + audit
    assert.ok(receipt.removed.conflictMaterials >= 2); // quarantine + rejected 留底
    assert.equal(receipt.removed.credentialSidecars, 1);
    assert.equal(receipt.removed.businessIndexes.inMemoryProjections, 'evicted-on-commit');
    // 物理删除
    assert.ok(!existsSync(pkgDir), '包目录已移除');
    assert.ok(!existsSync(join(dir, 'rejected', '2026-10-01T09-00-00-000Z-P1.json')), '被拒留底已删');
    // 每个文件都有内容哈希
    assert.ok(receipt.files.every((f) => /^[0-9a-f]{64}$/.test(f.sha256) && f.bytes > 0));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('回执：签名可验、哈希自洽、不含原始证据', () => {
  const dir = tmp();
  try {
    makePkg(dir, 'P1');
    const { store } = makeStore(dir, T0);
    store.setRetention('P1', { requestId: 'r1', retainUntil: new Date(T0 - 1000).toISOString(), setBy: 'ops' });
    const { receipt } = store.executeDestruction('P1', { requestedBy: 'ops' });
    assert.equal(receipt.schema, RECEIPT_SCHEMA);
    const v = store.verifyReceipt(receipt.receiptId);
    assert.equal(v.ok, true);
    assert.ok(Object.values(v.checks).every(Boolean));
    // 独立复算：receiptHash = sha256(canonicalJSON(去签名体))
    const { signature, keyId, receiptHash, ...body } = receipt;
    assert.equal(sha256Hex(canonicalJSON(body)), receipt.receiptHash);
    // 不含原始证据：设备号/回执内容不出现在回执里
    const text = JSON.stringify(receipt);
    assert.ok(!text.includes('D-1'), '不含设备号');
    assert.ok(!text.includes('EXECUTED'), '不含回执结果');
    assert.ok(!text.includes('gw-secret-material'), '不含凭据原文');
    assert.ok(!('records' in receipt) && !('entries' in receipt));
    // 但含可核对元数据
    assert.ok(receipt.evidenceSummary.reportDigest);
    assert.ok(receipt.evidenceSummary.chainTips.ledger.hash);
    // 篡改签名 → 验签失败
    const bad = store.signer.verify(receipt.receiptHash, '0'.repeat(128));
    assert.equal(bad, false);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('重复销毁：返回同一回执，链上只有一条 COMMITTED', () => {
  const dir = tmp();
  try {
    makePkg(dir, 'P1');
    const { store } = makeStore(dir, T0);
    store.setRetention('P1', { requestId: 'r1', retainUntil: new Date(T0 - 1000).toISOString(), setBy: 'ops' });
    const o1 = store.executeDestruction('P1', { requestedBy: 'ops' });
    const o2 = store.executeDestruction('P1', { requestedBy: 'ops' });
    assert.equal(o2.duplicate, true);
    assert.equal(o2.receipt.receiptId, o1.receipt.receiptId);
    const commits = store.chain.records.filter((r) => r.kind === 'DESTRUCTION_COMMITTED' && r.packageId === 'P1');
    assert.equal(commits.length, 1);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('崩溃恢复：仅 PREPARED（提交前断电）→ 恢复到唯一结果，读状态可区分', () => {
  const dir = tmp();
  try {
    makePkg(dir, 'P1');
    const { store } = makeStore(dir, T0);
    store.setRetention('P1', { requestId: 'r1', retainUntil: new Date(T0 - 1000).toISOString(), setBy: 'ops' });
    // 只准备不提交（模拟提交前断电）
    const prepared = store.prepareDestruction('P1');
    assert.equal(store.destructionStatus('P1').status, 'PREPARED'); // 正在提交
    assert.ok(existsSync(join(dir, 'packages', 'P1', 'ledger.jsonl')), '提交前文件完整');
    assert.equal(store.isDestroyed('P1'), false, '提交前读=完整旧状态');
    // 模拟重启：新 store 从链重放 + recover
    const { store: s2 } = makeStore(dir, T0 + 1000);
    const resumed = s2.recover();
    assert.deepEqual(resumed, [{ packageId: 'P1', from: 'PREPARED', to: 'COMPLETED' }]);
    assert.equal(s2.destructionStatus('P1').status, 'COMPLETED');
    assert.ok(!existsSync(join(dir, 'packages', 'P1')));
    // 回执唯一：receiptId 由计划派生
    const receipt = s2.receiptForPackage('P1');
    assert.ok(receipt.receiptId.startsWith('dst_'));
    const commits = s2.chain.records.filter((r) => r.kind === 'DESTRUCTION_COMMITTED');
    assert.equal(commits.length, 1);
    // 再次 recover 幂等
    assert.deepEqual(s2.recover(), []);
    void prepared;
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('崩溃恢复：COMMITTED 未 COMPLETED（删除中断）→ 继续删除，无第二份回执', () => {
  const dir = tmp();
  try {
    makePkg(dir, 'P1');
    const { store } = makeStore(dir, T0);
    store.setRetention('P1', { requestId: 'r1', retainUntil: new Date(T0 - 1000).toISOString(), setBy: 'ops' });
    store.prepareDestruction('P1');
    const receipt = store.commitDestruction('P1', { requestedBy: 'ops' });
    // 已提交：读=已销毁（即使文件还在）
    assert.equal(store.isDestroyed('P1'), true);
    assert.equal(store.destructionStatus('P1').status, 'COMMITTED');
    // 模拟重启
    const { store: s2 } = makeStore(dir, T0 + 1000);
    assert.equal(s2.destructionStatus('P1').status, 'COMMITTED');
    const resumed = s2.recover();
    assert.deepEqual(resumed, [{ packageId: 'P1', from: 'COMMITTED', to: 'COMPLETED' }]);
    assert.ok(!existsSync(join(dir, 'packages', 'P1')));
    // 回执与崩溃前完全一致（唯一结果）
    const receipt2 = s2.receiptForPackage('P1');
    assert.equal(receipt2.receiptId, receipt.receiptId);
    assert.equal(receipt2.receiptHash, receipt.receiptHash);
    assert.equal(s2.chain.records.filter((r) => r.kind === 'DESTRUCTION_COMMITTED').length, 1);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('存储删除失败：记录 FAILED 可核对，重试后完成且回执不变', () => {
  const dir = tmp();
  try {
    makePkg(dir, 'P1');
    const { store } = makeStore(dir, T0);
    store.setRetention('P1', { requestId: 'r1', retainUntil: new Date(T0 - 1000).toISOString(), setBy: 'ops' });
    // 注入故障删除器：第一个文件删除失败
    let failed = false;
    const flaky = {
      unlink(abs) {
        if (!failed) { failed = true; throw Object.assign(new Error('EPERM: 模拟存储故障'), { code: 'EPERM' }); }
        try { unlinkSync(abs); } catch (e) { if (e.code !== 'ENOENT') throw e; }
      },
      rmdir(abs) {
        try { rmdirSync(abs); } catch (e) { if (e.code !== 'ENOENT') throw e; }
      },
    };
    let receiptId;
    try {
      store.executeDestruction('P1', { requestedBy: 'ops', deleter: flaky });
      assert.fail('应抛 STORAGE_DELETE_FAILED');
    } catch (e) {
      assert.equal(e.code, 'STORAGE_DELETE_FAILED');
      assert.equal(e.status, 500);
      assert.ok(e.details.remainingFiles.length >= 1);
      receiptId = e.details.receiptId;
    }
    // 状态可核对：FAILED + 剩余文件
    const st = store.destructionStatus('P1');
    assert.equal(st.status, 'FAILED');
    assert.ok(st.remainingFiles.length >= 1);
    assert.equal(store.isDestroyed('P1'), true, '已提交：读=已销毁');
    // 链上有 FAILED 记录
    assert.ok(store.chain.records.some((r) => r.kind === 'DESTRUCTION_FAILED'));
    // 重试（正常删除器）→ 完成，回执不变
    const retried = store.retryDestruction('P1');
    assert.equal(retried.status, 'COMPLETED');
    assert.equal(retried.receipt.receiptId, receiptId);
    assert.equal(store.chain.records.filter((r) => r.kind === 'DESTRUCTION_COMMITTED').length, 1);
    assert.ok(!existsSync(join(dir, 'packages', 'P1')));
    // 再重试 → 幂等
    const again = store.retryDestruction('P1');
    assert.equal(again.duplicate, true);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('重启重放：期限/保全/回执投影一致', () => {
  const dir = tmp();
  try {
    makePkg(dir, 'P1');
    makePkg(dir, 'P2');
    const { store } = makeStore(dir, T0);
    store.setRetention('P1', { requestId: 'r1', retainUntil: new Date(T0 + DAY).toISOString(), setBy: 'ops' });
    store.createHold('P1', { requestId: 'h1', caseNo: 'CASE-1', reason: 'r', auditor: 'aud' });
    store.setRetention('P2', { requestId: 'r2', retainUntil: new Date(T0 - 1000).toISOString(), setBy: 'ops' });
    const { receipt } = store.executeDestruction('P2', { requestedBy: 'ops' });
    // 新 store 重放
    const { store: s2 } = makeStore(dir, T0);
    assert.equal(s2.retention.get('P1').retainUntil, new Date(T0 + DAY).toISOString());
    assert.equal(s2.activeHolds('P1').length, 1);
    assert.equal(s2.activeHolds('P1')[0].caseNo, 'CASE-1');
    assert.equal(s2.receiptForPackage('P2').receiptId, receipt.receiptId);
    assert.equal(s2.destructionStatus('P2').status, 'COMPLETED');
    // 幂等台账重启后仍在：同 requestId 重放返原结果
    const replay = s2.createHold('P1', { requestId: 'h1', caseNo: 'CASE-1', reason: 'r', auditor: 'aud' });
    assert.equal(replay.replay, true);
    assert.equal(replay.result.holdId, 'P1-H1');
    // 销毁后命令 → 410
    assert.throws(() => s2.setRetention('P2', { requestId: 'r9', retainUntil: '2030-01-01T00:00:00Z', setBy: 'ops' }),
      { code: 'PACKAGE_DESTROYED', status: 410 });
    assert.throws(() => s2.createHold('P2', { requestId: 'h9', caseNo: 'C', reason: 'r', auditor: 'a' }),
      { code: 'PACKAGE_DESTROYED', status: 410 });
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('到期任务：只销毁合格包，跳过原因可核对；保全解除后下一轮才销毁', () => {
  const dir = tmp();
  try {
    for (const id of ['P-EXP', 'P-FUTURE', 'P-HELD', 'P-NORET']) makePkg(dir, id, { withConflict: false, withSidecar: false, withRejected: false });
    const { store } = makeStore(dir, T0);
    store.setRetention('P-EXP', { requestId: 'r1', retainUntil: new Date(T0 - 1000).toISOString(), setBy: 'ops' });
    store.setRetention('P-FUTURE', { requestId: 'r2', retainUntil: new Date(T0 + DAY).toISOString(), setBy: 'ops' });
    store.setRetention('P-HELD', { requestId: 'r3', retainUntil: new Date(T0 - 1000).toISOString(), setBy: 'ops' });
    // P-HELD 的保全须在期限内发起：先把时钟拨回
    const { store: s2, setClock } = makeStore(dir, T0 - 2 * DAY);
    s2.createHold('P-HELD', { requestId: 'h1', caseNo: 'CASE-9', reason: 'r', auditor: 'aud' });
    setClock(T0); // 回到现在（期限已过）
    const out = s2.sweep();
    assert.deepEqual(out.destroyed.map((x) => x.packageId), ['P-EXP']);
    const skipBy = Object.fromEntries(out.skipped.map((s) => [s.packageId, s.reason]));
    assert.equal(skipBy['P-FUTURE'], 'RETENTION_NOT_EXPIRED');
    assert.equal(skipBy['P-HELD'], 'HOLDS_ACTIVE');
    assert.equal(skipBy['P-NORET'], 'RETENTION_NOT_SET');
    assert.ok(existsSync(join(dir, 'packages', 'P-HELD')), '保全中的包未被误删');
    assert.ok(!existsSync(join(dir, 'packages', 'P-EXP')));
    // 解除保全后下一轮才销毁
    s2.releaseHold('P-HELD', 'P-HELD-H1', { requestId: 'rel-1', caseNo: 'CASE-9' });
    const out2 = s2.sweep();
    assert.deepEqual(out2.destroyed.map((x) => x.packageId), ['P-HELD']);
    assert.ok(!existsSync(join(dir, 'packages', 'P-HELD')));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('待销毁列表：合格/阻塞/在途分类正确', () => {
  const dir = tmp();
  try {
    makePkg(dir, 'P-OK', { withConflict: false, withSidecar: false, withRejected: false });
    makePkg(dir, 'P-HELD', { withConflict: false, withSidecar: false, withRejected: false });
    const { store, setClock } = makeStore(dir, T0 - 2 * DAY);
    store.setRetention('P-OK', { requestId: 'r1', retainUntil: new Date(T0 - 1000).toISOString(), setBy: 'ops' });
    store.setRetention('P-HELD', { requestId: 'r2', retainUntil: new Date(T0 - 1000).toISOString(), setBy: 'ops' });
    store.createHold('P-HELD', { requestId: 'h1', caseNo: 'CASE-1', reason: 'r', auditor: 'aud' });
    setClock(T0);
    const p = store.pendingDestruction();
    assert.deepEqual(p.eligible.map((x) => x.packageId), ['P-OK']);
    assert.deepEqual(p.blocked.map((x) => x.packageId), ['P-HELD']);
    assert.equal(p.blocked[0].holds[0].caseNo, 'CASE-1');
    store.executeDestruction('P-OK', { requestedBy: 'ops' });
    const p2 = store.pendingDestruction();
    assert.equal(p2.eligible.length, 0);
    assert.ok(!p2.inFlight.some((x) => x.packageId === 'P-OK'), '已完成不在在途列表');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('生命周期链篡改 → 命令抛 CHAIN_QUARANTINED（只读隔离）', () => {
  const dir = tmp();
  try {
    makePkg(dir, 'P1');
    const { store } = makeStore(dir, T0);
    store.setRetention('P1', { requestId: 'r1', retainUntil: '2026-10-10T00:00:00Z', setBy: 'ops' });
    const file = join(dir, 'lifecycle.jsonl');
    const tampered = readFileSync(file, 'utf8').replace('2026-10-10', '2027-10-10');
    writeFileSync(file, tampered);
    const { store: s2 } = makeStore(dir, T0);
    assert.equal(s2.writable, false);
    assert.throws(() => s2.createHold('P1', { requestId: 'h1', caseNo: 'C', reason: 'r', auditor: 'a' }),
      { code: 'CHAIN_QUARANTINED' });
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('回执验签：链锚定与结构检查；未知回执返回 null', () => {
  const dir = tmp();
  try {
    makePkg(dir, 'P1');
    const { store } = makeStore(dir, T0);
    store.setRetention('P1', { requestId: 'r1', retainUntil: new Date(T0 - 1000).toISOString(), setBy: 'ops' });
    const { receipt } = store.executeDestruction('P1', { requestedBy: 'ops' });
    const v = store.verifyReceipt(receipt.receiptId);
    assert.equal(v.ok, true);
    assert.equal(v.checks.chainAnchored, true);
    assert.equal(v.checks.noRawEvidence, true);
    assert.equal(store.verifyReceipt('dst_nonexistent'), null);
    // 重启后验签仍然有效（签名密钥 sidecar 持久）
    const { store: s2 } = makeStore(dir, T0);
    const v2 = s2.verifyReceipt(receipt.receiptId);
    assert.equal(v2.ok, true);
    assert.equal(v2.publicKeyPem, v.publicKeyPem);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('销毁后 rejected 目录中其他包的留底不受影响', () => {
  const dir = tmp();
  try {
    makePkg(dir, 'P1');
    makePkg(dir, 'P2');
    const rejDir = join(dir, 'rejected');
    writeFileSync(join(rejDir, 'other-pkg.json'),
      JSON.stringify({ at: '2026-10-01T09:00:00Z', targetPackageId: 'P2', code: 'X', message: 'y', envelope: null }) + '\n');
    const { store } = makeStore(dir, T0);
    store.setRetention('P1', { requestId: 'r1', retainUntil: new Date(T0 - 1000).toISOString(), setBy: 'ops' });
    store.executeDestruction('P1', { requestedBy: 'ops' });
    assert.ok(existsSync(join(rejDir, 'other-pkg.json')), '其他包留底保留');
    assert.ok(existsSync(join(dir, 'packages', 'P2')), '其他包目录保留');
    // 销毁回执列表只有 P1
    assert.deepEqual(store.listReceipts().map((r) => r.packageId), ['P1']);
    // 包目录列表（供 listPackages）不再含 P1
    assert.ok(!readdirSync(join(dir, 'packages')).includes('P1'));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
