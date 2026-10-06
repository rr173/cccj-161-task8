// 灵活负荷资格闸领域契约（node:test）：
// 逐设备准入（互斥标签/暂停/跨区域/最短提前期/未知设备/多原因并列）· 申请号幂等与正文冲突 ·
// 规则定时生效/撤销/回滚 · 版本绑定不被追改 · 重叠规则/乐观锁冲突/过期规则/撤销后重试 ·
// 空批次 · 批次冻结与脱敏清单 · 独立验签 · 重启重放版本链与裁决顺序不变。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { EligibilityRegistry, GATE_NOW, seedGate } from '../eligibility/registry.js';
import { EventStore } from '../src/store.js';
import { PackageKeyStore } from '../src/package-crypto.js';
import { sha256Hex, canonicalJSON } from '../src/util.js';

const H = 60 * 60000;
const D = 24 * H;

function mem() {
  return EligibilityRegistry.freshMemory(GATE_NOW);
}
function event(region = 'RG-EAST', startInMinutes = 60, id = 'EV-1') {
  return { eventId: id, region, startMs: GATE_NOW + startInMinutes * 60000 };
}
function apply(g, rec) {
  g.apply(rec);
  return rec;
}
function expectCode(fn, code) {
  try { fn(); } catch (e) {
    assert.equal(e.code, code, `期望 ${code}，实际 ${e.code}：${e.message}`);
    return e;
  }
  assert.fail(`应当抛出 ${code}`);
}
const reasonsOf = (batch, id) => batch.items.find((i) => i.deviceId === id).reasons;
const decisionOf = (batch, id) => batch.items.find((i) => i.deviceId === id).decision;

test('逐设备裁决：未知设备独立拒绝，不影响其他设备', () => {
  const g = mem();
  const { batch } = g.decideBatch({
    requestId: 'R1', aggregatorId: 'AGG-A', event: event(),
    deviceIds: ['GFD-1', 'NOPE'],
  }, GATE_NOW);
  assert.deepEqual(reasonsOf(batch, 'NOPE'), ['UNKNOWN_DEVICE']
  );
  assert.equal(batch.items[0].rule.ruleId, 'RULE-EAST-DEFAULT');
});

test('互斥标签命中：携带 CRITICAL 的 GFD-2 被拒 MUTEX_TAG', () => {
  const g = mem();
  const { batch } = g.decideBatch({
    requestId: 'R2', aggregatorId: 'AGG-A', event: event('RG-EAST', 120),
    deviceIds: ['GFD-1', 'GFD-2'],
  }, GATE_NOW);
  assert.equal(decisionOf(batch, 'GFD-1'), 'APPROVED');
  assert.deepEqual(reasonsOf(batch, 'GFD-2'), ['MUTEX_TAG']);
});

test('暂停设备：DEVICE_SUSPENDED；恢复后可准入', () => {
  const g = mem();
  const r = g.decideBatch({
    requestId: 'R3', aggregatorId: 'AGG-A', event: event('RG-EAST', 120),
    deviceIds: ['GFD-4'],
  }, GATE_NOW);
  assert.deepEqual(reasonsOf(r.batch, 'GFD-4'), ['DEVICE_SUSPENDED']);
  g.suspendDevice({ deviceId: 'GFD-4', suspended: false }, GATE_NOW);
  const r2 = g.decideBatch({
    requestId: 'R3b', aggregatorId: 'AGG-A', event: event('RG-EAST', 120),
    deviceIds: ['GFD-4'],
  }, GATE_NOW);
  assert.equal(decisionOf(r2.batch, 'GFD-4'), 'APPROVED');
});

test('跨区域：西区设备参加东区事件被拒 CROSS_REGION（同时给本地区规则版本）', () => {
  const g = mem();
  const { batch } = g.decideBatch({
    requestId: 'R4', aggregatorId: 'AGG-A', event: event('RG-EAST', 120),
    deviceIds: ['GFD-3'],
  }, GATE_NOW);
  assert.deepEqual(reasonsOf(batch, 'GFD-3'), ['CROSS_REGION']);
  assert.equal(batch.items[0].rule.ruleId, 'RULE-WEST-DEFAULT');
});

test('最短提前期不满足：LEAD_TIME；边界（恰好等于提前期）通过', () => {
  const g = mem();
  const tight = g.decideBatch({
    requestId: 'R5a', aggregatorId: 'AGG-A', event: event('RG-EAST', 29),
    deviceIds: ['GFD-1'],
  }, GATE_NOW);
  assert.deepEqual(reasonsOf(tight.batch, 'GFD-1'), ['LEAD_TIME']);
  const exact = g.decideBatch({
    requestId: 'R5b', aggregatorId: 'AGG-A', event: event('RG-EAST', 30),
    deviceIds: ['GFD-1'],
  }, GATE_NOW);
  assert.equal(decisionOf(exact.batch, 'GFD-1'), 'APPROVED');
});

test('多原因并列：暂停 + 互斥 + 提前期全部列出', () => {
  const g = mem();
  // 让 GFD-4（HVAC, suspended）命中互斥：发布其设备专属规则 denyTags HVAC
  g.publishRule({
    ruleId: 'R-DEV4', scope: { deviceId: 'GFD-4', region: 'RG-EAST' },
    body: { denyTags: ['HVAC'], minLeadMinutes: 60 },
    validFrom: '2026-10-01', validUntil: '2026-10-31',
  }, GATE_NOW);
  const { batch } = g.decideBatch({
    requestId: 'R6', aggregatorId: 'AGG-A', event: event('RG-EAST', 10),
    deviceIds: ['GFD-4'],
  }, GATE_NOW);
  assert.deepEqual(reasonsOf(batch, 'GFD-4'), ['DEVICE_SUSPENDED', 'MUTEX_TAG', 'LEAD_TIME']);
});

test('设备专属规则优先于地区默认', () => {
  const g = mem();
  g.publishRule({
    ruleId: 'R-DEV1-RELAX', scope: { deviceId: 'GFD-1', region: 'RG-EAST' },
    body: { denyTags: [], minLeadMinutes: 0 },
    validFrom: '2026-10-01', validUntil: '2026-10-31',
  }, GATE_NOW);
  const { batch } = g.decideBatch({
    requestId: 'R7', aggregatorId: 'AGG-A', event: event('RG-EAST', 0),
    deviceIds: ['GFD-1'],
  }, GATE_NOW);
  assert.equal(decisionOf(batch, 'GFD-1'), 'APPROVED');
  assert.equal(batch.items[0].rule.ruleId, 'R-DEV1-RELAX');
});

test('申请号幂等：同号同文返回原裁决；同号异文 409 REQUEST_ID_CONFLICT', () => {
  const g = mem();
  const cmd = { requestId: 'IDEM', aggregatorId: 'AGG-A', event: event('RG-EAST', 120), deviceIds: ['GFD-1'] };
  const first = g.decideBatch(cmd, GATE_NOW);
  assert.equal(first.idempotent, false);
  const again = g.decideBatch(cmd, GATE_NOW);
  assert.equal(again.idempotent, true);
  assert.equal(again.batch.batchId, first.batch.batchId);
  assert.equal(again.batch.batchDigest, first.batch.batchDigest);
  expectCode(() => g.decideBatch({ ...cmd, deviceIds: ['GFD-1', 'GFD-2'] }, GATE_NOW), 'REQUEST_ID_CONFLICT');
});

test('空批次：允许提交、可签名、可冻结与下载，计数为 0', () => {
  const g = mem();
  const { batch } = g.decideBatch({
    requestId: 'EMPTY', aggregatorId: 'AGG-A', event: event(), deviceIds: [],
  }, GATE_NOW);
  assert.deepEqual(batch.counts, { total: 0, approved: 0, rejected: 0 });
  assert.ok(batch.batchDigest);
  assert.equal(g.verifyBatch(batch.batchId).valid, true);
  g.freezeBatch({ batchId: batch.batchId }, GATE_NOW);
  const csv = g.redactedCsv(batch.batchId);
  assert.ok(csv.startsWith('order,deviceMasked'));
});

test('批次冻结：未冻结不能下载脱敏清单；冻结幂等；裁决内容不被冻结改写', () => {
  const g = mem();
  const { batch } = g.decideBatch({
    requestId: 'FRZ', aggregatorId: 'AGG-A', event: event('RG-EAST', 120), deviceIds: ['GFD-1'],
  }, GATE_NOW);
  expectCode(() => g.redactedCsv(batch.batchId), 'BATCH_NOT_FROZEN');
  const f1 = g.freezeBatch({ batchId: batch.batchId }, GATE_NOW);
  assert.equal(f1.idempotent, false);
  const f2 = g.freezeBatch({ batchId: batch.batchId }, GATE_NOW);
  assert.equal(f2.idempotent, true);
  const csv = g.redactedCsv(batch.batchId);
  assert.match(csv, /GFD-\*\*\*\*-[0-9a-f]{8}/);
  assert.doesNotMatch(csv, /GFD-1/);
});

test('版本绑定：裁决后发布新版本/撤销/回滚，历史批次仍绑旧版本且验签通过', () => {
  const g = mem();
  const { batch } = g.decideBatch({
    requestId: 'BIND', aggregatorId: 'AGG-A', event: event('RG-EAST', 120), deviceIds: ['GFD-1', 'GFD-2'],
  }, GATE_NOW);
  const tip = batch.ruleChainTip.version;
  const gfd2RuleVersion = batch.items[1].rule.version;

  // 后续把 GFD-2 互斥标签放宽（新设备专属规则）并撤销地区默认规则
  g.publishRule({
    ruleId: 'R-DEV2', scope: { deviceId: 'GFD-2', region: 'RG-EAST' },
    body: { denyTags: [], minLeadMinutes: 0 },
    validFrom: '2026-10-01', validUntil: '2026-10-31',
  }, GATE_NOW + H);
  g.revokeRule({ ruleId: 'RULE-EAST-DEFAULT' }, GATE_NOW + 2 * H);
  g.rollbackRule({ fromVersion: gfd2RuleVersion }, GATE_NOW + 3 * H);

  const rebound = g.batchView(batch.batchId);
  assert.equal(rebound.ruleChainTip.version, tip); // 历史批次版本钉死
  assert.deepEqual(reasonsOf(rebound, 'GFD-2'), ['MUTEX_TAG']); // 裁决不被追改
  const v = g.verifyBatch(batch.batchId);
  assert.equal(v.valid, true);
  assert.equal(v.tipIntact, true);
  assert.ok(v.ruleChecks.every((c) => c.intact));
});

test('规则定时生效：未来 validFrom 之前 NO_APPLICABLE_RULE，到期后适用', () => {
  const g = mem();
  // 撤销现有地区默认（今日生效），再发布 10-20 起的新规则
  g.revokeRule({ ruleId: 'RULE-WEST-DEFAULT' }, GATE_NOW);
  g.publishRule({
    ruleId: 'RULE-WEST-V2', scope: { region: 'RG-WEST' },
    body: { denyTags: [], minLeadMinutes: 5 },
    validFrom: '2026-10-20', validUntil: '2026-12-31',
  }, GATE_NOW);
  // 当前 10-06：西区无生效规则
  const now = g.decideBatch({
    requestId: 'FUT1', aggregatorId: 'AGG-A', event: event('RG-WEST', 10), deviceIds: ['GFD-3'],
  }, GATE_NOW);
  assert.deepEqual(reasonsOf(now.batch, 'GFD-3'), ['NO_APPLICABLE_RULE']);
  // 推进到 10-20：规则生效
  const at = GATE_NOW + 14 * D;
  const later = g.decideBatch({
    requestId: 'FUT2', aggregatorId: 'AGG-A', event: { eventId: 'EV-X', region: 'RG-WEST', startMs: at + 10 * 60000 },
    deviceIds: ['GFD-3'],
  }, at);
  assert.equal(decisionOf(later.batch, 'GFD-3'), 'APPROVED');
});

test('过期规则：validUntil 之后 NO_APPLICABLE_RULE', () => {
  const g = mem();
  g.revokeRule({ ruleId: 'RULE-WEST-DEFAULT' }, GATE_NOW);
  const at = GATE_NOW + 60 * D; // 2026-12-05，种子规则 10-31 已过期
  const { batch } = g.decideBatch({
    requestId: 'EXP', aggregatorId: 'AGG-A',
    event: { eventId: 'EV-X', region: 'RG-WEST', startMs: at + 2 * H },
    deviceIds: ['GFD-3'],
  }, at);
  assert.deepEqual(reasonsOf(batch, 'GFD-3'), ['NO_APPLICABLE_RULE']);
});

test('重叠规则：同作用域日期重叠 409 RULE_OVERLAP；日期相邻允许', () => {
  const g = mem();
  expectCode(() => g.publishRule({
    ruleId: 'R-DUP', scope: { region: 'RG-WEST' },
    body: { denyTags: [], minLeadMinutes: 1 },
    validFrom: '2026-10-15', validUntil: '2026-11-15',
  }, GATE_NOW), 'RULE_OVERLAP');
  // 与种子规则 10-01..10-31 相邻（11-01 起）允许
  const ok = g.publishRule({
    ruleId: 'R-ADJ', scope: { region: 'RG-WEST' },
    body: { denyTags: [], minLeadMinutes: 1 },
    validFrom: '2026-11-01', validUntil: '2026-11-30',
  }, GATE_NOW);
  assert.equal(ok.rule.head.version, 3);
});

test('版本冲突：expectedVersion 过期 -> 409 RULE_VERSION_CONFLICT', () => {
  const g = mem();
  expectCode(() => g.publishRule({
    ruleId: 'R-OPT', scope: { region: 'RG-WEST' },
    body: { denyTags: [], minLeadMinutes: 1 },
    validFrom: '2026-11-01', validUntil: '2026-11-30', expectedVersion: 1,
  }, GATE_NOW), 'RULE_VERSION_CONFLICT');
});

test('撤销与回滚：撤销后规则不可直接改；回滚恢复；撤销后重试申请的语义', () => {
  const g = mem();
  g.revokeRule({ ruleId: 'RULE-WEST-DEFAULT' }, GATE_NOW);
  // 已撤销规则直接发布新版本被拒
  expectCode(() => g.publishRule({
    ruleId: 'RULE-WEST-DEFAULT', scope: { region: 'RG-WEST' },
    body: { denyTags: ['X'], minLeadMinutes: 9 },
    validFrom: '2026-10-06', validUntil: '2026-12-31',
  }, GATE_NOW), 'RULE_REVOKED');
  // 撤销后重试申请：无规则 -> NO_APPLICABLE_RULE
  const denied = g.decideBatch({
    requestId: 'RETRY1', aggregatorId: 'AGG-A', event: event('RG-WEST', 120),
    deviceIds: ['GFD-3'],
  }, GATE_NOW);
  assert.deepEqual(reasonsOf(denied.batch, 'GFD-3'), ['NO_APPLICABLE_RULE']);
  // 回滚到 v2（种子西区规则）恢复准入
  const rb = g.rollbackRule({ fromVersion: 2 }, GATE_NOW);
  assert.equal(rb.rule.head.ruleVersion, 2);
  assert.equal(rb.rule.head.restoredFromVersion, 2);
  const allowed = g.decideBatch({
    requestId: 'RETRY2', aggregatorId: 'AGG-A', event: event('RG-WEST', 120),
    deviceIds: ['GFD-3'],
  }, GATE_NOW);
  assert.equal(decisionOf(allowed.batch, 'GFD-3'), 'APPROVED');
});

test('定时撤销：未来生效日之前规则仍可裁决，到期当天退出', () => {
  const g = mem();
  g.revokeRule({ ruleId: 'RULE-WEST-DEFAULT', effectiveFrom: '2026-10-10' }, GATE_NOW);
  const before = g.decideBatch({
    requestId: 'SCHR1', aggregatorId: 'AGG-A', event: event('RG-WEST', 120),
    deviceIds: ['GFD-3'],
  }, GATE_NOW); // 10-06
  assert.equal(decisionOf(before.batch, 'GFD-3'), 'APPROVED');
  const at = GATE_NOW + 4 * D; // 10-10
  const after = g.decideBatch({
    requestId: 'SCHR2', aggregatorId: 'AGG-A',
    event: { eventId: 'EV-X', region: 'RG-WEST', startMs: at + 2 * H },
    deviceIds: ['GFD-3'],
  }, at);
  assert.deepEqual(reasonsOf(after.batch, 'GFD-3'), ['NO_APPLICABLE_RULE']);
});

test('规则内容哈希稳定性：同内容跨进程可复算', () => {
  const a = mem();
  const b = mem();
  assert.equal(a.stateView().rules[0].contentHash, b.stateView().rules[0].contentHash);
});

test('独立验签：篡改裁决项后摘要不符、签名失效', () => {
  const g = mem();
  const { batch } = g.decideBatch({
    requestId: 'TAMPER', aggregatorId: 'AGG-A', event: event('RG-EAST', 120),
    deviceIds: ['GFD-1', 'GFD-2'],
  }, GATE_NOW);
  // 直接篡改内存投影中的裁决（模拟对历史记录的篡改）
  const proj = g.s.batches.get(batch.batchId);
  proj.items[1].decision = 'APPROVED';
  proj.items[1].reasons = [];
  const v = g.verifyBatch(batch.batchId);
  assert.equal(v.digestMatches, false);
  assert.equal(v.signatureValid, false);
  assert.equal(v.valid, false);
});

test('重启重放：裁决顺序（recordSeq）、版本链、幂等台账、逐字节摘要全部不变', () => {
  const store = new EventStore(null);
  seedGate(store, GATE_NOW);
  const keys = new PackageKeyStore(null);
  const g1 = new EligibilityRegistry(store, { keys });
  const b1 = g1.decideBatch({
    requestId: 'PERSIST-1', aggregatorId: 'AGG-A', event: event('RG-EAST', 120),
    deviceIds: ['GFD-1'],
  }, GATE_NOW).batch;
  g1.publishRule({
    ruleId: 'R-PERSIST', scope: { region: 'RG-WEST' },
    body: { denyTags: [], minLeadMinutes: 1 },
    validFrom: '2026-11-01', validUntil: '2026-11-30',
  }, GATE_NOW + H);
  const b2 = g1.decideBatch({
    requestId: 'PERSIST-2', aggregatorId: 'AGG-A', event: event('RG-EAST', 10),
    deviceIds: ['GFD-1'],
  }, GATE_NOW + 2 * H).batch;
  const tipBefore = g1.chainTip();

  // 全新进程从同一日志重放（复用同一份 sidecar 密钥）
  const g2 = new EligibilityRegistry(store, { keys, boot: false });
  g2.replay();
  assert.deepEqual(g2.chainTip(), tipBefore);
  const r1 = g2.batchView(b1.batchId);
  const r2 = g2.batchView(b2.batchId);
  assert.ok(r1.recordSeq < r2.recordSeq); // 裁决顺序不变
  assert.equal(r1.batchDigest, b1.batchDigest);
  assert.equal(r2.batchDigest, b2.batchDigest);
  assert.equal(g2.verifyBatch(b1.batchId).valid, true);
  assert.equal(g2.verifyBatch(b2.batchId).valid, true);
  // 幂等台账重建：重放后同号同文仍返回原批次
  const replay = g2.decideBatch({
    requestId: 'PERSIST-1', aggregatorId: 'AGG-A', event: event('RG-EAST', 120),
    deviceIds: ['GFD-1'],
  }, GATE_NOW + 2 * H);
  assert.equal(replay.idempotent, true);
  assert.equal(replay.batch.batchId, b1.batchId);
});

test('并发按序落账：多条申请的裁决顺序与调用顺序一致（同步串行）', () => {
  const g = mem();
  const ids = [];
  for (let i = 0; i < 5; i++) {
    ids.push(g.decideBatch({
      requestId: `SEQ-${i}`, aggregatorId: 'AGG-A', event: event('RG-EAST', 120, `EV-${i}`),
      deviceIds: ['GFD-1'],
    }, GATE_NOW + i).batch.batchId);
  }
  const list = g.listBatches().filter((b) => b.requestId.startsWith('SEQ-'));
  assert.deepEqual(list.map((b) => b.batchId), ids);
  const seqs = list.map((b) => b.recordSeq);
  assert.deepEqual(seqs, [...seqs].sort((a, b) => a - b));
});

test('规则试算：草案规则不落盘即可改变裁决', () => {
  const g = mem();
  const before = g.trial({
    event: event('RG-EAST', 120), deviceIds: ['GFD-2'],
  });
  assert.equal(before.items[0].decision, 'REJECTED');
  const after = g.trial({
    event: event('RG-EAST', 120), deviceIds: ['GFD-2'],
    draftRule: {
      scope: { region: 'RG-EAST' },
      body: { denyTags: [], minLeadMinutes: 0 },
      validFrom: '2026-10-01', validUntil: '2026-10-31',
    },
  });
  assert.equal(after.items[0].decision, 'APPROVED');
  assert.equal(after.items[0].rule.ruleId, '@draft');
  // 草案未落盘
  assert.equal(g.listRules().filter((r) => r.ruleId === '@draft').length, 0);
});

test('规则版本链：全局版本号只增，链尖为规则变动记录哈希', () => {
  const g = mem();
  assert.equal(g.chainTip().version, 2);
  g.publishRule({
    ruleId: 'R-CHAIN', scope: { region: 'RG-WEST' },
    body: { denyTags: [], minLeadMinutes: 1 },
    validFrom: '2026-11-01', validUntil: '2026-11-30',
  }, GATE_NOW);
  assert.equal(g.chainTip().version, 3);
  const records = g.store.all().filter((r) => ['RULE_PUBLISHED', 'RULE_REVOKED', 'RULE_ROLLED_BACK'].includes(r.type));
  assert.equal(records.at(-1).hash, g.chainTip().hash);
  assert.notEqual(sha256Hex(canonicalJSON({ x: 1 })), g.chainTip().hash);
});
