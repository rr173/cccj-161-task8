// 灵活负荷资格闸 · 领域内核单测（node:test，纯内存链）。
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { GateChain } from '../gate/chain.js';
import { GateKeyStore } from '../gate/crypto.js';
import { GateEngine, evaluateDevice, maskId } from '../gate/engine.js';
import { canonicalJSON } from '../gate/util.js';

async function newEngine() {
  const chain = new GateChain(null);
  const keys = new GateKeyStore(null);
  const eng = new GateEngine(chain, keys);
  await eng.init();
  return { chain, keys, eng };
}

function submit(eng, applicationNo, items, { eventId = 'EV-1008-ZJ', aggregatorId = 'AGG-A' } = {}) {
  return eng.dispatch({ type: 'SUBMIT_APPLICATION', applicationNo, eventId, aggregatorId, items });
}

// ---------------------- 评估纯函数 ----------------------
test('evaluateDevice: 未知设备仅给 UNKNOWN_DEVICE', () => {
  const r = evaluateDevice(null, { region: 'ZJ', date: '2026-10-08' }, new Map(), Date.UTC(2026, 9, 5));
  assert.equal(r.outcome, 'REJECTED');
  assert.deepEqual(r.reasons.map((x) => x.code), ['UNKNOWN_DEVICE']);
  assert.equal(r.rule, null);
});

// ---------------------- 种子裁决：四类拒绝原因分别列出 ----------------------
test('种子批次：互斥/暂停/跨区域/未知 分别给出拒绝原因，准入者无原因', async () => {
  const { eng } = await newEngine();
  const out = await submit(eng, 'APP-SEED', [
    { deviceId: 'DEV-1001' },
    { deviceId: 'DEV-1002' },
    { deviceId: 'DEV-1003' },
    { deviceId: 'DEV-1004' },
    { deviceId: 'DEV-9999' },
  ]);
  const byId = Object.fromEntries(out.application.decisions.map((d) => [d.deviceId, d]));
  assert.equal(byId['DEV-1001'].outcome, 'ADMITTED');
  assert.deepEqual(byId['DEV-1001'].reasons, []);
  assert.deepEqual(byId['DEV-1002'].reasons.map((r) => r.code), ['MUTEX_TAG']);
  assert.deepEqual(byId['DEV-1003'].reasons.map((r) => r.code), ['DEVICE_SUSPENDED']);
  assert.deepEqual(byId['DEV-1004'].reasons.map((r) => r.code), ['CROSS_REGION']);
  assert.deepEqual(byId['DEV-9999'].reasons.map((r) => r.code), ['UNKNOWN_DEVICE']);
  assert.equal(byId['DEV-1001'].rule.ruleId, 'RULE-ZJ-GENERAL');
  assert.equal(byId['DEV-1001'].rule.version, 1);
});

test('同一设备可并列多个拒绝原因（跨区域 + 暂停）', async () => {
  const { eng } = await newEngine();
  // DEV-1003 是 ZJ 暂停设备；申报到 JS 事件 -> SUSPENDED + CROSS_REGION
  const out = await submit(eng, 'APP-MULTI', [{ deviceId: 'DEV-1003' }], { eventId: 'EV-1006-JS' });
  const codes = out.application.decisions[0].reasons.map((r) => r.code);
  assert.ok(codes.includes('CROSS_REGION'));
  assert.ok(codes.includes('DEVICE_SUSPENDED'));
  assert.equal(codes.length, 2);
});

// ---------------------- 最短提前期 ----------------------
test('最短提前期：临界等于要求准入，少一分钟拒绝', async () => {
  const { eng } = await newEngine();
  // EV-1005-FAST-ZJ 10:00 开始，种子时钟 08:00 => 120 分钟，恰好等于 ZJ 要求
  let t = eng.trial({ eventId: 'EV-1005-FAST-ZJ', items: [{ deviceId: 'DEV-1001' }] });
  assert.equal(t.decisions[0].outcome, 'ADMITTED');
  await eng.dispatch({ type: 'TICK', minutes: 1 }); // 119 < 120
  t = eng.trial({ eventId: 'EV-1005-FAST-ZJ', items: [{ deviceId: 'DEV-1001' }] });
  assert.equal(t.decisions[0].outcome, 'REJECTED');
  assert.deepEqual(t.decisions[0].reasons.map((r) => r.code), ['LEAD_TIME_TOO_SHORT']);
  assert.equal(t.decisions[0].reasons[0].detail.requiredMinutes, 120);
  assert.equal(t.decisions[0].reasons[0].detail.actualMinutes, 119);
});

// ---------------------- 定时生效 / 过期 ----------------------
test('定时生效：生效日前 RULE_PENDING；到达后命中；过期规则 RULE_EXPIRED', async () => {
  const { eng } = await newEngine();
  // 11 月事件 + 11 月规则 RULE-ZJ-NOV（2026-11-01 起）
  await eng.dispatch({
    type: 'REGISTER_EVENT', eventId: 'EV-NOV', region: 'ZJ',
    effectiveDate: '2026-11-10', startMs: Date.UTC(2026, 10, 10, 12),
  });
  // 10 月裁决：11 月规则未生效，10 月规则窗不覆盖 11 月日期
  let t = eng.trial({ eventId: 'EV-NOV', items: [{ deviceId: 'DEV-1001' }] });
  assert.deepEqual(t.decisions[0].reasons.map((r) => r.code), ['RULE_PENDING']);
  // atMs 模拟 11 月当天提前 8 小时（480 >= 240）-> 命中 NOV 规则
  t = eng.trial({ eventId: 'EV-NOV', atMs: Date.UTC(2026, 10, 10, 4), items: [{ deviceId: 'DEV-1001' }] });
  assert.equal(t.decisions[0].outcome, 'ADMITTED');
  assert.equal(t.decisions[0].rule.ruleId, 'RULE-ZJ-NOV');

  // 9 月事件在 9 月时刻命中 9 月规则；在 10 月时刻（atMs=now）回看 9 月日期 -> EXPIRED
  await eng.dispatch({
    type: 'REGISTER_EVENT', eventId: 'EV-SEP', region: 'ZJ',
    effectiveDate: '2026-09-15', startMs: Date.UTC(2026, 8, 15, 12),
  });
  const inSept = eng.trial({ eventId: 'EV-SEP', atMs: Date.UTC(2026, 8, 15, 8), items: [{ deviceId: 'DEV-1001' }] });
  assert.equal(inSept.decisions[0].rule.ruleId, 'RULE-ZJ-SEPT');
  const inOct = eng.trial({ eventId: 'EV-SEP', items: [{ deviceId: 'DEV-1001' }] });
  assert.deepEqual(inOct.decisions[0].reasons.map((r) => r.code), ['RULE_EXPIRED']);
});

// ---------------------- 幂等 / 409 ----------------------
test('同申请号同文幂等返回原裁决（同 seq/同签名）；异文 409', async () => {
  const { eng } = await newEngine();
  const body = [{ deviceId: 'DEV-1001' }, { deviceId: 'DEV-1002' }];
  const a = await submit(eng, 'APP-IDEM', body);
  const sig0 = a.application.decisions[0].signature;
  const b = await submit(eng, 'APP-IDEM', body);
  assert.equal(b.idempotent, true);
  assert.equal(b.application.seq, a.application.seq);
  assert.equal(b.application.decisions[0].signature, sig0);
  await assert.rejects(
    () => submit(eng, 'APP-IDEM', [{ deviceId: 'DEV-1001' }]),
    (e) => e.status === 409 && e.code === 'APPLICATION_NO_CONFLICT',
  );
});

test('空批次：counts 全 0，可冻结，重送幂等', async () => {
  const { eng } = await newEngine();
  const a = await submit(eng, 'APP-0', []);
  assert.deepEqual(a.application.counts, { total: 0, admitted: 0, rejected: 0 });
  const f = await eng.dispatch({ type: 'FREEZE_BATCH', applicationNo: 'APP-0' });
  assert.equal(f.idempotent, false);
  assert.equal(f.frozen.manifest.items.length, 0);
  const f2 = await eng.dispatch({ type: 'FREEZE_BATCH', applicationNo: 'APP-0' });
  assert.equal(f2.idempotent, true);
  assert.equal(f2.frozen.manifestDigest, f.frozen.manifestDigest);
});

test('批次内重复设备 422 DUPLICATE_ITEM', async () => {
  const { eng } = await newEngine();
  await assert.rejects(
    () => submit(eng, 'APP-DUP', [{ deviceId: 'DEV-1001' }, { deviceId: 'DEV-1001' }]),
    (e) => e.status === 422 && e.code === 'DUPLICATE_ITEM',
  );
});

// ---------------------- 规则版本链：撤销/复活/回滚/版本冲突 ----------------------
test('规则撤销后新申请 RULE_REVOKED；已生成批次仍绑定 v1 不被追改', async () => {
  const { eng } = await newEngine();
  const before = await submit(eng, 'APP-BIND', [{ deviceId: 'DEV-1001' }]);
  const v1hash = before.application.decisions[0].rule.versionHash;

  await eng.dispatch({ type: 'REVOKE_RULE', ruleId: 'RULE-ZJ-GENERAL', expectedVersion: 1, reason: '撤' });
  const after = await submit(eng, 'APP-AFTER', [{ deviceId: 'DEV-1001' }]);
  assert.deepEqual(after.application.decisions[0].reasons.map((r) => r.code), ['RULE_REVOKED']);

  // 老申请号重送 -> 仍是 v1
  const replay = await submit(eng, 'APP-BIND', [{ deviceId: 'DEV-1001' }]);
  assert.equal(replay.idempotent, true);
  assert.equal(replay.application.decisions[0].rule.versionHash, v1hash);
});

test('撤销后以 expectedVersion=REVOKED 发布替代版本；错误期望 409', async () => {
  const { eng } = await newEngine();
  await eng.dispatch({ type: 'REVOKE_RULE', ruleId: 'RULE-ZJ-GENERAL', expectedVersion: 1 });
  await assert.rejects(
    () => eng.dispatch({
      type: 'PUBLISH_RULE', ruleId: 'RULE-ZJ-GENERAL', expectedVersion: 1,
      scope: { region: 'ZJ', deviceId: null }, effectiveFrom: '2026-10-01',
      effectiveTo: '2026-10-31', minLeadMinutes: 30, mutexTags: [],
    }),
    (e) => e.code === 'RULE_VERSION_CONFLICT',
  );
  const out = await eng.dispatch({
    type: 'PUBLISH_RULE', ruleId: 'RULE-ZJ-GENERAL', expectedVersion: 'REVOKED',
    scope: { region: 'ZJ', deviceId: null }, effectiveFrom: '2026-10-01',
    effectiveTo: '2026-10-31', minLeadMinutes: 30, mutexTags: [],
  });
  assert.equal(out.rule.currentVersion, 2);
  assert.equal(out.revived, true);
});

test('回滚 = 追加复刻旧正文的新版本，旧版本原样保留', async () => {
  const { eng } = await newEngine();
  await eng.dispatch({
    type: 'PUBLISH_RULE', ruleId: 'RULE-ZJ-GENERAL', expectedVersion: 1,
    scope: { region: 'ZJ', deviceId: null }, effectiveFrom: '2026-10-01',
    effectiveTo: '2026-10-31', minLeadMinutes: 30, mutexTags: ['CRITICAL'],
  });
  const rb = await eng.dispatch({
    type: 'ROLLBACK_RULE', ruleId: 'RULE-ZJ-GENERAL', expectedVersion: 2, targetVersion: 1,
  });
  assert.equal(rb.newVersion.currentVersion, 3);
  assert.equal(rb.newVersion.current.minLeadMinutes, 120);
  assert.equal(rb.newVersion.current.rolledBackFrom, 1);
  const versions = eng.ruleView('RULE-ZJ-GENERAL').versions;
  assert.deepEqual(versions.map((v) => v.version), [1, 2, 3]);
  // 版本摘要链：v3.prevVersionHash === v2.versionHash；v1/v2 摘要不变
  assert.equal(versions[2].prevVersionHash, versions[1].versionHash);
  assert.equal(versions[0].minLeadMinutes, 120);
  assert.equal(versions[1].minLeadMinutes, 30);
});

test('乐观并发控制：stale expectedVersion 409；缺少 expectedVersion 409', async () => {
  const { eng } = await newEngine();
  await eng.dispatch({
    type: 'PUBLISH_RULE', ruleId: 'RULE-SOLO',
    scope: { region: 'SH', deviceId: null }, effectiveFrom: '2026-12-01',
    effectiveTo: '2026-12-31', minLeadMinutes: 60,
  });
  await assert.rejects(
    () => eng.dispatch({
      type: 'PUBLISH_RULE', ruleId: 'RULE-SOLO', expectedVersion: 5,
      scope: { region: 'SH', deviceId: null }, effectiveFrom: '2026-12-01',
      effectiveTo: '2026-12-31', minLeadMinutes: 45,
    }),
    (e) => e.code === 'RULE_VERSION_CONFLICT' && e.details.currentVersion === 1,
  );
  await assert.rejects(
    () => eng.dispatch({
      type: 'PUBLISH_RULE', ruleId: 'RULE-SOLO',
      scope: { region: 'SH', deviceId: null }, effectiveFrom: '2026-12-01',
      effectiveTo: '2026-12-31', minLeadMinutes: 45,
    }),
    (e) => e.code === 'RULE_VERSION_CONFLICT',
  );
});

// ---------------------- 重叠规则 ----------------------
test('同层级同优先级重叠：发布 409（可 force），裁决命中时 RULE_OVERLAP', async () => {
  const { eng } = await newEngine();
  // 先撤销 GENERAL，腾出唯一窗
  await eng.dispatch({ type: 'REVOKE_RULE', ruleId: 'RULE-ZJ-GENERAL', expectedVersion: 1 });
  const body = {
    scope: { region: 'ZJ', deviceId: null }, effectiveFrom: '2026-10-01',
    effectiveTo: '2026-10-31', minLeadMinutes: 120, mutexTags: [], priority: 100,
  };
  await eng.dispatch({ type: 'PUBLISH_RULE', ruleId: 'RULE-A', ...body });
  await assert.rejects(
    () => eng.dispatch({ type: 'PUBLISH_RULE', ruleId: 'RULE-B', ...body }),
    (e) => e.code === 'RULE_OVERLAP_DETECTED' && e.details.conflicts.length === 1,
  );
  // force 后两条同优先级并存 -> 设备被 RULE_OVERLAP 拒绝（不替调度员猜）
  await eng.dispatch({ type: 'PUBLISH_RULE', ruleId: 'RULE-B', ...body, forceOverlap: true });
  const out = await submit(eng, 'APP-OVL', [{ deviceId: 'DEV-1001' }]);
  assert.deepEqual(out.application.decisions[0].reasons.map((r) => r.code), ['RULE_OVERLAP']);
  assert.equal(out.application.decisions[0].reasons[0].detail.rules.length, 2);
});

test('地区级与设备级是正常层次（不报重叠），设备级优先中选', async () => {
  const { eng } = await newEngine();
  // 种子已有 ZJ 地区级 + DEV-1005 设备级规则；DEV-1005 命中设备级（被其 ISLAND 互斥拒）
  const out = await submit(eng, 'APP-SPEC', [{ deviceId: 'DEV-1005' }]);
  assert.equal(out.application.decisions[0].rule.ruleId, 'RULE-DEV-1005');
  assert.deepEqual(out.application.decisions[0].reasons.map((r) => r.code), ['MUTEX_TAG']);
});

// ---------------------- 复核 / 冻结 ----------------------
test('复核只追加复核层，初裁与签名不变；重复复核/冻结后复核被拒', async () => {
  const { eng } = await newEngine();
  await submit(eng, 'APP-RV', [{ deviceId: 'DEV-1001' }, { deviceId: 'DEV-1002' }]);
  const orig = await eng.appView('APP-RV');
  await eng.dispatch({
    type: 'REVIEW_ITEM', applicationNo: 'APP-RV', deviceId: 'DEV-1001',
    reviewer: 'rv', disposition: 'CONFIRMED', note: 'ok',
  });
  await assert.rejects(
    () => eng.dispatch({
      type: 'REVIEW_ITEM', applicationNo: 'APP-RV', deviceId: 'DEV-1001',
      reviewer: 'rv2', disposition: 'OVERRULED',
    }),
    (e) => e.code === 'ITEM_ALREADY_REVIEWED',
  );
  await eng.dispatch({ type: 'FREEZE_BATCH', applicationNo: 'APP-RV', by: 'd' });
  await assert.rejects(
    () => eng.dispatch({
      type: 'REVIEW_ITEM', applicationNo: 'APP-RV', deviceId: 'DEV-1002',
      reviewer: 'rv', disposition: 'CONFIRMED',
    }),
    (e) => e.code === 'BATCH_FROZEN',
  );
  const after = await eng.appView('APP-RV');
  assert.equal(after.decisions[0].signature, orig.decisions[0].signature);
  assert.equal(after.decisions[0].outcome, 'ADMITTED');
  assert.equal(after.decisions[0].review.disposition, 'CONFIRMED');
});

// ---------------------- 签名 ----------------------
test('逐设备裁决：签名/摘要可独立复验，canonical 确定', async () => {
  const { eng, keys } = await newEngine();
  await submit(eng, 'APP-SIG', [{ deviceId: 'DEV-1001' }]);
  const v = eng.verifyDecision('APP-SIG', 'DEV-1001');
  assert.equal(v.valid, true);
  assert.equal(v.digestMatches, true);
  // 篡改 canonical 一个字节 -> 验签失败
  const tampered = v.canonical.replace('ADMITTED', 'REJECTED');
  assert.equal(eng.verifyOffline({ keyId: v.keyId, canonical: tampered, signature: v.signature }).valid, false);
  // 用错误签名 -> 失败
  assert.equal(eng.verifyOffline({ keyId: v.keyId, canonical: v.canonical, signature: '00'.repeat(64) }).valid, false);
  void keys;
});

test('冻结清单：manifest 摘要与签名可复验，空批次也签', async () => {
  const { eng } = await newEngine();
  await submit(eng, 'APP-MF', [{ deviceId: 'DEV-1001' }, { deviceId: 'DEV-1002' }]);
  await eng.dispatch({ type: 'FREEZE_BATCH', applicationNo: 'APP-MF', by: 'd' });
  const vm = eng.verifyManifest('APP-MF');
  assert.equal(vm.valid, true);
  assert.equal(vm.digestMatches, true);
  // manifest 内逐项签名与逐设备签名一致
  const items = JSON.parse(vm.canonical).items;
  const app = eng.appView('APP-MF');
  assert.equal(items[0].signature, app.decisions[0].signature);
  assert.deepEqual(items.map((i) => i.reasons), [[], ['MUTEX_TAG']]);
});

// ---------------------- 并发按序 ----------------------
test('并发申请严格按序落账：seq 连续无重复', async () => {
  const { eng } = await newEngine();
  const rs = await Promise.all(Array.from({ length: 12 }, (_, i) =>
    submit(eng, `APP-C${i}`, [{ deviceId: 'DEV-1001' }])));
  const seqs = rs.map((r) => r.application.seq).sort((a, b) => a - b);
  assert.equal(new Set(seqs).size, 12);
  seqs.forEach((s, i) => { if (i) assert.equal(s, seqs[i - 1] + 1); });
});

// ---------------------- 脱敏 ----------------------
test('maskId：前缀 + 星号 + 尾两位，不泄露完整标识', () => {
  assert.equal(maskId('DEV-1001'), 'DEV-****01');
  assert.equal(maskId('AGG-LANKE'), 'AGG-****KE');
  assert.ok(!maskId('DEV-1001').includes('1001'));
});

// ---------------------- 时钟推进 ----------------------
test('SIM_TICK 推进仿真时钟并上链', async () => {
  const { eng } = await newEngine();
  const before = eng.now();
  await eng.dispatch({ type: 'TICK', minutes: 30 });
  assert.equal(eng.now() - before, 30 * 60000);
  await assert.rejects(() => eng.dispatch({ type: 'TICK', minutes: 0 }), (e) => e.status === 400);
});

test('规范 JSON 键排序：字段顺序不同指纹相同', () => {
  assert.equal(canonicalJSON({ a: 1, b: 2 }), canonicalJSON({ b: 2, a: 1 }));
});
