// 资格闸 · 重启恢复与哈希链完整性单测（真实文件链，node:test）。
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, appendFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { GateChain } from '../gate/chain.js';
import { GateKeyStore } from '../gate/crypto.js';
import { GateEngine } from '../gate/engine.js';

let dir;
before(() => {
  dir = mkdtempSync(join(tmpdir(), 'gate-restart-'));
});
after(() => rmSync(dir, { recursive: true, force: true }));

const logPath = () => join(dir, 'gate.log');
const keyPath = () => join(dir, 'gate-keys.json');

async function boot() {
  const chain = new GateChain(logPath());
  const keys = new GateKeyStore(keyPath());
  const eng = new GateEngine(chain, keys);
  await eng.init();
  return { chain, keys, eng };
}

test('重启后：链完整、裁决顺序(seq)/版本链/逐设备签名逐字节不变', async () => {
  rmSync(logPath(), { force: true });
  rmSync(keyPath(), { force: true });

  // 第一次进程：申请 + 改版 + 撤销 + 复活 + 回滚 + 复核 + 冻结，制造丰富版本链
  {
    const { eng, chain } = await boot();
    await eng.dispatch({
      type: 'SUBMIT_APPLICATION', applicationNo: 'APP-PERSIST',
      eventId: 'EV-1008-ZJ', aggregatorId: 'AGG-A',
      items: [{ deviceId: 'DEV-1001' }, { deviceId: 'DEV-1002' }, { deviceId: 'DEV-1003' }],
    });
    await eng.dispatch({
      type: 'PUBLISH_RULE', ruleId: 'RULE-ZJ-GENERAL', expectedVersion: 1,
      scope: { region: 'ZJ', deviceId: null }, effectiveFrom: '2026-10-01',
      effectiveTo: '2026-10-31', minLeadMinutes: 45, mutexTags: ['CRITICAL'],
    });
    await eng.dispatch({
      type: 'ROLLBACK_RULE', ruleId: 'RULE-ZJ-GENERAL',
      expectedVersion: 2, targetVersion: 1,
    });
    await eng.dispatch({
      type: 'REVIEW_ITEM', applicationNo: 'APP-PERSIST', deviceId: 'DEV-1001',
      reviewer: 'rv', disposition: 'CONFIRMED',
    });
    await eng.dispatch({ type: 'FREEZE_BATCH', applicationNo: 'APP-PERSIST', by: 'd' });

    const app = eng.appView('APP-PERSIST');
    const vm = eng.verifyManifest('APP-PERSIST');
    const vd = eng.verifyDecision('APP-PERSIST', 'DEV-1001');
    // 快照
    writeFileSync(join(dir, 'snap1.json'), JSON.stringify({
      seq: chain.seq,
      tip: chain.tipHash,
      appSeq: app.seq,
      versions: eng.ruleView('RULE-ZJ-GENERAL').versions.map((v) => ({
        version: v.version, hash: v.versionHash, prev: v.prevVersionHash,
        lead: v.minLeadMinutes, rolledFrom: v.rolledBackFrom ?? null,
      })),
      signatures: app.decisions.map((d) => d.signature),
      digests: app.decisions.map((d) => d.decisionDigest),
      review: app.decisions[0].review.disposition,
      manifestDigest: vm.digest,
      manifestSig: vm.signature,
      decisionValid: vd.valid,
    }));
  }

  // 第二次进程：全新实例，从同一文件恢复
  const { eng, chain } = await boot();
  const snap = JSON.parse(readFileSync(join(dir, 'snap.json').replace('snap.json', 'snap1.json')));
  const verify = chain.verify();
  assert.equal(verify.ok, true);
  assert.equal(chain.seq, snap.seq);
  assert.equal(chain.tipHash, snap.tip);

  const app = eng.appView('APP-PERSIST');
  assert.equal(app.seq, snap.appSeq);
  assert.deepEqual(app.decisions.map((d) => d.signature), snap.signatures);
  assert.deepEqual(app.decisions.map((d) => d.decisionDigest), snap.digests);
  assert.equal(app.decisions[0].review.disposition, snap.review);
  // 裁决绑定的规则版本（v1）不受后续 v2/v3 追改
  assert.equal(app.decisions[0].rule.version, 1);
  assert.equal(app.decisions[0].rule.minLeadMinutes, 120);

  // 版本链完整保留
  const versions = eng.ruleView('RULE-ZJ-GENERAL').versions;
  assert.deepEqual(versions.map((v) => v.version), [1, 2, 3]);
  assert.deepEqual(versions.map((v) => v.minLeadMinutes), [120, 45, 120]);
  assert.equal(versions[2].rolledBackFrom, 1);

  // 签名仍可用恢复后的 sidecar 公钥复验
  const vd = eng.verifyDecision('APP-PERSIST', 'DEV-1001');
  const vm = eng.verifyManifest('APP-PERSIST');
  assert.equal(vd.valid, true);
  assert.equal(vm.valid, true);
  assert.equal(vm.digest, snap.manifestDigest);
  assert.equal(vm.signature, snap.manifestSig);
});

test('重启后幂等依旧生效：同申请号重送仍返回原裁决', async () => {
  const { eng } = await boot();
  const out = await eng.dispatch({
    type: 'SUBMIT_APPLICATION', applicationNo: 'APP-PERSIST',
    eventId: 'EV-1008-ZJ', aggregatorId: 'AGG-A',
    items: [{ deviceId: 'DEV-1001' }, { deviceId: 'DEV-1002' }, { deviceId: 'DEV-1003' }],
  });
  assert.equal(out.idempotent, true);
});

test('篡改中间记录 -> 只读隔离（QUARANTINED），写入 503，链文件保留', async () => {
  const f = logPath();
  const lines = readFileSync(f, 'utf8').trim().split('\n');
  const idx = Math.floor(lines.length / 2);
  const rec = JSON.parse(lines[idx]);
  rec.payload = { ...rec.payload, tampered: true };
  lines[idx] = JSON.stringify(rec); // hash 不再匹配
  writeFileSync(f, lines.join('\n') + '\n');

  const chain = new GateChain(f);
  const v = chain.load();
  assert.equal(v.ok, false);
  assert.equal(v.writable, false);
  assert.equal(v.recovery.kind, 'corrupt');

  const keys = new GateKeyStore(keyPath());
  const eng = new GateEngine(chain, keys);
  await eng.init();
  await assert.rejects(
    () => eng.dispatch({ type: 'TICK', minutes: 1 }),
    (e) => e.status === 503 && e.code === 'CHAIN_QUARANTINED',
  );
});

test('文件末尾断电残尾 -> 归档旁证后截断续链，从最后完好记录恢复', async () => {
  // 用一个独立目录避免污染前一个用例的隔离状态
  const d2 = mkdtempSync(join(tmpdir(), 'gate-torn-'));
  try {
    const lf = join(d2, 'gate.log');
    const kf = join(d2, 'gate-keys.json');
    {
      const chain = new GateChain(lf);
      const keys = new GateKeyStore(kf);
      const eng = new GateEngine(chain, keys);
      await eng.init();
      await eng.dispatch({
        type: 'SUBMIT_APPLICATION', applicationNo: 'APP-TORN',
        eventId: 'EV-1008-ZJ', aggregatorId: 'AGG-A', items: [{ deviceId: 'DEV-1001' }],
      });
    }
    const good = readFileSync(lf, 'utf8');
    const goodTip = good.trim().split('\n').at(-1);
    // 追加一条写了一半、没有终止换行的残尾（字节级）
    appendFileSync(lf, '{"seq":999,"ts":"2026-10-05T08:00:00.000Z","type":"BROKEN');

    const chain = new GateChain(lf);
    const v = chain.load();
    assert.equal(v.ok, true); // 残尾已恢复，链在最后完好记录处闭合，可继续写
    assert.equal(v.recovery.kind, 'torn-tail-recovered');

    const keys = new GateKeyStore(kf);
    const eng = new GateEngine(chain, keys);
    await eng.init();
    // 批次仍在
    const app = eng.appView('APP-TORN');
    assert.equal(app.counts.total, 1);
    // 新记录延续原链：prevHash === 残尾前最后一条 hash
    const after = await eng.dispatch({ type: 'TICK', minutes: 5 });
    assert.equal(after.ok, true);
    const last = chain.all().at(-1);
    assert.equal(last.prevHash, JSON.parse(goodTip).hash);
  } finally {
    rmSync(d2, { recursive: true, force: true });
  }
});

test('种子确定性：全新内存库初始化后链记录确定', async () => {
  const a = new GateChain(null);
  const ka = new GateKeyStore(null);
  const ea = new GateEngine(a, ka);
  await ea.init();
  const tipA = a.tipHash;
  const seqA = a.seq;
  // 第二套独立实例（密钥不同会影响 GATE_KEY_PUBLISHED 之后的哈希；
  // 但种子数据部分（密钥之前）应完全一致）
  const b = new GateChain(null);
  const kb = new GateKeyStore(null);
  const eb = new GateEngine(b, kb);
  await eb.init();
  assert.equal(b.seq, seqA);
  // 找到密钥发布位置，其之前的记录（全部种子事实）哈希应一致
  const seedTipA = a.all().find((r) => r.type === 'GATE_KEY_PUBLISHED').prevHash;
  const seedTipB = b.all().find((r) => r.type === 'GATE_KEY_PUBLISHED').prevHash;
  assert.equal(seedTipA, seedTipB);
  void tipA;
});
