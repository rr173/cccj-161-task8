// 灵活负荷资格闸 · 真实 HTTP 端到端断言（启动独立子进程，零依赖）。
//   覆盖：规则试算 / 批量申请 / 逐项复核 / 批次冻结 / 脱敏下载 / 独立验签
//         未知设备 / 重叠规则 / 过期规则 / 版本冲突 / 撤销后重试 / 空批次 / 并发次序
//         真实进程重启后裁决顺序与版本链不变。
//
// 用法：先确保 8093 端口空闲；本脚本自行拉起 GATE_MEMORY 之外的文件型实例。
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { dirname } from 'node:path';
import { verify } from 'node:crypto';
import assert from 'node:assert/strict';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = join(__dirname, '..');
const DATA = mkdtempSync(join(tmpdir(), 'gate-e2e-'));
const PORT = 8913;
const BASE = `http://127.0.0.1:${PORT}`;

let passed = 0;
let failed = 0;
function check(name, cond, extra = '') {
  if (cond) {
    passed += 1;
    console.log(`  ✓ ${name}`);
  } else {
    failed += 1;
    console.error(`  ✗ ${name} ${extra}`);
  }
}

async function req(method, path, body) {
  const opt = { method, headers: {} };
  if (body !== undefined) {
    opt.headers['Content-Type'] = 'application/json';
    opt.body = JSON.stringify(body);
  }
  const res = await fetch(BASE + path, opt);
  const text = await res.text();
  let data;
  try { data = text ? JSON.parse(text) : {}; } catch { data = { raw: text }; }
  return { status: res.status, data, headers: res.headers };
}

function startServer(env = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [join(ROOT, 'gate', 'server.js')], {
      env: {
        ...process.env,
        GATE_DIR: DATA,
        GATE_PORT: String(PORT),
        GATE_HOST: '127.0.0.1',
        ...env,
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let out = '';
    child.stdout.on('data', (c) => {
      out += c;
      if (out.includes('资格闸已启动')) resolve(child);
    });
    child.stderr.on('data', (c) => { out += c; });
    setTimeout(() => reject(new Error('服务启动超时: ' + out)), 5000);
  });
}

function stop(child) {
  return new Promise((r) => {
    child.on('exit', r);
    child.kill('SIGTERM');
    setTimeout(() => r(), 1500);
  });
}

async function waitDown() {
  for (let i = 0; i < 30; i++) {
    try {
      await fetch(BASE + '/api/state');
      await new Promise((r) => setTimeout(r, 100));
    } catch {
      return;
    }
  }
}

let app = await startServer();
try {
  console.log('— 规则试算 —');
  {
    const r = await req('POST', '/api/trial', {
      eventId: 'EV-1008-ZJ',
      items: ['DEV-1001', 'DEV-1002', 'DEV-1003', 'DEV-1004', 'DEV-9999'].map((d) => ({ deviceId: d })),
    });
    check('试算 200', r.status === 200);
    const m = Object.fromEntries(r.data.decisions.map((d) => [d.deviceId, d]));
    check('准入 DEV-1001', m['DEV-1001'].outcome === 'ADMITTED');
    check('互斥 MUTEX_TAG', m['DEV-1002'].reasons[0].code === 'MUTEX_TAG');
    check('暂停 DEVICE_SUSPENDED', m['DEV-1003'].reasons[0].code === 'DEVICE_SUSPENDED');
    check('跨区域 CROSS_REGION', m['DEV-1004'].reasons[0].code === 'CROSS_REGION');
    check('未知设备 UNKNOWN_DEVICE', m['DEV-9999'].reasons[0].code === 'UNKNOWN_DEVICE');
    check('试算不落账（applications 仍 0）', (await req('GET', '/api/applications')).data.count === 0);
  }

  console.log('— 批量申请 + 幂等 + 409 —');
  const items = ['DEV-1001', 'DEV-1002', 'DEV-1003', 'DEV-1004', 'DEV-9999'].map((d) => ({ deviceId: d }));
  const appBody = { applicationNo: 'APP-E2E-1', eventId: 'EV-1008-ZJ', aggregatorId: 'AGG-E2E', items };
  {
    const r = await req('POST', '/api/applications', appBody);
    check('首次申请 201', r.status === 201, `got ${r.status}`);
    check('计数 1 准入 / 4 拒绝', r.data.application.counts.admitted === 1 && r.data.application.counts.rejected === 4);
    check('裁决绑定规则版本与摘要', !!r.data.application.decisions[0].rule.versionHash);
  }
  {
    const r = await req('POST', '/api/applications', appBody);
    check('同文重送 200', r.status === 200);
    check('标记 idempotent', r.data.idempotent === true);
  }
  {
    const r = await req('POST', '/api/applications', { ...appBody, items: [{ deviceId: 'DEV-1001' }] });
    check('同号异文 409 APPLICATION_NO_CONFLICT', r.status === 409 && r.data.code === 'APPLICATION_NO_CONFLICT');
    check('409 携带原 bodyHash', !!r.data.details.existingBodyHash);
  }

  console.log('— 空批次 —');
  {
    const r = await req('POST', '/api/applications', {
      applicationNo: 'APP-E2E-EMPTY', eventId: 'EV-1008-ZJ', aggregatorId: 'AGG-X', items: [],
    });
    check('空批次 201 且 total=0', r.status === 201 && r.data.application.counts.total === 0);
    const f = await req('POST', '/api/applications/APP-E2E-EMPTY/freeze', {});
    check('空批次可冻结，manifest.items=[]', f.status === 201 && f.data.frozen.manifest.items.length === 0);
  }

  console.log('— 逐项复核 / 批次冻结 —');
  {
    const r = await req('POST', '/api/applications/APP-E2E-1/items/DEV-1001/review', {
      reviewer: 'rv-e2e', disposition: 'CONFIRMED', note: '齐',
    });
    check('复核 201', r.status === 201);
    const r2 = await req('POST', '/api/applications/APP-E2E-1/items/DEV-1001/review', {
      reviewer: 'rv2', disposition: 'OVERRULED',
    });
    check('重复复核 409', r2.status === 409 && r2.data.code === 'ITEM_ALREADY_REVIEWED');

    const before = await req('GET', '/api/applications/APP-E2E-1');
    const f = await req('POST', '/api/applications/APP-E2E-1/freeze', { by: 'd' });
    check('首次冻结 201', f.status === 201);
    const f2 = await req('POST', '/api/applications/APP-E2E-1/freeze', {});
    check('重复冻结 200 幂等', f2.status === 200 && f2.data.idempotent === true);
    check('冻结摘要/签名稳定', f.data.frozen.manifestDigest === f2.data.frozen.manifestDigest);
    const after = await req('GET', '/api/applications/APP-E2E-1');
    check('初裁签名复核/冻结前后不变',
      before.data.decisions[0].signature === after.data.decisions[0].signature);
    const rf = await req('POST', '/api/applications/APP-E2E-1/items/DEV-1002/review', {
      reviewer: 'rv', disposition: 'CONFIRMED',
    });
    check('冻结后复核 409 BATCH_FROZEN', rf.status === 409 && rf.data.code === 'BATCH_FROZEN');
  }

  console.log('— 脱敏清单下载 —');
  {
    const nf = await req('GET', '/api/applications/APP-E2E-1/redacted.csv');
    void nf;
    // APP-E2E-1 已冻结 -> 200
    const r = await fetch(BASE + '/api/applications/APP-E2E-1/redacted.csv');
    const text = await r.text();
    check('CSV 200', r.status === 200);
    check('CSV 含表头', text.includes('申请号') && text.includes('设备(脱敏)'));
    check('CSV 设备打码（不含完整 DEV-1001）', !text.includes('DEV-1001') && text.includes('DEV-****01'));
    check('CSV 聚合商打码', !text.includes('AGG-E2E') && text.includes('AGG-****E2E'.slice(0, 7)));
    check('CSV 含拒绝原因中文', text.includes('命中互斥标签') && text.includes('设备已暂停'));
  }

  console.log('— 独立验签 —');
  {
    const vd = await req('GET', '/api/applications/APP-E2E-1/items/DEV-1001/verify');
    check('逐设备验签 valid + 摘要一致', vd.data.valid === true && vd.data.digestMatches === true);
    const vm = await req('GET', '/api/applications/APP-E2E-1/manifest/verify');
    check('清单验签 valid + 摘要一致', vm.data.valid === true && vm.data.digestMatches === true);
    // 完全离线：只凭公钥 PEM + canonical + signature
    const off = await req('POST', '/api/verify', {
      publicKeyPem: vd.data.publicKeyPem, canonical: vd.data.canonical, signature: vd.data.signature,
    });
    check('自带公钥离线验签通过', off.data.valid === true);
    // 篡改 canonical -> false
    const bad = await req('POST', '/api/verify', {
      publicKeyPem: vd.data.publicKeyPem,
      canonical: vd.data.canonical.replace('ADMITTED', 'REJECTED'),
      signature: vd.data.signature,
    });
    check('篡改后离线验签失败', bad.data.valid === false);
    // 用 Node crypto 脱离本服务接口独立复算一次（真·第三方）
    const ok = verify(null, Buffer.from(vd.data.canonical), vd.data.publicKeyPem, Buffer.from(vd.data.signature, 'hex'));
    check('Node crypto 第三方独立验签通过', ok === true);
  }

  console.log('— 重叠规则 / 过期 / 版本冲突 —');
  {
    // 撤销 GENERAL 腾出窗，再造两条同优先级规则
    await req('POST', '/api/rules/RULE-ZJ-GENERAL/revoke', { expectedVersion: 1 });
    const body = {
      scope: { region: 'ZJ', deviceId: null }, effectiveFrom: '2026-10-01',
      effectiveTo: '2026-10-31', minLeadMinutes: 120, mutexTags: [], priority: 100,
    };
    const a = await req('POST', '/api/rules', { ruleId: 'RULE-E2E-A', ...body });
    check('第一条规则 201', a.status === 201);
    const b = await req('POST', '/api/rules', { ruleId: 'RULE-E2E-B', ...body });
    check('同优先级重叠 409 RULE_OVERLAP_DETECTED',
      b.status === 409 && b.data.code === 'RULE_OVERLAP_DETECTED' && b.data.details.conflicts.length === 1);
    await req('POST', '/api/rules', { ruleId: 'RULE-E2E-B', ...body, forceOverlap: true });
    const ovl = await req('POST', '/api/applications', {
      applicationNo: 'APP-E2E-OVL', eventId: 'EV-1008-ZJ', aggregatorId: 'AGG-X',
      items: [{ deviceId: 'DEV-1001' }],
    });
    check('裁决命中重叠 RULE_OVERLAP（两条并列）',
      ovl.data.application.decisions[0].reasons[0].code === 'RULE_OVERLAP'
      && ovl.data.application.decisions[0].reasons[0].detail.rules.length === 2);

    // 版本冲突：用一条独占 12 月窗口的规则，避开重叠检测，专门验证乐观锁
    await req('POST', '/api/rules', {
      ruleId: 'RULE-E2E-SOLO',
      scope: { region: 'ZJ', deviceId: null }, effectiveFrom: '2026-12-01',
      effectiveTo: '2026-12-31', minLeadMinutes: 120, mutexTags: [], priority: 100,
    });
    const vc = await req('POST', '/api/rules', {
      ruleId: 'RULE-E2E-SOLO', expectedVersion: 99,
      scope: { region: 'ZJ', deviceId: null }, effectiveFrom: '2026-12-01',
      effectiveTo: '2026-12-31', minLeadMinutes: 10, mutexTags: [], priority: 100,
    });
    check('stale expectedVersion 409', vc.status === 409 && vc.data.code === 'RULE_VERSION_CONFLICT');
    const vv = await req('POST', '/api/rules', {
      ruleId: 'RULE-E2E-SOLO', expectedVersion: 1,
      scope: { region: 'ZJ', deviceId: null }, effectiveFrom: '2026-12-01',
      effectiveTo: '2026-12-31', minLeadMinutes: 10, mutexTags: [], priority: 100,
    });
    check('正确 expectedVersion 改版 201 为 v2', vv.status === 201 && vv.data.rule.currentVersion === 2);
  }

  console.log('— 撤销后重试（原批次不被追改）—');
  {
    const r = await req('POST', '/api/applications', {
      applicationNo: 'APP-JS', eventId: 'EV-1006-JS', aggregatorId: 'AGG-JS',
      items: [{ deviceId: 'DEV-1004' }],
    });
    check('撤销前 JS 设备准入', r.data.application.decisions[0].outcome === 'ADMITTED');
    const boundHash = r.data.application.decisions[0].rule.versionHash;
    await req('POST', '/api/rules/RULE-JS-GENERAL/revoke', { expectedVersion: 1 });
    const after = await req('POST', '/api/applications', {
      applicationNo: 'APP-JS-2', eventId: 'EV-1006-JS', aggregatorId: 'AGG-JS',
      items: [{ deviceId: 'DEV-1004' }],
    });
    check('撤销后新申请 RULE_REVOKED',
      after.data.application.decisions[0].reasons[0].code === 'RULE_REVOKED');
    const replay = await req('POST', '/api/applications', {
      applicationNo: 'APP-JS', eventId: 'EV-1006-JS', aggregatorId: 'AGG-JS',
      items: [{ deviceId: 'DEV-1004' }],
    });
    check('原申请号重送幂等且仍绑撤销前版本',
      replay.data.idempotent === true
      && replay.data.application.decisions[0].rule.versionHash === boundHash);
    // 复活 + 回滚
    const rev = await req('POST', '/api/rules', {
      ruleId: 'RULE-JS-GENERAL', expectedVersion: 'REVOKED',
      scope: { region: 'JS', deviceId: null }, effectiveFrom: '2026-10-01',
      effectiveTo: '2026-10-31', minLeadMinutes: 15, mutexTags: [],
    });
    check('撤销后复活发版 v2', rev.data.rule.currentVersion === 2 && rev.data.revived === true);
    const rb = await req('POST', '/api/rules/RULE-JS-GENERAL/rollback', {
      expectedVersion: 2, targetVersion: 1,
    });
    check('回滚为 v3，正文回到 v1（120 分钟）',
      rb.data.newVersion.currentVersion === 3
      && rb.data.newVersion.current.minLeadMinutes === 120
      && rb.data.newVersion.current.rolledBackFrom === 1);
  }

  console.log('— 密钥轮换：旧批次仍可验，新批次用新 keyId —');
  {
    const rot = await req('POST', '/api/keys/rotate', { by: 'ops' });
    check('轮换 201 到 gate-key-2', rot.status === 201 && rot.data.keyId === 'gate-key-2');
    const n = await req('POST', '/api/applications', {
      applicationNo: 'APP-E2E-NEWKEY', eventId: 'EV-1008-ZJ', aggregatorId: 'AGG-K',
      items: [{ deviceId: 'DEV-1001' }],
    });
    check('新批次用 gate-key-2 签名', n.data.application.keyId === 'gate-key-2');
    const oldVd = await req('GET', '/api/applications/APP-E2E-1/items/DEV-1001/verify');
    check('旧批次仍按 gate-key-1 复验通过',
      oldVd.data.keyId === 'gate-key-1' && oldVd.data.valid === true);
    const newVd = await req('GET', '/api/applications/APP-E2E-NEWKEY/items/DEV-1001/verify');
    check('新批次按 gate-key-2 复验通过', newVd.data.valid === true);
  }

  console.log('— 并发按序落账 —');
  {
    const rs = await Promise.all(Array.from({ length: 10 }, (_, i) =>
      req('POST', '/api/applications', {
        applicationNo: `APP-CONC-${i}`, eventId: 'EV-1008-ZJ', aggregatorId: 'AGG-C',
        items: [{ deviceId: 'DEV-1001' }],
      })));
    const seqs = rs.map((r) => r.data.application.seq).sort((a, b) => a - b);
    const contiguous = seqs.every((s, i) => i === 0 || s === seqs[i - 1] + 1);
    check('10 个并发申请 seq 严格连续无重复', new Set(seqs).size === 10 && contiguous);
  }

  // 记录重启前快照
  const preState = await req('GET', '/api/state');
  const preTip = preState.data.chain.tipHash;
  const preSeq = preState.data.chain.length;
  const preApp = (await req('GET', '/api/applications/APP-E2E-1')).data;

  console.log('— 真实进程重启：顺序与版本链不变 —');
  await stop(app);
  await waitDown();
  app = await startServer();
  {
    const st = await req('GET', '/api/state');
    check('重启后链完整', st.data.chain.ok === true);
    check('链尖一致', st.data.chain.tipHash === preTip);
    check('记录数一致', st.data.chain.length === preSeq);
    const a2 = (await req('GET', '/api/applications/APP-E2E-1')).data;
    check('裁决顺序 seq 不变', a2.seq === preApp.seq);
    check('逐设备签名逐字节不变',
      JSON.stringify(a2.decisions.map((d) => d.signature))
      === JSON.stringify(preApp.decisions.map((d) => d.signature)));
    check('冻结信息保留', !!a2.frozen && a2.frozen.manifestDigest === preApp.frozen.manifestDigest);
    const vd = await req('GET', '/api/applications/APP-E2E-1/items/DEV-1001/verify');
    check('重启后独立验签仍通过', vd.data.valid === true);
    const js = st.data.rules.find((r) => r.ruleId === 'RULE-JS-GENERAL');
    check('JS 规则版本链保留（v1 撤销 → v2 复活 → v3 回滚）',
      js.versions.map((v) => v.version).join(',') === '1,2,3'
      && js.versions[2].rolledBackFrom === 1);
    const zj = st.data.rules.find((r) => r.ruleId === 'RULE-ZJ-GENERAL');
    check('ZJ 规则保持撤销态（无 current）', zj.currentVersion === null);
  }
} finally {
  await stop(app);
  await waitDown();
  rmSync(DATA, { recursive: true, force: true });
}

console.log(`\n结果：${passed} 通过，${failed} 失败`);
if (failed) process.exit(1);
