// 灵活负荷资格闸 · 端到端（真实 HTTP + 真实进程重启）。
// 覆盖：未知设备/互斥标签/暂停/跨区域/最短提前期/多原因 · 申请号幂等与 409 正文冲突 ·
// 规则试算 · 定时生效/过期/定时撤销 · 重叠规则/版本冲突 · 撤销后重试与回滚 ·
// 空批次 · 批次冻结与脱敏 CSV · 独立验签与版本钉死 · 并发按序落账 ·
// 真实重启后裁决顺序、版本链、幂等台账、逐字节摘要不变。
import { spawn } from 'node:child_process';
import { mkdtempSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';

const PORT = Number(process.env.PORT || 8094);
const BASE = `http://localhost:${PORT}`;
const dir = mkdtempSync(join(tmpdir(), 'gate-e2e-'));
const LOG = join(dir, 'eligibility.log');
const KEYS = join(dir, 'eligibility-keys.json');

let pass = 0, fail = 0;
function check(name, cond, extra = '') {
  if (cond) { pass++; console.log('  ✅', name, extra); }
  else { fail++; console.log('  ❌', name, extra); }
}
async function api(path, body, method = 'POST') {
  const res = await fetch(BASE + path, {
    method,
    headers: body ? { 'Content-Type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json();
  if (!res.ok) throw Object.assign(new Error(data.error), { code: data.code, status: res.status, details: data.details });
  return data;
}

function startServer() {
  const child = spawn(process.execPath, ['eligibility/server.js'], {
    env: { ...process.env, PORT: String(PORT), GATE_LOG: LOG, GATE_KEYS: KEYS },
    stdio: ['ignore', 'pipe', 'inherit'],
  });
  return child;
}
async function waitReady(child, timeoutMs = 8000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try { await api('/api/state', null, 'GET'); return; } catch { await sleep(100); }
  }
  child.kill();
  throw new Error('服务启动超时');
}
async function restart(child) {
  child.kill();
  await sleep(300);
  const next = startServer();
  await waitReady(next);
  return next;
}

let child = startServer();
await waitReady(child);
let st = await api('/api/state', null, 'GET');
const NOW = st.now;
const inMin = (m) => NOW + m * 60000;
const itemOf = (b, id) => b.items.find((i) => i.deviceId === id);

console.log('场景 A：逐设备准入与拒绝原因');
st = await api('/api/state', null, 'GET');
let res = await api('/api/applications', {
  requestId: 'BID-A', aggregatorId: 'AGG-A',
  event: { eventId: 'EV-A', region: 'RG-EAST', startMs: inMin(20) },
  deviceIds: ['GFD-1', 'GFD-2', 'GFD-3', 'GFD-4', 'GFD-UNKNOWN'],
});
const ba = res.batch;
check('裁决含 5 台设备且顺序保留', ba.counts.total === 5 && ba.items.map((i) => i.order).join() === '0,1,2,3,4');
check('未知设备 -> UNKNOWN_DEVICE', itemOf(ba, 'GFD-UNKNOWN').reasons.join() === 'UNKNOWN_DEVICE');
check('GFD-1 提前期不足 -> LEAD_TIME', itemOf(ba, 'GFD-1').reasons.join() === 'LEAD_TIME');
check('GFD-2 互斥标签 + 提前期 -> MUTEX_TAG,LEAD_TIME',
  itemOf(ba, 'GFD-2').reasons.join() === 'MUTEX_TAG,LEAD_TIME', itemOf(ba, 'GFD-2').reasons.join());
check('GFD-3 跨区域 -> CROSS_REGION', itemOf(ba, 'GFD-3').reasons.join() === 'CROSS_REGION');
check('GFD-4 暂停 + 提前期 -> DEVICE_SUSPENDED,LEAD_TIME',
  itemOf(ba, 'GFD-4').reasons.join() === 'DEVICE_SUSPENDED,LEAD_TIME', itemOf(ba, 'GFD-4').reasons.join());
check('批次带规则版本与签名摘要', !!ba.batchDigest && !!ba.signature && ba.keyId === 'pkg-key-1');
check('绑定种子规则链尖 v2', ba.ruleChainTip.version === 2);
let vfy = await api(`/api/batches/${ba.batchId}/verify`, null, 'GET');
check('独立验签整体有效', vfy.valid === true && vfy.signatureValid === true && vfy.digestMatches === true);

console.log('场景 B：申请号幂等（同号重送原裁决）与正文变更 409');
const resend = await api('/api/applications', {
  requestId: 'BID-A', aggregatorId: 'AGG-A',
  event: { eventId: 'EV-A', region: 'RG-EAST', startMs: inMin(20) },
  deviceIds: ['GFD-1', 'GFD-2', 'GFD-3', 'GFD-4', 'GFD-UNKNOWN'],
});
check('同号同文返回原批次（幂等）', resend.idempotent === true && resend.batch.batchId === ba.batchId);
let conflict;
try {
  await api('/api/applications', {
    requestId: 'BID-A', aggregatorId: 'AGG-A',
    event: { eventId: 'EV-A', region: 'RG-EAST', startMs: inMin(20) },
    deviceIds: ['GFD-1'], // 正文变更
  });
} catch (e) { conflict = e; }
check('同号异文 -> 409 REQUEST_ID_CONFLICT', conflict?.status === 409 && conflict.code === 'REQUEST_ID_CONFLICT', conflict?.code);

console.log('场景 C：规则试算（不落盘，可叠加草案）');
const tr1 = await api('/api/rules/trial', {
  at: NOW, event: { eventId: 'TR', region: 'RG-EAST', startMs: inMin(120) },
  deviceIds: ['GFD-2'],
});
check('草案前 GFD-2 被互斥拒绝', tr1.items[0].decision === 'REJECTED');
const tr2 = await api('/api/rules/trial', {
  at: NOW, event: { eventId: 'TR', region: 'RG-EAST', startMs: inMin(120) },
  deviceIds: ['GFD-2'],
  draftRule: { scope: { region: 'RG-EAST', deviceId: null }, body: { denyTags: [], minLeadMinutes: 0 }, validFrom: '2026-10-01', validUntil: '2026-12-31' },
});
check('叠加放宽草案后 GFD-2 准入（@draft）', tr2.items[0].decision === 'APPROVED' && tr2.items[0].rule.ruleId === '@draft');
st = await api('/api/state', null, 'GET');
check('草案未写入版本链（链尖仍 v2）', st.ruleChain.version === 2);

console.log('场景 D：规则维护 —— 重叠 409 / 乐观锁冲突 / 设备专属优先');
let overlap;
try {
  await api('/api/rules', {
    scope: { region: 'RG-WEST', deviceId: null }, body: { denyTags: [], minLeadMinutes: 1 },
    validFrom: '2026-10-15', validUntil: '2026-11-15',
  });
} catch (e) { overlap = e; }
check('同作用域日期重叠 -> 409 RULE_OVERLAP', overlap?.code === 'RULE_OVERLAP', overlap?.code);
let verConflict;
try {
  await api('/api/rules', {
    scope: { region: 'RG-WEST', deviceId: null }, body: { denyTags: [], minLeadMinutes: 1 },
    validFrom: '2026-11-01', validUntil: '2026-11-30', expectedVersion: 1,
  });
} catch (e) { verConflict = e; }
check('过期 expectedVersion -> 409 RULE_VERSION_CONFLICT', verConflict?.code === 'RULE_VERSION_CONFLICT', verConflict?.code);
const devRule = await api('/api/rules', {
  ruleId: 'R-DEV1-NOLEAD',
  scope: { region: 'RG-EAST', deviceId: 'GFD-1' }, body: { denyTags: [], minLeadMinutes: 0 },
  validFrom: '2026-10-01', validUntil: '2026-12-31',
});
check('设备专属规则发布到 v3', devRule.rule.head.version === 3);
const appr = await api('/api/applications', {
  requestId: 'BID-C', aggregatorId: 'AGG-A',
  event: { eventId: 'EV-C', region: 'RG-EAST', startMs: inMin(0) },
  deviceIds: ['GFD-1'],
});
check('设备专属规则优先：GFD-1 立即事件也准入', itemOf(appr.batch, 'GFD-1').decision === 'APPROVED'
  && itemOf(appr.batch, 'GFD-1').rule.ruleId === 'R-DEV1-NOLEAD');

console.log('场景 E：撤销后重试 -> 无规则；回滚恢复准入；定时撤销');
await api(`/api/rules/RULE-WEST-DEFAULT/revoke`, { reason: '西区规则复核', effectiveFrom: '2026-10-10' });
st = await api('/api/state', null, 'GET');
check('定时撤销记录占用版本号（链尖 v4）', st.ruleChain.version === 4);
const westBefore = await api('/api/applications', {
  requestId: 'BID-W1', aggregatorId: 'AGG-A',
  event: { eventId: 'EV-W', region: 'RG-WEST', startMs: inMin(120) }, deviceIds: ['GFD-3'],
});
check('撤销生效日前 GFD-3 仍可准入', itemOf(westBefore.batch, 'GFD-3').decision === 'APPROVED');
await api('/api/sim/tick', { minutes: 4 * 24 * 60 }); // 到 2026-10-10
st = await api('/api/state', null, 'GET');
const westAfter = await api('/api/applications', {
  requestId: 'BID-W2', aggregatorId: 'AGG-A',
  event: { eventId: 'EV-W2', region: 'RG-WEST', startMs: st.now + 120 * 60000 }, deviceIds: ['GFD-3'],
});
check('撤销生效日 GFD-3 -> NO_APPLICABLE_RULE', itemOf(westAfter.batch, 'GFD-3').reasons.join() === 'NO_APPLICABLE_RULE');
const head = await api('/api/rules/RULE-WEST-DEFAULT', null, 'GET');
check('头版本生命周期显示 REVOKED', head.head.lifecycle === 'REVOKED');
let republishErr;
try {
  await api('/api/rules', {
    ruleId: 'RULE-WEST-DEFAULT', scope: { region: 'RG-WEST' }, body: { denyTags: ['X'], minLeadMinutes: 9 },
    validFrom: '2026-10-10', validUntil: '2026-12-31',
  });
} catch (e) { republishErr = e; }
check('撤销后直接改规则 -> 409 RULE_REVOKED（须走回滚）', republishErr?.code === 'RULE_REVOKED', republishErr?.code);
const rollback = await api('/api/rules/rollback', { fromVersion: 2 });
check('回滚到 v2 内容：规则 v2、restoredFromVersion=2', rollback.rule.head.ruleVersion === 2 && rollback.rule.head.restoredFromVersion === 2);
const westRetry = await api('/api/applications', {
  requestId: 'BID-W3', aggregatorId: 'AGG-A',
  event: { eventId: 'EV-W3', region: 'RG-WEST', startMs: st.now + 120 * 60000 }, deviceIds: ['GFD-3'],
});
check('撤销后重试：回滚恢复后 GFD-3 准入', itemOf(westRetry.batch, 'GFD-3').decision === 'APPROVED');

console.log('场景 F：版本钉死 —— 历史批次不被后续规则追改');
const rebound = await api(`/api/batches/${ba.batchId}`, null, 'GET');
check('历史批次仍钉在 v2，裁决不变',
  rebound.ruleChainTip.version === 2 && itemOf(rebound, 'GFD-2').reasons.join() === 'MUTEX_TAG,LEAD_TIME');
const reboundV = await api(`/api/batches/${ba.batchId}/verify`, null, 'GET');
check('历史批次在规则回滚后验签依然有效', reboundV.valid === true && reboundV.tipIntact === true);

console.log('场景 G：空批次');
const empty = await api('/api/applications', {
  requestId: 'BID-EMPTY', aggregatorId: 'AGG-B',
  event: { eventId: 'EV-E', region: 'RG-EAST', startMs: st.now + 60 * 60000 }, deviceIds: [],
});
check('空批次计数为 0 且带摘要', empty.batch.counts.total === 0 && !!empty.batch.batchDigest);
check('空批次验签有效', (await api(`/api/batches/${empty.batch.batchId}/verify`, null, 'GET')).valid === true);
await api(`/api/batches/${empty.batch.batchId}/freeze`, {});
let csvErr;
try { await api(`/api/batches/${appr.batch.batchId}/redacted.csv`, null, 'GET'); } catch (e) { csvErr = e; }
check('未冻结批次拒绝脱敏下载 -> 409 BATCH_NOT_FROZEN', csvErr?.code === 'BATCH_NOT_FROZEN', csvErr?.code);
await api(`/api/batches/${appr.batch.batchId}/freeze`, {});
const csvRes = await fetch(`${BASE}/api/batches/${appr.batch.batchId}/redacted.csv`);
const csv = await csvRes.text();
check('脱敏 CSV 200 且不含原始设备号 GFD-1', csvRes.status === 200 && !csv.includes('GFD-1') && /GFD-\*\*\*\*-[0-9a-f]{8}/.test(csv));

console.log('场景 H：并发按序落账（同步串行，顺序=到达顺序）');
const seqIds = [];
for (let i = 0; i < 6; i++) {
  const r = await api('/api/applications', {
    requestId: `SEQ-${i}`, aggregatorId: 'AGG-A',
    event: { eventId: `EV-S${i}`, region: 'RG-EAST', startMs: st.now + 120 * 60000 },
    deviceIds: ['GFD-1'],
  });
  seqIds.push(r.batch.batchId);
}
const list = await api('/api/batches', null, 'GET');
const seqBatches = list.batches.filter((b) => b.requestId.startsWith('SEQ-'));
check('6 条申请严格按调用顺序落账', seqBatches.map((b) => b.batchId).join() === seqIds.join());
const seqs = seqBatches.map((b) => b.recordSeq);
check('recordSeq 单调递增', seqs.join() === [...seqs].sort((a, b) => a - b).join());

console.log('场景 I：真实进程重启 —— 顺序/版本链/幂等/摘要不变');
const beforeChain = (await api('/api/state', null, 'GET')).ruleChain;
const beforeDigests = list.batches.map((b) => [b.batchId, b.recordSeq, b.ruleChainTip.version, b.status]);
child = await restart(child);
check('sidecar 密钥落盘（0600 同目录）', existsSync(KEYS) && existsSync(LOG));
const st2 = await api('/api/state', null, 'GET');
check('重启后规则版本链尖一致', st2.ruleChain.version === beforeChain.version && st2.ruleChain.hash === beforeChain.hash);
const list2 = await api('/api/batches', null, 'GET');
let orderIntact = true, digestIntact = true, verifyIntact = true, frozenKept = true;
for (const [id, recSeq, tipVer, status] of beforeDigests) {
  const got = list2.batches.find((b) => b.batchId === id);
  if (!got || got.recordSeq !== recSeq || got.ruleChainTip.version !== tipVer) orderIntact = false;
  if (status === 'FROZEN' && got.status !== 'FROZEN') frozenKept = false;
  const full = await api(`/api/batches/${id}`, null, 'GET');
  if (full.batchDigest !== list.batches.find((b) => b.batchId === id).batchDigest) digestIntact = false;
  const v = await api(`/api/batches/${id}/verify`, null, 'GET');
  if (!v.valid) verifyIntact = false;
}
check('重启后批次顺序与绑定版本不变', orderIntact);
check('重启后冻结状态保留', frozenKept);
check('重启后批次摘要逐字节一致', digestIntact);
check('重启后 Ed25519 独立验签仍有效', verifyIntact);
// 幂等台账重建：重放后同号同文仍返回原批次
const replay = await api('/api/applications', {
  requestId: 'BID-A', aggregatorId: 'AGG-A',
  event: { eventId: 'EV-A', region: 'RG-EAST', startMs: inMin(20) },
  deviceIds: ['GFD-1', 'GFD-2', 'GFD-3', 'GFD-4', 'GFD-UNKNOWN'],
});
check('重启后同号重送仍返回原裁决', replay.idempotent === true && replay.batch.batchId === ba.batchId);
// 链校验
const chain = await api('/api/chain/verify', null, 'GET');
check('重启后哈希链校验通过', chain.ok === true && chain.ruleTip.version === beforeChain.version);

child.kill();
console.log(`\n结果：${pass} 通过，${fail} 失败`);
process.exit(fail ? 1 : 0);
