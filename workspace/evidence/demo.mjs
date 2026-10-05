#!/usr/bin/env node
// 证据归档模块一键演示：
//   node evidence/demo.mjs --print          输出可直接粘到网页“③ 导入”的示例信封
//   node evidence/demo.mjs                  自动拉起服务、登记网关、顺序演完全部场景并打印报告
//
// 私钥只在本进程内生成与使用；服务端只收到公钥。输出的示例信封本身不含 upload secret。
process.env.EVIDENCE_DEMO ??= '1';
const keep = process.argv.includes('--keep');
const wantPrint = process.argv.includes('--print');

const { createServer } = await import('node:http');
const { buildEnvelope, R, manifestHashOf, generateGatewayKeyPair } = await import('./pack.js');

// ---------- 场景素材（两个网关、同一作业包） ----------
const T = '2026-10-01T08:00:00Z';
const gwA = generateGatewayKeyPair();
const gwB = generateGatewayKeyPair();
const KID = 'gw-key-1';
const PKG = process.env.DEMO_PACKAGE || 'PKG-DEMO-001';

const manifest = {
  entries: [
    { seq: 0, deviceId: 'DEV-1' },
    { seq: 1, deviceId: 'DEV-2' },
    { seq: 2, deviceId: 'DEV-3' },
  ],
  issuedAt: T,
  validUntil: '2026-10-03T00:00:00Z',
};

const env01 = buildEnvelope({
  packageId: PKG, gatewayId: 'gw-A', keyId: KID, privateKeyPem: gwA.privateKeyPem,
  records: [
    R.manifest(T, manifest, manifestHashOf(manifest)),
    R.fence(T, 'fence-A', 1, 'CREATED', null, '首次领取'),
    R.segment(T, 'fence-A', 1, 1, [
      { seq: 0, deviceId: 'DEV-1', outcome: 'EXECUTED', note: '正常完成' },
      { seq: 1, deviceId: 'DEV-2', outcome: 'SKIPPED', note: null },
    ]),
    R.checkpoint(T, 'fence-A', 1, 1, { EXECUTED: 1, SKIPPED: 1, FAILED: 0 }),
  ],
});

// 与 env01 完全相同 → 重复导入返原结果
const env02 = JSON.parse(JSON.stringify(env01));

// seg2 首份（gw-B，EXECUTED）
const env03 = buildEnvelope({
  packageId: PKG, gatewayId: 'gw-B', keyId: KID, privateKeyPem: gwB.privateKeyPem,
  records: [
    R.segment('2026-10-01T09:00:00Z', 'fence-A', 1, 2, [
      { seq: 2, deviceId: 'DEV-3', outcome: 'EXECUTED', note: 'gw-B 记录' },
    ]),
  ],
});

// 同围栏同分段号、不同内容（gw-A 说 FAILED）→ 冲突隔离
const env04 = buildEnvelope({
  packageId: PKG, gatewayId: 'gw-A', keyId: KID, privateKeyPem: gwA.privateKeyPem,
  records: [
    R.segment('2026-10-01T09:05:00Z', 'fence-A', 1, 2, [
      { seq: 2, deviceId: 'DEV-3', outcome: 'FAILED', note: 'gw-A 说失败' },
    ]),
  ],
});

// 新围栏 v2 + 检查点水位推进（1 → 2，不倒退）
const env05 = buildEnvelope({
  packageId: PKG, gatewayId: 'gw-B', keyId: KID, privateKeyPem: gwB.privateKeyPem,
  records: [
    R.fence('2026-10-01T10:00:00Z', 'fence-B', 2, 'CREATED', 1, '强制移交'),
    R.segment('2026-10-01T10:10:00Z', 'fence-B', 2, 3, [
      { seq: 2, deviceId: 'DEV-3', outcome: 'EXECUTED', note: 'v2 续作' },
    ]),
    R.checkpoint('2026-10-01T10:15:00Z', 'fence-B', 2, 2, { EXECUTED: 2, SKIPPED: 1, FAILED: 0 }),
  ],
});

// v2 检查点倒退（lastSeq=0）→ CHECKPOINT_REGRESSED
const env06 = buildEnvelope({
  packageId: PKG, gatewayId: 'gw-B', keyId: KID, privateKeyPem: gwB.privateKeyPem,
  records: [
    R.checkpoint('2026-10-01T11:00:00Z', 'fence-B', 2, 0, { EXECUTED: 0, SKIPPED: 0, FAILED: 0 }),
  ],
});

// 关 v2、开 v3
const env07 = buildEnvelope({
  packageId: PKG, gatewayId: 'gw-A', keyId: KID, privateKeyPem: gwA.privateKeyPem,
  records: [
    R.fence('2026-10-01T12:00:00Z', 'fence-B', 2, 'CLOSED', 1, 'v2 完成关闭'),
    R.fence('2026-10-01T12:05:00Z', 'fence-C', 3, 'CREATED', 2, '再次移交'),
  ],
});

// 篡改：改分段结果但不重算 hash
const envTampered = JSON.parse(JSON.stringify(env01));
envTampered.records[2].entries[0].outcome = 'FAILED';

// 错签名：他网私钥代签（同内容、同 envelopeHash）
const envWrongSigner = buildEnvelope({
  packageId: PKG, gatewayId: 'gw-A', keyId: KID, privateKeyPem: gwB.privateKeyPem,
  records: env01.records,
});

const scenarios = [
  ['01-首封有效证据（清单+v1 围栏+seg1+检查点）', env01],
  ['02-同一信封再次导入（重复→原结果）', env02],
  ['03-seg2 首份 gw-B（EXECUTED）', env03],
  ['04-seg2 异内容 gw-A（FAILED→冲突隔离）', env04],
  ['05-v2 新围栏 + 水位推进到 2', env05],
  ['06-v2 检查点倒退 lastSeq=0（隔离）', env06],
  ['07-关闭 v2、开启 v3', env07],
  ['08-篡改内容不重算哈希（ENVELOPE_HASH_MISMATCH）', envTampered],
  ['09-他网私钥代签（SIGNATURE_INVALID）', envWrongSigner],
];

if (wantPrint) {
  // 只打印信封 + 网关公钥（网页先注册网关，再逐个粘贴信封）。
  const gateways = [
    { gatewayId: 'gw-A', keyId: KID, publicKeyPem: gwA.publicKeyPem },
    { gatewayId: 'gw-B', keyId: KID, publicKeyPem: gwB.publicKeyPem },
  ];
  console.log(JSON.stringify({
    说明: '先在页面 ② 用下面 gateways 注册公钥，再在 ③ 依次导入 envelopes',
    gateways,
    envelopes: Object.fromEntries(scenarios.map(([name, env]) => [name, env])),
  }, null, 2));
  process.exit(0);
}

// ---------- 自动演全场景 ----------
const { createApp } = await import('./server.js');
const probe = createServer();
await new Promise((r) => probe.listen(0, '127.0.0.1', r));
const port = probe.address().port;
await new Promise((r) => probe.close(r));

const app = await createApp({ port });
const actualPort = await app.start();
const BASE = `http://127.0.0.1:${actualPort}`;
const SECRET = app.uploadSecret;

async function call(path, body, method = 'POST') {
  const res = await fetch(BASE + path, {
    method,
    headers: {
      'Content-Type': 'application/json',
      'X-Upload-Secret': SECRET,
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return { status: res.status, json: await res.json() };
}

console.log(`服务已启动: ${BASE}/  （演示结束${keep ? '保持运行' : '自动停止'}）`);
console.log('先在浏览器打开页面，在 ① 填入 upload secret（下方），在 ② 注册两个网关：\n');
console.log('X-Upload-Secret =', SECRET);
console.log('网关公钥（gw-A / gw-B）请运行：node evidence/demo.mjs --print 查看（复制到页面 ②）\n');

await call('/api/gateways', { gatewayId: 'gw-A', keyId: KID, publicKeyPem: gwA.publicKeyPem });
await call('/api/gateways', { gatewayId: 'gw-B', keyId: KID, publicKeyPem: gwB.publicKeyPem });

for (const [name, env] of scenarios) {
  const r = await call(`/api/packages/${PKG}/import`, env);
  let summary;
  if (r.status >= 400) summary = `拒绝 ${r.json.code}`;
  else if (r.json.duplicate) summary = `重复导入 → 原结果(${r.json.disposition.result})`;
  else summary = `${r.json.result}（接受 ${r.json.disposition.recordsAccepted} / 重复 ${r.json.disposition.recordsDuplicate} / 冲突 ${r.json.disposition.recordsConflicted}）`;
  console.log(`• ${name}\n    → HTTP ${r.status} ${summary}`);
}

const report = await (await fetch(`${BASE}/api/packages/${PKG}/report`)).json();
console.log('\n核验报告摘要:', report.reportDigest);
console.log('当前围栏:', report.currentFence ? `v${report.currentFence.version}（${report.currentFence.closed ? '已关闭' : '活动'}）` : '无');
console.log('当前检查点:', report.currentProgress
  ? `fence v${report.currentProgress.fenceVersion} lastSeq=${report.currentProgress.lastSeq}${report.currentProgress.carried ? '（沿用旧围栏，不倒退）' : ''}`
  : '无');
console.log('冲突隔离:', report.conflicts.length, '条 →', report.conflicts.map((c) => c.reason).join(', '));

// ---------- ⑩ 证据保全与到期销毁演示（独立作业包，不影响上面 9 个场景） ----------
const DST = `PKG-DEMO-DST-${Date.now().toString(36)}`;
console.log(`\n⑩ 证据保全与到期销毁（演示包 ${DST}）`);
const dstManifest = { entries: [{ seq: 0, deviceId: 'DEV-9' }], issuedAt: T, validUntil: null };
await call(`/api/packages/${DST}/import`, buildEnvelope({
  packageId: DST, gatewayId: 'gw-A', keyId: KID, privateKeyPem: gwA.privateKeyPem,
  records: [
    R.manifest(T, dstManifest, manifestHashOf(dstManifest)),
    R.fence(T, 'fence-D', 1, 'CREATED'),
    R.segment(T, 'fence-D', 1, 1, [{ seq: 0, deviceId: 'DEV-9', outcome: 'EXECUTED' }]),
  ],
}));
const past = new Date(Date.now() - 5000).toISOString();
const future = new Date(Date.now() + 3600_000).toISOString();
await call(`/api/packages/${DST}/retention`, { requestId: 'demo-ret-1', retainUntil: future, setBy: 'ops-demo' });
console.log('• 设置保留期限（1 小时后到期）');
const h1 = await call(`/api/packages/${DST}/holds`, { requestId: 'demo-hold-1', caseNo: 'CASE-DEMO-001', reason: '监管稽查', auditor: 'auditor-1' });
const h2 = await call(`/api/packages/${DST}/holds`, { requestId: 'demo-hold-2', caseNo: 'CASE-DEMO-002', reason: '民事诉讼', auditor: 'auditor-2' });
console.log(`• 发起两个保全：${h1.json.holdId}（CASE-DEMO-001）、${h2.json.holdId}（CASE-DEMO-002）`);
const blocked = await call(`/api/packages/${DST}/destroy`, { requestedBy: 'ops-demo' });
console.log(`• 保全中销毁 → HTTP ${blocked.status} ${blocked.json.code}（有效保全 ${blocked.json.details?.activeHolds?.length} 个）`);
const wrongCase = await call(`/api/packages/${DST}/holds/${h1.json.holdId}/release`, { requestId: 'demo-rel-0', caseNo: 'CASE-WRONG' });
console.log(`• 错误案件号解除 → HTTP ${wrongCase.status} ${wrongCase.json.code}`);
await call(`/api/packages/${DST}/holds/${h1.json.holdId}/release`, { requestId: 'demo-rel-1', caseNo: 'CASE-DEMO-001', releasedBy: 'auditor-1' });
const concurrent = await call(`/api/packages/${DST}/holds/${h1.json.holdId}/release`, { requestId: 'demo-rel-2', caseNo: 'CASE-DEMO-001' });
console.log(`• 并发解除同一保全 → HTTP ${concurrent.status} ${concurrent.json.code}（安全失败）`);
await call(`/api/packages/${DST}/holds/${h2.json.holdId}/release`, { requestId: 'demo-rel-3', caseNo: 'CASE-DEMO-002', releasedBy: 'auditor-2' });
await call(`/api/packages/${DST}/retention`, { requestId: 'demo-ret-2', retainUntil: past, setBy: 'ops-demo' });
console.log('• 全部解除 + 期限届满 → 执行销毁');
const dst = await call(`/api/packages/${DST}/destroy`, { requestedBy: 'ops-demo', reason: '期限届满' });
const receipt = dst.json.receipt;
console.log(`  → 回执 ${receipt.receiptId}（覆盖：链 ${receipt.removed.chains} · 冲突材料 ${receipt.removed.conflictMaterials} · 凭据旁车 ${receipt.removed.credentialSidecars} · 共 ${receipt.removed.totalFiles} 文件）`);
const again = await call(`/api/packages/${DST}/destroy`, { requestedBy: 'ops-demo' });
console.log(`• 重复执行 → 同一回执 ${again.json.receipt.receiptId === receipt.receiptId}（不生成第二份）`);
const gone = await fetch(`${BASE}/api/packages/${DST}/report`);
console.log(`• 销毁后读报告 → HTTP ${gone.status}（统一已销毁，无部分删除）`);
const verify = await (await fetch(`${BASE}/api/destructions/${receipt.receiptId}/verify`)).json();
console.log(`• 回执验签 → ok=${verify.ok}（${Object.entries(verify.checks).map(([k, v]) => `${k}=${v}`).join(' ')}）`);

console.log(`\n打开 ${BASE}/ 选择 ${PKG} 查看时间线/冲突/下载报告（TXT/JSON/HTML，均已脱敏）`);
console.log(`页面底部 ⑥ 可查看 ${DST} 的销毁回执并验签（公钥：GET /api/destructions/key）`);

if (!keep) {
  setTimeout(() => process.exit(0), 300);
}
