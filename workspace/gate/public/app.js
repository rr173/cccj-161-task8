/* 灵活负荷资格闸调度台前端（零依赖，原生 fetch/DOM）。 */
'use strict';

const $ = (id) => document.getElementById(id);
let STATE = null;

async function api(method, path, body) {
  const opt = { method, headers: {} };
  if (body !== undefined) {
    opt.headers['Content-Type'] = 'application/json';
    opt.body = JSON.stringify(body);
  }
  const res = await fetch(path, opt);
  const text = await res.text();
  let data;
  try { data = text ? JSON.parse(text) : {}; } catch { data = { raw: text }; }
  if (!res.ok) {
    const e = new Error(data.error || `HTTP ${res.status}`);
    e.status = res.status;
    e.code = data.code;
    e.data = data;
    throw e;
  }
  return data;
}

function esc(s) {
  return String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
}

function showOut(id, obj, isErr = false) {
  const el = $(id);
  el.classList.toggle('err', isErr);
  el.textContent = typeof obj === 'string' ? obj : JSON.stringify(obj, null, 2);
}

function parseIds(text) {
  return String(text || '')
    .split(/[\s,，;；]+/)
    .map((s) => s.trim())
    .filter(Boolean)
    .map((deviceId, i) => ({ deviceId, bidKw: null }));
}

// ---------------- 导航 ----------------
document.querySelectorAll('#nav button').forEach((b) => {
  b.onclick = () => {
    document.querySelectorAll('#nav button').forEach((x) => x.classList.remove('active'));
    document.querySelectorAll('.tab').forEach((x) => x.classList.remove('active'));
    b.classList.add('active');
    $('tab-' + b.dataset.tab).classList.add('active');
    refreshTab(b.dataset.tab);
  };
});

function refreshTab(tab) {
  if (tab === 'review') loadReviewSelectors();
  if (tab === 'download') loadDownloadSelectors();
  if (tab === 'verify') loadVerifySelectors();
  if (tab === 'ledger') loadLedger();
}

// ---------------- 时钟 / 状态 ----------------
async function tick(minutes) {
  await api('POST', '/api/sim/tick', { minutes });
  await loadState();
}

async function doReset() {
  if (!confirm('复位账本并重建确定性种子？所有演示数据将被清空。')) return;
  await api('POST', '/api/sim/reset', {});
  await loadState();
}

async function loadState() {
  STATE = await api('GET', '/api/state');
  $('clock').textContent = STATE.now;
  const b = $('banner');
  if (!STATE.chain.writable) {
    b.classList.add('show');
    b.textContent = `⛔ 账本只读隔离：${STATE.chain.reason || ''}（seq=${STATE.chain.brokenAt ?? '?'}），所有写入将返回 503`;
  } else {
    b.classList.remove('show');
  }
  renderRules();
  renderEventSelects();
  renderFrozen();
  renderChainMeta();
}

function phaseTag(p) {
  const map = { ACTIVE: ['ok', '生效中'], PENDING: ['warn', '定时未生效'], EXPIRED: ['info', '已过期'], REVOKED: ['bad', '已撤销'] };
  const [cls, label] = map[p] || ['info', p];
  return `<span class="tag ${cls}">${label}</span>`;
}

// ---------------- ① 规则 ----------------
function renderRules() {
  const tb = $('rules-table').querySelector('tbody');
  tb.innerHTML = STATE.rules.map((r) => {
    const cur = r.current;
    const scope = cur ? `${cur.scope.region}${cur.scope.deviceId ? '/' + cur.scope.deviceId : '/(全区)'}` : '—';
    const win = cur ? `${cur.effectiveFrom} → ${cur.effectiveTo || '长期'}` : '—';
    const chain = r.versions.map((v) =>
      `v${v.version}${v.rolledBackFrom ? `(回滚自v${v.rolledBackFrom})` : ''}${v.status === 'REVOKED' ? '(撤)' : ''}`).join(' → ');
    const hashes = r.versions.map((v) => `<div class="mono">v${v.version}: ${v.versionHash.slice(0, 16)}…</div>`).join('');
    return `<tr>
      <td><b>${esc(r.ruleId)}</b></td>
      <td>${esc(scope)}</td>
      <td>${esc(win)}</td>
      <td>${cur ? cur.minLeadMinutes + ' 分' : '—'}</td>
      <td>${cur ? (cur.mutexTags || []).map((t) => `<span class="tag violet">${esc(t)}</span>`).join('') || '—' : '—'}</td>
      <td>${cur ? cur.priority : '—'}</td>
      <td>${cur ? 'v' + cur.version : '—'}</td>
      <td>${cur ? phaseTag(cur.phase) : phaseTag('REVOKED')}</td>
      <td class="mono">${esc(chain)}</td>
      <td>${hashes}</td>
    </tr>`;
  }).join('');
}

function rulePayload(force) {
  const tags = $('r-mutex').value.split(/[,，]/).map((s) => s.trim()).filter(Boolean);
  const p = {
    scope: { region: $('r-region').value.trim(), deviceId: $('r-deviceId').value.trim() || null },
    effectiveFrom: $('r-from').value,
    effectiveTo: $('r-to').value || null,
    minLeadMinutes: Number($('r-lead').value),
    priority: Number($('r-priority').value),
    mutexTags: tags,
    note: $('r-note').value || null,
    by: $('r-by').value || null,
    forceOverlap: !!force,
  };
  const ruleId = $('r-ruleId').value.trim();
  if (ruleId) p.ruleId = ruleId;
  const exp = $('r-expected').value.trim();
  if (exp) p.expectedVersion = exp;
  return p;
}

async function publishRule(force = false) {
  try {
    const out = await api('POST', '/api/rules', rulePayload(force));
    showOut('r-out', {
      published: out.rule.ruleId + ' v' + out.rule.currentVersion,
      revived: out.revived,
      ambiguous: out.ambiguous, advisory: out.advisory, forced: out.forced,
    });
    await loadState();
  } catch (e) {
    showOut('r-out', `[${e.status} ${e.code || ''}] ${e.message}\n` + (e.data?.details ? JSON.stringify(e.data.details, null, 2) : ''), true);
  }
}
async function forcePublish() { return publishRule(true); }

async function revokeRule() {
  try {
    const out = await api('POST', `/api/rules/${encodeURIComponent($('rr-ruleId').value.trim())}/revoke`, {
      expectedVersion: $('rr-expected').value || null,
      reason: $('rr-reason').value || null,
      by: $('rr-by').value || null,
    });
    showOut('rr-out', out);
    await loadState();
  } catch (e) { showOut('rr-out', `[${e.status} ${e.code || ''}] ${e.message}`, true); }
}

async function rollbackRule() {
  try {
    const out = await api('POST', `/api/rules/${encodeURIComponent($('rr-ruleId').value.trim())}/rollback`, {
      expectedVersion: $('rr-expected').value || null,
      targetVersion: Number($('rr-target').value),
      reason: $('rr-reason').value || null,
      by: $('rr-by').value || null,
    });
    showOut('rr-out', {
      rolledBack: out.ruleId,
      fromVersion: out.rolledBackFrom,
      newVersion: out.newVersion.currentVersion,
      newVersionHash: out.newVersion.current.versionHash,
    });
    await loadState();
  } catch (e) { showOut('rr-out', `[${e.status} ${e.code || ''}] ${e.message}`, true); }
}

async function setDevice(suspend) {
  const id = $('rr-device').value.trim();
  try {
    const path = `/api/devices/${encodeURIComponent(id)}/${suspend ? 'suspend' : 'resume'}`;
    const out = await api('POST', path, { reason: $('rr-devreason').value || null });
    showOut('rr-out', out);
    await loadState();
  } catch (e) { showOut('rr-out', `[${e.status} ${e.code || ''}] ${e.message}`, true); }
}

// ---------------- 事件下拉 ----------------
function renderEventSelects() {
  const opts = STATE.events.map((e) =>
    `<option value="${esc(e.eventId)}">${esc(e.eventId)} · ${esc(e.region)} · ${esc(e.date)} · ${esc(e.startIso)}</option>`).join('');
  for (const id of ['t-event', 'a-event']) {
    const cur = $(id).value;
    $(id).innerHTML = opts;
    if (cur) $(id).value = cur;
  }
}

// ---------------- ② 试算 ----------------
async function runTrial() {
  let atMs;
  const at = $('t-at').value;
  if (at) atMs = new Date(at).getTime();
  try {
    const out = await api('POST', '/api/trial', {
      eventId: $('t-event').value,
      atMs,
      items: parseIds($('t-devices').value),
    });
    $('t-out').classList.remove('err');
    $('t-out').textContent = `试算时刻 ${out.evaluatedAt}：${out.count} 台，准入 ${out.admitted}，拒绝 ${out.count - out.admitted}`;
    $('trial-table').querySelector('tbody').innerHTML = out.decisions.map((d) => `<tr>
      <td>${d.ordinal + 1}</td>
      <td>${esc(d.deviceId)} ${d.known ? '' : '<span class="tag bad">未知</span>'}</td>
      <td>${esc(d.deviceRegion || '—')}</td>
      <td>${outcomeTag(d.outcome)}</td>
      <td>${reasonsHtml(d.reasons)}</td>
      <td>${d.rule ? `${esc(d.rule.ruleId)} v${d.rule.version}` : '—'}</td>
    </tr>`).join('');
  } catch (e) {
    showOut('t-out', `[${e.status} ${e.code || ''}] ${e.message}`, true);
  }
}

// ---------------- ③ 申请 ----------------
async function submitApp(empty = false) {
  if (!$('a-no').value.trim()) {
    $('a-no').value = 'APP-' + Date.now().toString(36).toUpperCase();
  }
  try {
    const out = await api('POST', '/api/applications', {
      applicationNo: $('a-no').value.trim(),
      eventId: $('a-event').value,
      aggregatorId: $('a-agg').value.trim(),
      items: empty ? [] : parseIds($('a-devices').value),
    });
    renderApplication(out.application, out.idempotent);
    showOut('a-out', out.idempotent
      ? `幂等重送：返回 seq=${out.application.seq} 的原裁决（未重算、未新增记录）`
      : `已落账：seq=${out.application.seq}，密钥 ${out.application.keyId}`);
    await loadState();
    renderApplication(out.application, out.idempotent);
  } catch (e) {
    showOut('a-out', `[${e.status} ${e.code || ''}] ${e.message}\n${e.data?.details ? JSON.stringify(e.data.details, null, 2) : ''}`, true);
  }
}
async function submitEmpty() { return submitApp(true); }

function outcomeTag(o) {
  return o === 'ADMITTED'
    ? '<span class="tag ok">准入</span>'
    : '<span class="tag bad">拒绝</span>';
}
function reasonsHtml(reasons) {
  if (!reasons || !reasons.length) return '<span class="tag ok">—</span>';
  return reasons.map((r) => `<div class="reason"><span class="rcode">${esc(r.code)}</span> ${esc(r.message)}</div>`).join('');
}

function renderApplication(app, idempotent) {
  $('a-meta').innerHTML = `
    <div>申请号 <b>${esc(app.applicationNo)}</b> · 事件 <b>${esc(app.eventId)}</b> · 聚合商 <b>${esc(app.aggregatorId)}</b></div>
    <div>落账 seq=<b>${app.seq}</b> · 裁决时刻 <b>${esc(app.decidedAt)}</b> · 密钥 <b>${esc(app.keyId)}</b>${idempotent ? ' · <span class="tag info">幂等原裁决</span>' : ''}</div>
    <div class="mono">bodyHash=${esc(app.bodyHash)}</div>
    <div>共 ${app.counts.total} 台：<span class="tag ok">准入 ${app.counts.admitted}</span> <span class="tag bad">拒绝 ${app.counts.rejected}</span>${app.frozen ? ' <span class="tag violet">已冻结</span>' : ''}</div>`;
  $('app-table').querySelector('tbody').innerHTML = app.decisions.map((d) => `<tr>
    <td>${d.ordinal + 1}</td>
    <td>${esc(d.deviceId)}</td>
    <td>${outcomeTag(d.outcome)}</td>
    <td>${reasonsHtml(d.reasons)}</td>
    <td>${d.rule ? `${esc(d.rule.ruleId)} <b>v${d.rule.version}</b><div class="mono">${esc(d.rule.versionHash.slice(0, 20))}…</div>` : '—'}</td>
    <td><details><summary>${esc(d.decisionDigest.slice(0, 12))}…</summary><div class="sigbox">${esc(d.signature)}</div></details></td>
  </tr>`).join('');
}

// ---------------- ④ 复核 / 冻结 ----------------
async function loadReviewSelectors() {
  const opts = STATE.applications.map((a) =>
    `<option value="${esc(a.applicationNo)}">${esc(a.applicationNo)} · seq ${a.seq} · ${a.counts.admitted}/${a.counts.total} 准入${a.frozen ? ' · 已冻结' : ''}</option>`).join('');
  $('rv-app').innerHTML = opts;
  $('fz-app').innerHTML = opts;
  loadReviewApp();
}

async function loadReviewApp() {
  const no = $('rv-app').value;
  if (!no) return;
  const app = await api('GET', `/api/applications/${encodeURIComponent(no)}`);
  $('rv-items').innerHTML = app.decisions.map((d) => {
    const reviewed = !!d.review;
    return `<div style="border-top:1px solid var(--line);padding:8px 0">
      <div><b>${esc(d.deviceId)}</b> ${outcomeTag(d.outcome)} ${reasonsHtml(d.reasons)}</div>
      <div class="row" style="margin-top:4px">
        <div style="flex:2"><input id="note-${esc(d.deviceId)}" placeholder="复核备注" value="${esc(d.review?.note || '')}" ${reviewed || app.frozen ? 'disabled' : ''} /></div>
        <div style="max-width:130px"><button class="act ${reviewed ? '' : 'ghost'}" id="btn-c-${esc(d.deviceId)}" ${reviewed || app.frozen ? 'disabled' : ''}>维持</button></div>
        <div style="max-width:130px"><button class="act warn" id="btn-o-${esc(d.deviceId)}" ${reviewed || app.frozen ? 'disabled' : ''}>异议</button></div>
      </div>
      <div class="kv">${d.review
        ? `已复核 #${d.review.reviewSeq}：<b>${d.review.disposition === 'CONFIRMED' ? '维持初裁' : '标注异议'}</b> by ${esc(d.review.reviewer)} @ ${esc(d.review.at)}`
        : (app.frozen ? '批次已冻结，不可复核' : '未复核')}</div>
    </div>`;
  }).join('') || '<div class="hint">（空批次，无设备可复核）</div>';
  app.decisions.forEach((d) => {
    const c = $('btn-c-' + d.deviceId);
    const o = $('btn-o-' + d.deviceId);
    if (c) c.onclick = () => reviewItem(no, d.deviceId, 'CONFIRMED');
    if (o) o.onclick = () => reviewItem(no, d.deviceId, 'OVERRULED');
  });
}

async function reviewItem(no, deviceId, disposition) {
  try {
    await api('POST', `/api/applications/${encodeURIComponent(no)}/items/${encodeURIComponent(deviceId)}/review`, {
      reviewer: $('rv-by').value || 'reviewer',
      disposition,
      note: $('note-' + deviceId).value || null,
    });
    await loadState();
    await loadReviewApp();
  } catch (e) { alert(`[${e.status} ${e.code || ''}] ${e.message}`); }
}

async function freezeApp() {
  const no = $('fz-app').value;
  try {
    const out = await api('POST', `/api/applications/${encodeURIComponent(no)}/freeze`, { by: $('fz-by').value || null });
    showOut('fz-out', {
      idempotent: out.idempotent,
      frozenAt: out.frozen.at,
      manifestDigest: out.frozen.manifestDigest,
      keyId: out.frozen.keyId,
      signature: out.frozen.signature,
    });
    await loadState();
  } catch (e) { showOut('fz-out', `[${e.status} ${e.code || ''}] ${e.message}`, true); }
}

function renderFrozen() {
  const rows = STATE.applications.filter((a) => a.frozen).map((a) => `<tr>
    <td>${esc(a.applicationNo)}</td><td>${esc(a.eventId)}</td>
    <td>${esc(a.frozen.at)}</td><td class="mono">${esc(a.frozen.manifestDigest.slice(0, 20))}…</td>
    <td>${esc(a.frozen.keyId)}</td></tr>`).join('');
  $('frozen-table').querySelector('tbody').innerHTML = rows || '<tr><td colspan="5" class="hint">暂无已冻结批次</td></tr>';
}

// ---------------- ⑤ 下载 ----------------
async function loadDownloadSelectors() {
  $('dl-app').innerHTML = STATE.applications.map((a) =>
    `<option value="${esc(a.applicationNo)}">${esc(a.applicationNo)} ${a.frozen ? '· 已冻结' : '· 未冻结'}</option>`).join('');
  $('dl-preview').textContent = '';
}

async function downloadCsv() {
  const no = $('dl-app').value;
  const res = await fetch(`/api/applications/${encodeURIComponent(no)}/redacted.csv`);
  const text = await res.text();
  if (!res.ok) {
    let data; try { data = JSON.parse(text); } catch { data = { error: text }; }
    $('dl-preview').classList.add('err');
    $('dl-preview').textContent = `[${res.status}] ${data.error || ''} ${data.code || ''}`;
    return;
  }
  $('dl-preview').classList.remove('err');
  $('dl-preview').textContent = text;
  const blob = new Blob(['﻿', text], { type: 'text/csv;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `gate-${no}-redacted.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

// ---------------- ⑥ 验签 ----------------
async function loadVerifySelectors() {
  $('vf-app').innerHTML = STATE.applications.map((a) =>
    `<option value="${esc(a.applicationNo)}">${esc(a.applicationNo)}${a.frozen ? ' · 已冻结' : ''}</option>`).join('');
  fillVfDevices();
}

async function fillVfDevices() {
  const no = $('vf-app').value;
  if (!no) return;
  try {
    const app = await api('GET', `/api/applications/${encodeURIComponent(no)}`);
    $('vf-device').innerHTML = app.decisions.map((d) =>
      `<option value="${esc(d.deviceId)}">${esc(d.deviceId)} · ${d.outcome}</option>`).join('');
  } catch { /* ignore */ }
}

async function verifyDecisionWeb() {
  const no = $('vf-app').value;
  const dev = $('vf-device').value;
  try {
    const v = await api('GET', `/api/applications/${encodeURIComponent(no)}/items/${encodeURIComponent(dev)}/verify`);
    showOut('vf-out', {
      kind: v.kind, keyId: v.keyId,
      digestMatches: v.digestMatches,
      signatureValid: v.valid,
      storedDigest: v.storedDigest,
      recomputedDigest: v.digest,
      canonical: v.canonical,
      signature: v.signature,
      publicKeyPem: v.publicKeyPem,
    });
  } catch (e) { showOut('vf-out', `[${e.status} ${e.code || ''}] ${e.message}`, true); }
}

async function verifyManifestWeb() {
  const no = $('vf-app').value;
  try {
    const v = await api('GET', `/api/applications/${encodeURIComponent(no)}/manifest/verify`);
    showOut('vf-out', {
      kind: v.kind, keyId: v.keyId,
      digestMatches: v.digestMatches,
      signatureValid: v.valid,
      storedDigest: v.storedDigest,
      recomputedDigest: v.digest,
      canonical: v.canonical,
      signature: v.signature,
      publicKeyPem: v.publicKeyPem,
    });
  } catch (e) { showOut('vf-out', `[${e.status} ${e.code || ''}] ${e.message}`, true); }
}

async function verifyOfflineWeb() {
  try {
    const body = {
      keyId: $('vo-keyid').value || null,
      publicKeyPem: $('vo-pem').value || null,
      canonical: $('vo-canonical').value,
      signature: $('vo-sig').value.trim(),
    };
    const v = await api('POST', '/api/verify', body);
    showOut('vo-out', { signatureValid: v.valid, digest: v.digest });
  } catch (e) { showOut('vo-out', `[${e.status} ${e.code || ''}] ${e.message}`, true); }
}

// ---------------- ⑦ 账本 ----------------
async function rotateKey() {
  try {
    const out = await api('POST', '/api/keys/rotate', { by: 'dispatch-01' });
    alert(`已轮换到 ${out.keyId}（第 ${out.totalKeys} 把）；历史批次仍用各自 keyId 复验。`);
    await loadState();
    await loadLedger();
  } catch (e) { alert(`[${e.status} ${e.code || ''}] ${e.message}`); }
}

async function loadLedger() {
  const v = STATE.chain;
  $('chain-meta').innerHTML = `
    <div class="kv">模式：${v.ok ? '<span class="tag ok">OK 可写</span>' : '<span class="tag bad">QUARANTINED 只读</span>'}</div>
    <div class="kv">记录数：<b>${v.length}</b></div>
    <div class="mono" style="margin:6px 0">链尖：${esc(v.tipHash)}</div>
    ${v.recovery ? `<div class="reason">恢复：${esc(v.recovery.reason || JSON.stringify(v.recovery))}</div>` : ''}`;
  $('keys-list').innerHTML = STATE.keys.map((k) =>
    `<details style="margin:6px 0"><summary><b>${esc(k.keyId)}</b> <span class="tag ${k.canSign ? 'ok' : 'warn'}">${k.canSign ? '可签发' : '仅公钥'}</span> ${esc(k.rotatedAt)}</summary>
      <pre class="mono" style="white-space:pre-wrap">${esc(k.publicKeyPem)}</pre></details>`).join('');

  const types = ['APPLICATION_ACCEPTED', 'RULE_VERSION_PUBLISHED', 'RULE_VERSION_REVOKED', 'RULE_ROLLED_BACK',
    'BATCH_FROZEN', 'ITEM_REVIEWED', 'DEVICE_SUSPENDED', 'DEVICE_RESUMED', 'GATE_KEY_PUBLISHED',
    'SEED_DEVICE', 'SEED_EVENT', 'SEED_RULE', 'SIM_TICK'];
  $('lg-type').innerHTML = '<option value="">全部</option>' + types.map((t) => `<option>${t}</option>`).join('');
  renderLog();
}

async function renderLog() {
  const type = $('lg-type').value;
  const limit = Number($('lg-limit').value || 100);
  const q = new URLSearchParams();
  if (type) q.set('type', type);
  q.set('limit', limit);
  const { records } = await api('GET', '/api/log?' + q);
  $('log-table').querySelector('tbody').innerHTML = records.map((r) => {
    let brief = '';
    if (r.type === 'APPLICATION_ACCEPTED') {
      brief = `${r.payload.applicationNo} → ${r.payload.counts.admitted}/${r.payload.counts.total}`;
    } else if (r.type.startsWith('RULE') || r.type === 'SEED_RULE') {
      const v = r.payload.version || r.payload;
      brief = `${v.ruleId || r.payload.ruleId} v${v.version ?? r.payload.version}${r.type === 'RULE_VERSION_REVOKED' ? ' 撤销' : ''}`;
    } else if (r.type === 'BATCH_FROZEN') {
      brief = `${r.payload.applicationNo} ${r.payload.manifestDigest.slice(0, 12)}…`;
    } else if (r.type === 'ITEM_REVIEWED') {
      brief = `${r.payload.applicationNo}/${r.payload.deviceId} ${r.payload.disposition}`;
    } else {
      brief = JSON.stringify(r.payload).slice(0, 80);
    }
    return `<tr>
      <td>${r.seq}</td><td class="mono">${esc((r.ts || '').replace('T', ' ').replace('.000Z', 'Z'))}</td>
      <td><span class="tag info">${esc(r.type)}</span></td>
      <td class="mono">${esc(brief)}</td>
      <td class="mono">${esc(r.hash.slice(0, 14))}…</td>
    </tr>`;
  }).join('');
}

loadState().catch((e) => {
  $('banner').classList.add('show');
  $('banner').textContent = '加载状态失败：' + e.message;
});
