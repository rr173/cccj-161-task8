// 灵活负荷资格闸 · 运营台前端逻辑（零依赖原生 JS）。
let S = null;
let selectedBatch = null;

async function api(path, body, method = 'POST') {
  const res = await fetch(path, {
    method,
    headers: body ? { 'Content-Type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw Object.assign(new Error(data.error || path), { code: data.code, details: data.details, status: res.status });
  return data;
}
const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
const short = (h) => h ? `${String(h).slice(0, 10)}…` : '—';
function toast(msg, kind = '') {
  const t = document.createElement('div');
  t.className = `toast ${kind}`;
  t.textContent = msg;
  $('toasts').appendChild(t);
  setTimeout(() => t.remove(), 4200);
}
function list(v) {
  return String(v || '').split(',').map((x) => x.trim()).filter(Boolean);
}
function todayPlus(days) {
  return new Date(S.now + days * 86400000).toISOString().slice(0, 10);
}

async function refresh() {
  S = await api('/api/state', null, 'GET');
  render();
}

function render() {
  $('clock').textContent = S.nowIso.replace('T', ' ').slice(0, 16) + ' UTC';
  const chain = S.chain || {};
  $('chainBadge').innerHTML = chain.ok
    ? `<span class="ok-txt">链完整</span> <span class="muted mono">v${S.ruleChain.version}</span>`
    : `<span class="bad-txt">链隔离 ${chain.brokenAt ?? ''}</span>`;

  // 设备
  $('deviceList').innerHTML = S.devices.map((d) => `
    <div class="card">
      <div class="row">
        <b>${esc(d.deviceId)}</b>
        <span class="pill">${esc(d.region)}</span>
        ${d.suspended ? '<span class="tag REJECTED">已暂停</span>' : '<span class="tag APPROVED">在册</span>'}
        <span class="spacer" style="flex:1"></span>
        <button class="ghost" onclick="toggleSuspend('${esc(d.deviceId)}',${d.suspended})">${d.suspended ? '恢复' : '暂停'}</button>
      </div>
      <div class="muted">${esc(d.name)} · 标签 ${d.tags.map(esc).join(', ') || '—'}</div>
    </div>`).join('');

  const regions = S.regions.map((r) => `<option value="${esc(r.code)}">${esc(r.code)} ${esc(r.name)}</option>`).join('');
  ['ndRegion', 'tRegion', 'tDRRegion', 'aRegion'].forEach((id) => { $(id).innerHTML = regions; });
  const devOpts = '<option value="">— 地区默认 —</option>' +
    S.devices.map((d) => `<option value="${esc(d.deviceId)}">${esc(d.deviceId)} (${esc(d.region)})</option>`).join('');
  $('rDevice').innerHTML = devOpts;
  $('aAgg').innerHTML = S.aggregators.map((a) => `<option value="${esc(a.id)}">${esc(a.id)} ${esc(a.name)}</option>`).join('');

  // 规则版本链
  $('ruleChainTip').textContent = `规则版本链尖：v${S.ruleChain.version}  ${short(S.ruleChain.hash)}（共 ${S.ruleChain.length} 条规则变动）`;
  $('ruleList').innerHTML = S.rules.map((r) => `
    <div class="card">
      <div class="row">
        <b>${esc(r.ruleId)}</b>
        <span class="tag ${r.lifecycle}">${r.lifecycle}</span>
        <span class="pill mono">全局v${r.version} / 规则v${r.ruleVersion}</span>
        ${r.restoredFromVersion ? `<span class="pill">回滚自v${r.restoredFromVersion}</span>` : ''}
        <span class="spacer" style="flex:1"></span>
        <button class="ghost" onclick="revokeRule('${esc(r.ruleId)}')">撤销</button>
        <button class="ghost" onclick="rollbackRule(${r.version})">回滚到此版</button>
      </div>
      <div class="muted">
        作用域 ${r.scope.deviceId ? '设备 ' + esc(r.scope.deviceId) : '地区默认'} · ${esc(r.scope.region)}　|
        ${esc(r.validFrom)} → ${esc(r.validUntil)}
      </div>
      <div class="muted">互斥标签 ${(r.body.denyTags || []).map(esc).join(', ') || '（无）'} · 最短提前期 ${r.body.minLeadMinutes} 分钟</div>
      <div class="hash">${esc(r.contentHash)}</div>
    </div>`).join('') || '<div class="muted">暂无规则</div>';

  // 批次列表
  $('batchList').innerHTML = S.batches.map((b) => `
    <div class="card ${b.batchId === selectedBatch ? 'sel' : ''}" onclick="openBatch('${esc(b.batchId)}')" style="cursor:pointer">
      <div class="row">
        <b>${esc(b.batchId)}</b>
        <span class="tag ${b.status}">${b.status}</span>
        <span class="pill">${esc(b.aggregatorId)}</span>
        <span class="spacer" style="flex:1"></span>
        <span class="muted mono">${b.counts.approved}✅ / ${b.counts.rejected}⛔ / ${b.counts.total}</span>
      </div>
      <div class="muted">申请号 ${esc(b.requestId)} · 事件 ${esc(b.event.eventId)} (${esc(b.event.region)}) · 绑定规则 v${b.ruleChainTip.version}</div>
    </div>`).join('') || '<div class="muted">尚无批次</div>';

  if (selectedBatch) openBatch(selectedBatch, true);
}

async function tick(minutes) {
  await api('/api/sim/tick', { minutes });
  await refresh();
}
async function resetAll() {
  if (!confirm('确定重置演示数据？将截断资格闸日志。')) return;
  await api('/api/sim/reset', {});
  selectedBatch = null;
  await refresh();
  toast('已重置演示数据', 'ok');
}

async function registerDevice() {
  try {
    await api('/api/devices', {
      deviceId: $('ndId').value.trim(),
      region: $('ndRegion').value,
      name: $('ndId').value.trim(),
      tags: list($('ndTags').value),
    });
    $('ndId').value = '';
    await refresh();
    toast('设备已登记', 'ok');
  } catch (e) { toast(`${e.code}: ${e.message}`, 'err'); }
}
async function toggleSuspend(deviceId, currently) {
  const reason = currently ? '' : prompt('暂停原因', '临时检修');
  if (!currently && reason === null) return;
  try {
    await api(`/api/devices/${encodeURIComponent(deviceId)}/suspend`, { suspended: !currently, reason });
    await refresh();
    toast(currently ? '设备已恢复' : '设备已暂停', 'ok');
  } catch (e) { toast(`${e.code}: ${e.message}`, 'err'); }
}

async function publishRule() {
  try {
    const body = {
      ruleId: $('rId').value.trim() || undefined,
      scope: { region: $('rRegion').value, deviceId: $('rDevice').value || null },
      body: { denyTags: list($('rDeny').value), minLeadMinutes: Number($('rLead').value || 0) },
      validFrom: $('rFrom').value || todayPlus(0),
      validUntil: $('rUntil').value || '2026-12-31',
      expectedVersion: $('rExpect').value ? Number($('rExpect').value) : undefined,
    };
    const out = await api('/api/rules', body);
    toast(`规则 ${out.rule.ruleId} 全局v${out.rule.head.version} 已写入版本链`, 'ok');
    $('rExpect').value = '';
    await refresh();
  } catch (e) { toast(`${e.code}: ${e.message}`, 'err'); }
}
async function revokeRule(ruleId) {
  const eff = prompt('撤销生效日（YYYY-MM-DD，留空=今天；未来日期=定时撤销）', todayPlus(0));
  if (eff === null) return;
  const reason = prompt('撤销原因', '运营方撤销');
  if (reason === null) return;
  try {
    await api(`/api/rules/${encodeURIComponent(ruleId)}/revoke`, { reason, effectiveFrom: eff || undefined });
    await refresh();
    toast(`规则 ${ruleId} 已撤销（生效 ${eff || '今天'}）`, 'ok');
  } catch (e) { toast(`${e.code}: ${e.message}`, 'err'); }
}
async function rollbackRule(version) {
  if (!confirm(`回滚到全局 v${version} 的规则内容，将作为该规则的新版本在版。继续？`)) return;
  try {
    const out = await api('/api/rules/rollback', { fromVersion: version });
    toast(`已回滚生成 ${out.rule.ruleId} v${out.rule.head.ruleVersion}`, 'ok');
    await refresh();
  } catch (e) { toast(`${e.code}: ${e.message}`, 'err'); }
}

async function trial() {
  try {
    const at = S.now;
    const body = {
      at,
      event: { eventId: 'TRIAL', region: $('tRegion').value, startMs: at + Number($('tLead').value) * 60000 },
      deviceIds: list($('tDevices').value),
    };
    const draftDeny = $('tDDeny').value.trim();
    const useDraft = draftDeny !== '' || $('tDLead').value !== '0';
    if (useDraft) {
      body.draftRule = {
        scope: { region: $('tDRRegion').value, deviceId: null },
        body: { denyTags: list(draftDeny), minLeadMinutes: Number($('tDLead').value || 0) },
        validFrom: todayPlus(0), validUntil: '2999-12-31',
      };
    }
    const out = await api('/api/rules/trial', body);
    $('trialOut').innerHTML = `
      <div class="muted">试算结果（不落盘）：<span class="ok-txt">${out.approved} 准入</span> · <span class="bad-txt">${out.rejected} 拒绝</span>${out.draft ? ' · 已叠加草案' : ''}</div>
      <table><thead><tr><th>#</th><th>设备</th><th>裁决</th><th>原因 / 命中规则</th></tr></thead><tbody>
      ${out.items.map((it) => `<tr>
        <td>${it.order}</td><td class="mono">${esc(it.deviceId)}</td>
        <td><span class="tag ${it.decision}">${it.decision}</span></td>
        <td>${it.reasons.map((r) => `<span class="tag reason">${r}</span>`).join('') || '—'}
            <div class="muted">${it.rule ? `${esc(it.rule.ruleId)} 全局v${it.rule.version ?? 'draft'}` : '无适用规则'}</div></td>
      </tr>`).join('')}
      </tbody></table>`;
  } catch (e) { toast(`${e.code}: ${e.message}`, 'err'); }
}

async function applyBatch() {
  const req = $('aReq').value.trim();
  if (!req) { toast('申请号 requestId 必填', 'err'); return; }
  try {
    const out = await api('/api/applications', {
      requestId: req,
      aggregatorId: $('aAgg').value,
      event: {
        eventId: $('aEventId').value.trim(),
        region: $('aRegion').value,
        startMs: S.now + Number($('aLead').value) * 60000,
      },
      deviceIds: list($('aDevices').value),
    });
    selectedBatch = out.batch.batchId;
    await refresh();
    toast(out.idempotent ? '同一申请号重送：返回原裁决（幂等）' : `批次 ${out.batch.batchId} 已落账`, out.idempotent ? '' : 'ok');
  } catch (e) { toast(`${e.code}: ${e.message}`, 'err'); }
}

async function openBatch(batchId, silent = false) {
  try {
    selectedBatch = batchId;
    const b = await api(`/api/batches/${encodeURIComponent(batchId)}`, null, 'GET');
    const v = await api(`/api/batches/${encodeURIComponent(batchId)}/verify`, null, 'GET');
    $('batchDetail').innerHTML = `
      <div class="row">
        <b>${esc(b.batchId)}</b>
        <span class="tag ${b.status}">${b.status}</span>
        <span class="spacer" style="flex:1"></span>
        ${b.status === 'OPEN'
          ? `<button class="good" onclick="freeze('${esc(b.batchId)}')">冻结批次</button>`
          : `<a class="ghost" href="/api/batches/${encodeURIComponent(b.batchId)}/redacted.csv" target="_blank"><button class="primary">下载脱敏 CSV</button></a>`}
      </div>
      <div class="muted" style="margin:6px 0">
        申请号 ${esc(b.requestId)} · ${esc(b.aggregatorId)} · 事件 ${esc(b.event.eventId)} / ${esc(b.event.region)}<br/>
        裁决时刻 ${esc(b.decidedAtIso)} · 记录序号 #${b.recordSeq} ·
        <span class="mono">${b.counts.approved}✅ ${b.counts.rejected}⛔ ${b.counts.total} 台</span>
      </div>
      <table><thead><tr><th>#</th><th>设备</th><th>裁决</th><th>拒绝原因</th><th>绑定规则版本</th></tr></thead><tbody>
      ${b.items.map((it) => `<tr>
        <td>${it.order}</td>
        <td class="mono">${esc(it.deviceId)}</td>
        <td><span class="tag ${it.decision}">${it.decision}</span></td>
        <td>${it.reasons.map((r) => `<span class="tag reason">${r}</span>`).join('') || '—'}</td>
        <td class="muted mono">${it.rule ? `${esc(it.rule.ruleId)}<br/>全局v${it.rule.version ?? '?'} / 规则v${it.rule.ruleVersion ?? '?'}` : '—'}</td>
      </tr>`).join('')}
      </tbody></table>
      <details open>
        <summary>独立验签（Ed25519 + 内容指纹 + 版本链尖）</summary>
        <div class="kv muted" style="margin-top:6px">
          <div>总体有效：<b class="${v.valid ? 'ok-txt' : 'bad-txt'}">${v.valid ? 'VALID ✓' : 'INVALID ✗'}</b></div>
          <div>签名有效：<b class="${v.signatureValid ? 'ok-txt' : 'bad-txt'}">${v.signatureValid}</b>（密钥 ${esc(v.keyId)}）</div>
          <div>摘要一致：<b class="${v.digestMatches ? 'ok-txt' : 'bad-txt'}">${v.digestMatches}</b></div>
          <div>版本链尖完好：<b class="${v.tipIntact ? 'ok-txt' : 'bad-txt'}">${v.tipIntact}</b>（绑定 v${v.ruleChainTip.version}）</div>
          <div>逐设备版本指纹：${v.ruleChecks.length ? v.ruleChecks.map((c) => `<span class="${c.intact ? 'ok-txt' : 'bad-txt'}">v${c.version}✓</span>`).join(' ') : '—'}</div>
        </div>
        <div class="hash" style="margin-top:5px">digest ${esc(v.recomputedDigest)}</div>
        <div class="hash">signature ${esc(v.signature)}</div>
        <details><summary>验签公钥（可离线复制）</summary><pre class="box">${esc(v.publicKeyPem || '')}</pre></details>
      </details>`;
    if (!silent) render();
  } catch (e) { toast(`${e.code}: ${e.message}`, 'err'); }
}

async function freeze(batchId) {
  try {
    await api(`/api/batches/${encodeURIComponent(batchId)}/freeze`, { by: '调度员' });
    await refresh();
    toast('批次已冻结；裁决绑定当时规则版本，后续规则变更不追改', 'ok');
  } catch (e) { toast(`${e.code}: ${e.message}`, 'err'); }
}

// 初始化默认日期
(async function init() {
  await refresh();
  $('rFrom').value = todayPlus(0);
  $('rUntil').value = '2026-12-31';
  $('aReq').value = `BID-${new Date(S.now).toISOString().slice(0, 10).replace(/-/g, '')}-001`;
})();
