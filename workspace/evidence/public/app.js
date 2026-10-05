/* 证据归档页面：原生 JS。
   安全纪律：upload secret 只存在内存变量 SECRET，仅经请求头发送；
   所有渲染文本都会过 ensureNoSecret（发现原文立即替换并告警）。 */
let SECRET = '';
let SELECTED = null;
let REPORTS = new Map();

const $ = (id) => document.getElementById(id);

function esc(s) {
  return String(s ?? '').replace(/[&<>"]/g, (c) => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;' }[c]));
}
function toast(msg, kind = '') {
  const el = document.createElement('div');
  el.className = `toast ${kind}`;
  el.textContent = msg;
  $('toasts').appendChild(el);
  setTimeout(() => el.remove(), 6000);
}

// 出口扫描：任何即将渲染/记录的文本若含 secret 原文，打码并红色告警。
function ensureNoSecret(text) {
  if (SECRET && text.includes(SECRET)) {
    toast('安全告警：响应中出现 upload secret 原文，已在页面打码！', 'err');
    return text.split(SECRET).join('***LEAK-BLOCKED***');
  }
  return text;
}
function safeText(v) { return ensureNoSecret(String(v ?? '')); }

async function api(path, { method = 'GET', body = null, auth = false, raw = false } = {}) {
  const headers = {};
  if (body) headers['Content-Type'] = 'application/json';
  if (auth) {
    if (!SECRET) { toast('请先设置 X-Upload-Secret', 'warn'); throw new Error('no secret'); }
    headers['X-Upload-Secret'] = SECRET;
  }
  const res = await fetch(path, { method, headers, body: body ? JSON.stringify(body) : undefined });
  const text = await res.text();
  const cleanText = ensureNoSecret(text);
  let data;
  try { data = JSON.parse(cleanText); } catch { data = raw ? cleanText : {}; }
  if (!res.ok) throw Object.assign(new Error(data.error || `HTTP ${res.status}`), { code: data.code, details: data.details, status: res.status });
  return raw ? cleanText : data;
}

function setSecretState() {
  $('secretState').textContent = SECRET ? `已设置（长度 ${SECRET.length}，仅内存）` : '未设置';
  $('secretState').className = SECRET ? 'tag ok' : 'muted';
}
$('btnSaveSecret').onclick = () => {
  SECRET = $('secret').value.trim();
  $('secret').value = '';
  setSecretState();
  toast('upload secret 已保存在页面内存（不会持久化）', 'ok');
};
setSecretState();

// ---------- 网关 ----------
async function loadGateways() {
  const r = await api('/api/gateways');
  $('gwList').innerHTML = r.gateways.length
    ? '已登记：' + r.gateways.map((g) => `<span class="tag info">${esc(g.gatewayId)} <span class="muted">(${esc(g.keyId)})</span></span>`).join(' ')
    : '（尚无登记网关）';
}
$('btnRegGw').onclick = async () => {
  try {
    await api('/api/gateways', { method: 'POST', auth: true, body: {
      gatewayId: $('gwId').value.trim(), keyId: $('gwKeyId').value.trim(), publicKeyPem: $('gwPub').value.trim(),
    } });
    $('gwId').value = $('gwKeyId').value = $('gwPub').value = '';
    toast('网关注册成功', 'ok');
    loadGateways();
  } catch (e) { toast(`${e.code || '错误'}：${safeText(e.message)}`, 'err'); }
};

// ---------- 导入 ----------
$('btnFormat').onclick = () => {
  try { $('envelope').value = JSON.stringify(JSON.parse($('envelope').value), null, 2); }
  catch (e) { toast('JSON 无法解析：' + e.message, 'err'); }
};
$('btnImport').onclick = async () => {
  let env;
  try { env = JSON.parse($('envelope').value); }
  catch (e) { toast('证据信封不是合法 JSON', 'err'); return; }
  $('importState').textContent = '校验中…';
  try {
    const r = await api(`/api/packages/${encodeURIComponent(env.packageId || '')}/import`, { method: 'POST', auth: true, body: env });
    const kind = r.duplicate ? '重复导入（返回原归档结果）' : (r.result === 'CONFLICTS' ? '导入完成：存在冲突隔离' : '导入成功');
    $('importState').innerHTML = `<span class="tag ${r.duplicate || r.result === 'CONFLICTS' ? 'warn' : 'ok'}">${kind}</span>`;
    $('importResult').textContent = ensureNoSecret(JSON.stringify({
      packageId: r.packageId,
      duplicate: r.duplicate,
      importId: r.importId,
      firstImportedAt: r.firstImportedAt || null,
      importedAt: r.importedAt || null,
      result: r.duplicate ? r.result : r.result,
      disposition: r.duplicate ? r.disposition : r.disposition,
      envelopeHash: r.envelopeHash,
    }, null, 2));
    toast(kind, r.duplicate || r.result === 'CONFLICTS' ? 'warn' : 'ok');
    await refreshPackages();
  } catch (e) {
    $('importState').innerHTML = `<span class="tag err">${esc(e.code || 'REJECTED')}</span>`;
    $('importResult').textContent = ensureNoSecret(JSON.stringify({ code: e.code, error: e.message, details: e.details }, null, 2));
    toast(`导入被拒绝：${e.code}`, 'err');
  }
};

// ---------- 包列表 ----------
async function refreshPackages(selectId = SELECTED) {
  const r = await api('/api/packages');
  REPORTS = new Map(r.packages.map((p) => [p.packageId, p]));
  $('pkgList').innerHTML = r.packages.length ? '' : '<div class="muted">（尚无归档）</div>';
  for (const p of r.packages) {
    const div = document.createElement('div');
    div.className = 'pkg-item' + (p.packageId === selectId ? ' active' : '');
    const fence = p.currentFence
      ? `v${p.currentFence.version} ${p.currentFence.closed ? '·已关闭' : '·活动'}` : '无围栏';
    const prog = p.currentProgress
      ? `lastSeq=${p.currentProgress.lastSeq}${p.currentProgress.carried ? '·沿用' : ''}` : '无检查点';
    const holdTag = p.activeHoldCount > 0
      ? ` <span class="tag warn">保全中 ${p.activeHoldCount}</span>` : '';
    const retTag = p.retention
      ? ` <span class="tag ${p.retention.expired ? 'err' : 'info'}">${p.retention.expired ? '已到期' : '期限内'}</span>` : '';
    div.innerHTML = `<div><b>${esc(p.packageId)}</b>
        <span class="tag ${p.conflictCount ? 'err' : 'ok'}">冲突 ${p.conflictCount}</span>${holdTag}${retTag}</div>
      <div class="muted mono">${esc(p.reportDigest.slice(0, 20))}…</div>
      <div class="muted">围栏：${esc(fence)} ｜ 进度：${esc(prog)} ｜ 记录 ${p.acceptedRecordCount}</div>`;
    div.onclick = () => { SELECTED = p.packageId; renderDetail(); refreshPackages(p.packageId); loadLifecycle(); };
    $('pkgList').appendChild(div);
  }
  if (selectId && !REPORTS.has(selectId)) SELECTED = null;
  if (SELECTED) renderDetail();
}
$('btnRefresh').onclick = () => refreshPackages().then(() => toast('已刷新', 'ok')).catch((e) => toast(e.message, 'err'));

// ---------- 详情/报告 ----------
async function renderDetail() {
  if (!SELECTED) return;
  try {
    const r = await api(`/api/packages/${encodeURIComponent(SELECTED)}/report`);
    $('detail').innerHTML = reportHTML(r);
  } catch (e) {
    if (e.code === 'PACKAGE_DESTROYED') {
      const receiptId = e.details?.receiptId || '';
      $('detail').innerHTML = `<div class="tag err">已销毁</div>
        <h3>${esc(SELECTED)} 的证据已销毁</h3>
        <div class="muted">提交后读接口统一返回已销毁状态（不会看到部分删除）。销毁回执（不含原始证据）仍可在下方 ⑥ 核验。</div>
        <div style="margin-top:8px">回执：<code>${esc(receiptId)}</code>
        <button data-receipt="${esc(receiptId)}" class="receipt-view">查看回执</button></div>`;
      return;
    }
    throw e;
  }
}

function reportHTML(r) {
  const dl = (fmt) => `/api/packages/${encodeURIComponent(r.packageId)}/report.${fmt}`;
  const fenceRows = r.fences.map((f) => `<tr>
      <td>v${f.version}${f.isCurrent ? ' <span class="tag info">当前</span>' : ''}</td>
      <td>${esc(f.fenceId || '-')}</td>
      <td>${esc(f.createdAt || '-')}</td>
      <td>${f.closedAt ? `<span class="tag warn">已关闭 ${esc(f.closedAt)}</span>` : '<span class="tag ok">活动</span>'}</td>
      <td>${f.segmentSeqs.length ? f.segmentSeqs.map((s) => `#${s}`).join(' ') : '-'}</td>
      <td>${f.checkpoint ? `lastSeq=${f.checkpoint.lastSeq} E/S/F=${f.checkpoint.counts.EXECUTED}/${f.checkpoint.counts.SKIPPED}/${f.checkpoint.counts.FAILED}` : '-'}</td>
      <td><a href="#" data-fence="${f.version}" class="old-fence-link">查询证据</a></td></tr>`).join('');
  const rows = r.timeline.map((t) => {
    const fence = t.fenceVersion === 0 ? 'manifest' : `v${t.fenceVersion}`;
    const body = t.type === 'SEGMENT_ACCEPTED'
      ? esc(t.entries.map((e) => `seq=${e.seq} ${e.deviceId} ${e.outcome}${e.note ? ' ' + e.note : ''}`).join('；'))
      : t.type === 'CHECKPOINT'
        ? `lastSeq=${t.lastSeq} E/S/F=${t.counts.EXECUTED}/${t.counts.SKIPPED}/${t.counts.FAILED}`
        : esc(t.detail || t.type);
    return `<tr><td>${esc(t.ts)}</td><td>${esc(fence)}</td><td>${t.segSeq ? '#' + t.segSeq : ''}</td>
      <td>${esc(t.type)}</td><td>${body}</td><td>${esc(t.gatewayId || '-')}</td></tr>`;
  }).join('');
  const conflicts = r.conflicts.map((c) => {
    const d = c.detail || {};
    const extra = d.segSeq != null ? `seg#${d.segSeq}` : d.lastSeq != null ? `lastSeq=${d.lastSeq}` : '';
    return `<tr><td>${c.seq}</td><td><span class="tag err">${esc(c.reason)}</span></td>
      <td>${esc(c.slot)}</td><td>${esc(extra)}</td><td>${esc(c.gatewayId)}</td>
      <td><code>${esc(c.fingerprint.slice(0, 16))}…</code></td>
      <td><code>${esc((c.existingFingerprint || '').slice(0, 16))}…</code></td>
      <td>${esc(c.envelopeHash.slice(0, 12))}…</td></tr>`;
  }).join('');
  const cp = r.currentProgress;
  return `
  <div class="row" style="justify-content:space-between">
    <div><b>${esc(r.packageId)}</b></div>
    <div class="row">
      <a href="${dl('txt')}" target="_blank"><button>下载 TXT</button></a>
      <a href="${dl('json')}" target="_blank"><button>下载脱敏 JSON</button></a>
      <button id="btnHtml">预览 HTML 片段</button>
    </div>
  </div>
  <h3>报告摘要（重启/重复导入后不变）</h3>
  <div class="mono" style="word-break:break-all">${esc(r.reportDigest)}</div>
  <div class="muted">链尖：ledger#${r.chainTips.ledger.seq} · quarantine#${r.chainTips.quarantine.seq} · audit#${r.chainTips.audit.seq}</div>
  <h3>当前状态</h3>
  <div>清单：<code>${esc((r.manifest?.manifestHash || '-').slice(0, 24))}…</code>（${r.manifest?.entries.length ?? 0} 条）</div>
  <div>当前围栏：${r.currentFence
    ? `v${r.currentFence.version} · ${esc(r.currentFence.fenceId)} · ${r.currentFence.closed ? '<span class="tag warn">已关闭</span>' : '<span class="tag ok">活动中</span>'}`
    : '（无）'}</div>
  <div>当前检查点：${cp
    ? `<b>v${cp.fenceVersion}</b> lastSeq=${cp.lastSeq} E/S/F=${cp.counts.EXECUTED}/${cp.counts.SKIPPED}/${cp.counts.FAILED}
       ${cp.carried ? '<span class="tag warn">沿用上一围栏水位（不倒退）</span>' : ''}
       ${cp.active ? '' : '<span class="tag warn">围栏已关闭，仅历史可查</span>'}`
    : '（无）'}</div>
  <h3>围栏（多围栏合并；旧围栏可查询但不充当当前进度）</h3>
  <table class="grid"><thead><tr><th>版本</th><th>fenceId</th><th>创建</th><th>状态</th><th>已收分段</th><th>检查点</th><th></th></tr></thead><tbody>${fenceRows}</tbody></table>
  <h3>确定性时间线（围栏 → 分段序号）</h3>
  <table class="grid"><thead><tr><th>时间</th><th>围栏</th><th>分段</th><th>类型</th><th>内容</th><th>网关</th></tr></thead><tbody>${rows}</tbody></table>
  <h3>冲突隔离（${r.conflicts.length}，原证据保留、未覆盖）</h3>
  <table class="grid"><thead><tr><th>#</th><th>原因</th><th>槽位</th><th>定位</th><th>网关</th><th>外来指纹</th><th>已存指纹</th><th>信封</th></tr></thead>
  <tbody>${conflicts || '<tr><td colspan=8 class=muted>（无冲突）</td></tr>'}</tbody></table>
  <h3>导入裁决历史</h3>
  <table class="grid"><thead><tr><th>时间</th><th>网关</th><th>结果</th><th>接受</th><th>重复</th><th>冲突</th><th>信封</th></tr></thead><tbody>
  ${r.imports.map((i) => `<tr><td>${esc(i.at)}</td><td>${esc(i.gatewayId)}</td>
    <td><span class="tag ${i.result === 'CONFLICTS' ? 'warn' : 'ok'}">${i.result}</span></td>
    <td>${i.recordsAccepted}</td><td>${i.recordsDuplicate}</td><td>${i.recordsConflicted}</td>
    <td><code>${esc(i.envelopeHash.slice(0, 12))}…</code></td></tr>`).join('')}
  </tbody></table>`;
}

document.addEventListener('click', async (ev) => {
  const a = ev.target.closest('.old-fence-link');
  if (a) {
    ev.preventDefault();
    const v = a.dataset.fence;
    try {
      const r = await api(`/api/packages/${encodeURIComponent(SELECTED)}/fences/${v}`);
      const segs = (r.segments || []).map((s) =>
        `[${s.ts}] seg#${s.segSeq} ${s.entries.map((e) => `${e.seq}:${e.deviceId}/${e.outcome}`).join(' ')}`).join('\n');
      alert(ensureNoSecret(`围栏 v${v}（${r.note}）\n状态：${r.fence.closedAt ? '已关闭' : '活动'}\n分段：\n${segs || '（无）'}`));
    } catch (e) { toast(e.message, 'err'); }
  }
  if (ev.target.id === 'btnHtml') {
    fetch(`/api/packages/${encodeURIComponent(SELECTED)}/report.html`).then((x) => x.text()).then((t) => {
      const w = window.open('', '_blank');
      w.document.write(`<meta charset=utf8><title>${SELECTED}</title><style>body{font:13px sans-serif;padding:16px}
        table{border-collapse:collapse}td,th{border:1px solid #ccc;padding:3px 6px;font-size:12px}code{font-size:11px}</style>` + ensureNoSecret(t));
    });
  }
});

// ---------- 链核验 / 重启 ----------
$('btnVerify').onclick = async () => {
  const r = await api('/api/chain/verify');
  const lines = [];
  for (const [id, v] of Object.entries(r.packages)) {
    for (const [name, c] of Object.entries(v.chains)) {
      lines.push(`${id}/${name}: ${c.ok ? 'OK' : 'BROKEN'} seq=${c.length} tip=${c.tipHash.slice(0, 12)}…${c.ok ? '' : ' reason=' + c.reason}`);
    }
  }
  $('verifyOut').textContent = lines.join('\n') || '（无包）';
};
$('btnRestart').onclick = async () => {
  try {
    await api('/api/admin/restart', { method: 'POST', auth: true });
    toast('已从磁盘重放重建（等价重启）', 'ok');
    await refreshPackages();
    if (SELECTED) {
      const before = REPORTS.get(SELECTED)?.reportDigest;
      await refreshPackages();
      const after = REPORTS.get(SELECTED)?.reportDigest;
      if (before && before !== after) toast('摘要在重放后发生变化！', 'err');
      else toast('重放后报告摘要一致', 'ok');
    }
  } catch (e) { toast(e.message, 'err'); }
};

loadGateways().catch(() => {});
refreshPackages().catch(() => {});
setInterval(() => refreshPackages().catch(() => {}), 15000);

// ---------- ⑥ 证据保全与到期销毁 ----------
function newReqId(prefix) {
  return `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
}

async function loadLifecycle() {
  if (!SELECTED) {
    $('lcForms').style.display = 'none';
    $('lcDetail').textContent = '选择左侧作业包后在此设置期限、发起/解除保全、执行销毁。';
    return;
  }
  $('lcForms').style.display = '';
  $('retReq').value = $('retReq').value || newReqId('ret');
  $('holdReq').value = newReqId('hold');
  let v;
  try {
    v = await api(`/api/packages/${encodeURIComponent(SELECTED)}/lifecycle`);
  } catch (e) {
    $('lcDetail').innerHTML = `<span class="tag err">${esc(e.code || 'ERR')}</span> ${esc(e.message)}`;
    return;
  }
  const ret = v.retention;
  const dst = v.destruction;
  const dstTag = {
    NONE: '<span class="tag ok">未销毁</span>',
    PREPARED: '<span class="tag warn">正在提交（中断待恢复）</span>',
    COMMITTED: '<span class="tag warn">已提交，删除未完成</span>',
    FAILED: '<span class="tag err">删除失败（可重试）</span>',
    COMPLETED: '<span class="tag err">已销毁</span>',
  }[dst.status] || dst.status;
  $('lcDetail').innerHTML = `
    <div>状态：${dstTag} ${v.eligible ? '<span class="tag info">可销毁（已到期且无保全）</span>' : ''}</div>
    <div>保留期限：${ret
      ? `<code>${esc(ret.retainUntil)}</code>（${ret.expired ? '<span class="tag err">已到期</span>' : '<span class="tag ok">期限内</span>'} · 由 ${esc(ret.setBy)} 设置于 ${esc(ret.setAt)}）`
      : '<span class="muted">未设置（永不自动销毁）</span>'}</div>
    <div>有效保全：<b>${v.activeHoldCount}</b> 个 ｜ 阻塞项：${v.blockers.length ? v.blockers.map((b) => `<code>${esc(b)}</code>`).join(' ') : '（无）'}</div>
    ${dst.receiptId ? `<div>销毁回执：<code>${esc(dst.receiptId)}</code> <button data-receipt="${esc(dst.receiptId)}" class="receipt-view">查看/验签</button></div>` : ''}`;
  $('btnRetry').style.display = dst.status === 'FAILED' ? '' : 'none';
  $('btnDestroy').disabled = dst.status === 'COMPLETED';
  const holds = v.holds || [];
  $('holdList').innerHTML = holds.length ? `<table class="grid"><thead><tr>
      <th>保全号</th><th>案件号</th><th>审计人</th><th>原因</th><th>状态</th><th>发起</th><th>解除</th><th></th>
    </tr></thead><tbody>${holds.map((h) => `<tr>
      <td class="mono">${esc(h.holdId)}</td>
      <td>${esc(h.caseNo)}</td>
      <td>${esc(h.auditor)}</td>
      <td>${esc(h.reason)}</td>
      <td>${h.status === 'ACTIVE' ? '<span class="tag warn">有效</span>' : '<span class="tag ok">已解除</span>'}</td>
      <td class="muted">${esc(h.createdAt)}</td>
      <td class="muted">${h.releasedAt ? `${esc(h.releasedAt)}${h.releasedBy ? ' · ' + esc(h.releasedBy) : ''}` : '-'}</td>
      <td>${h.status === 'ACTIVE' ? `<button data-hold="${esc(h.holdId)}" data-case="${esc(h.caseNo)}" class="hold-release">解除</button>` : ''}</td>
    </tr>`).join('')}</tbody></table>`
    : '<div class="muted">（无保全记录）</div>';
}

$('btnRetHour').onclick = () => { $('retUntil').value = new Date(Date.now() + 3600_000).toISOString(); };
$('btnRetPast').onclick = () => { $('retUntil').value = new Date(Date.now() - 5000).toISOString(); };

$('btnSetRet').onclick = async () => {
  try {
    const r = await api(`/api/packages/${encodeURIComponent(SELECTED)}/retention`, {
      method: 'POST', auth: true,
      body: {
        requestId: $('retReq').value.trim() || newReqId('ret'),
        retainUntil: $('retUntil').value.trim(),
        setBy: $('retBy').value.trim(),
      },
    });
    $('lcOut').textContent = ensureNoSecret(JSON.stringify(r, null, 2));
    toast(r.replay ? '同一请求号：返回原设置结果（幂等）' : '保留期限已设置', 'ok');
    $('retReq').value = newReqId('ret');
    await loadLifecycle(); await refreshPackages();
  } catch (e) {
    $('lcOut').textContent = ensureNoSecret(JSON.stringify({ code: e.code, error: e.message, details: e.details }, null, 2));
    toast(`设置期限被拒：${e.code}`, 'err');
  }
};

$('btnHold').onclick = async () => {
  try {
    const r = await api(`/api/packages/${encodeURIComponent(SELECTED)}/holds`, {
      method: 'POST', auth: true,
      body: {
        requestId: $('holdReq').value.trim() || newReqId('hold'),
        caseNo: $('holdCase').value.trim(),
        auditor: $('holdAuditor').value.trim(),
        reason: $('holdReason').value.trim(),
      },
    });
    $('lcOut').textContent = ensureNoSecret(JSON.stringify(r, null, 2));
    toast(r.replay ? '同一请求号：返回原保全（幂等）' : `保全已发起：${r.holdId}`, 'ok');
    $('holdReq').value = newReqId('hold');
    await loadLifecycle(); await refreshPackages();
  } catch (e) {
    $('lcOut').textContent = ensureNoSecret(JSON.stringify({ code: e.code, error: e.message, details: e.details }, null, 2));
    toast(`保全被拒：${e.code}`, 'err');
  }
};

$('btnDestroy').onclick = async () => {
  if (!confirm(`确认立即销毁 ${SELECTED}？\n销毁覆盖业务索引/链文件/冲突材料/凭据旁车，提交后读接口统一返回已销毁。`)) return;
  try {
    const r = await api(`/api/packages/${encodeURIComponent(SELECTED)}/destroy`, {
      method: 'POST', auth: true,
      body: { requestedBy: $('dstBy').value.trim(), reason: $('dstReason').value.trim() },
    });
    $('lcOut').textContent = ensureNoSecret(JSON.stringify({
      status: r.status, duplicate: r.duplicate, receiptId: r.receipt.receiptId,
      removed: r.receipt.removed, receiptHash: r.receipt.receiptHash,
    }, null, 2));
    toast(r.duplicate ? '重复执行：返回原回执（未生成第二份）' : `销毁完成，回执 ${r.receipt.receiptId}`, 'ok');
    await loadLifecycle(); await refreshPackages(); await refreshDestructions();
  } catch (e) {
    $('lcOut').textContent = ensureNoSecret(JSON.stringify({ code: e.code, error: e.message, details: e.details }, null, 2));
    toast(`销毁被拒：${e.code}`, 'err');
    await loadLifecycle();
  }
};

$('btnRetry').onclick = async () => {
  try {
    const r = await api(`/api/packages/${encodeURIComponent(SELECTED)}/destruction/retry`, { method: 'POST', auth: true, body: {} });
    $('lcOut').textContent = ensureNoSecret(JSON.stringify({ status: r.status, receiptId: r.receipt.receiptId }, null, 2));
    toast('重试完成（同一回执）', 'ok');
    await loadLifecycle(); await refreshDestructions();
  } catch (e) {
    $('lcOut').textContent = ensureNoSecret(JSON.stringify({ code: e.code, error: e.message, details: e.details }, null, 2));
    toast(`重试失败：${e.code}`, 'err');
  }
};

// 解除保全 / 查看回执（事件委托）
document.addEventListener('click', async (ev) => {
  const rel = ev.target.closest('.hold-release');
  if (rel) {
    const caseNo = prompt(`解除保全 ${rel.dataset.hold}\n请输入案件号核对（错误案件号将被拒 CASE_NO_MISMATCH）：`, rel.dataset.case || '');
    if (caseNo == null) return;
    try {
      const r = await api(`/api/packages/${encodeURIComponent(SELECTED)}/holds/${encodeURIComponent(rel.dataset.hold)}/release`, {
        method: 'POST', auth: true,
        body: { requestId: newReqId('rel'), caseNo: caseNo.trim(), releasedBy: 'web-console' },
      });
      toast(`保全已解除：${r.holdId}`, 'ok');
    } catch (e) {
      toast(`解除被拒：${e.code}（${safeText(e.message)}）`, 'err');
    }
    await loadLifecycle(); await refreshPackages();
    return;
  }
  const rv = ev.target.closest('.receipt-view');
  if (rv) {
    try {
      const [receipt, verify] = await Promise.all([
        api(`/api/destructions/${encodeURIComponent(rv.dataset.receipt)}`),
        api(`/api/destructions/${encodeURIComponent(rv.dataset.receipt)}/verify`),
      ]);
      $('receiptOut').textContent = ensureNoSecret(JSON.stringify({
        verify: { ok: verify.ok, checks: verify.checks, keyId: verify.keyId },
        receipt,
      }, null, 2));
      toast(verify.ok ? '回执验签通过' : '回执验签失败！', verify.ok ? 'ok' : 'err');
    } catch (e) { toast(e.message, 'err'); }
  }
});

// ---------- 待销毁列表 / 回执 ----------
async function refreshDestructions() {
  try {
    const p = await api('/api/destructions/pending');
    const sec = (t, arr, fn) => `<h4>${t}（${arr.length}）</h4>${arr.length ? arr.map(fn).join('') : '<div class="muted">（无）</div>'}`;
    $('pendingList').innerHTML =
      sec('合格（已到期且无保全）', p.eligible, (x) =>
        `<div>• <b>${esc(x.packageId)}</b> <span class="muted">期限 ${esc(x.retainUntil)}</span></div>`) +
      sec('被保全阻塞', p.blocked, (x) =>
        `<div>• <b>${esc(x.packageId)}</b> <span class="tag warn">保全 ${x.activeHoldCount}</span> <span class="muted">${x.holds.map((h) => esc(h.caseNo)).join('、')}</span></div>`) +
      sec('在途（提交中/失败）', p.inFlight, (x) =>
        `<div>• <b>${esc(x.packageId)}</b> <span class="tag ${x.status === 'FAILED' ? 'err' : 'warn'}">${esc(x.status)}</span> ${x.receiptId ? `<code>${esc(x.receiptId)}</code>` : ''}</div>`);
  } catch (e) {
    $('pendingList').innerHTML = `<span class="tag err">${esc(e.code || 'ERR')}</span>`;
  }
  try {
    const r = await api('/api/destructions');
    $('receiptList').innerHTML = r.receipts.length ? `<table class="grid"><thead><tr>
        <th>回执</th><th>作业包</th><th>提交时间</th><th>状态</th><th>覆盖</th><th></th>
      </tr></thead><tbody>${r.receipts.map((x) => `<tr>
        <td class="mono">${esc(x.receiptId.slice(0, 18))}…</td>
        <td>${esc(x.packageId)}</td>
        <td class="muted">${esc(x.committedAt)}</td>
        <td><span class="tag ${x.status === 'COMPLETED' ? 'ok' : 'err'}">${esc(x.status)}</span></td>
        <td class="muted">链 ${x.removed.chains} · 冲突 ${x.removed.conflictMaterials} · 凭据 ${x.removed.credentialSidecars} · ${x.removed.totalFiles} 文件</td>
        <td><button data-receipt="${esc(x.receiptId)}" class="receipt-view">验签</button></td>
      </tr>`).join('')}</tbody></table>`
      : '<div class="muted">（尚无销毁回执）</div>';
  } catch (e) {
    $('receiptList').innerHTML = `<span class="tag err">${esc(e.code || 'ERR')}</span>`;
  }
}

$('btnSweep').onclick = async () => {
  try {
    const r = await api('/api/destructions/sweep', { method: 'POST', auth: true, body: {} });
    $('sweepOut').textContent = ensureNoSecret(JSON.stringify(r, null, 2));
    toast(`到期清扫完成：销毁 ${r.destroyed.length}，跳过 ${r.skipped.length}，失败 ${r.errors.length}`, 'ok');
    await refreshDestructions(); await refreshPackages(); await loadLifecycle();
  } catch (e) { toast(`清扫失败：${e.code}`, 'err'); }
};
$('btnRefreshDst').onclick = () => refreshDestructions().then(() => toast('已刷新', 'ok'));

refreshDestructions().catch(() => {});
setInterval(() => refreshDestructions().catch(() => {}), 20000);
