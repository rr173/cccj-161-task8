// 证据保全与到期销毁（legal hold & expiry destruction）。
//
// 运营人员为作业包设置保留期限；审计人员在期限内发起带【原因 + 案件号】的保全；
// 一个作业包可同时被多个有效保全约束；只有【全部解除 且 期限已到】才允许销毁。
//
// 全部生命周期事实写入全局哈希链 data/evidence/lifecycle.jsonl（chainName=lifecycle，
// genesis 锚定 GLOBAL）——包目录被物理删除后，期限/保全/解除/回执历史仍可独立核验：
//   RETENTION_SET           设置/更新保留期限（requestId 幂等）
//   HOLD_CREATED            发起保全（requestId 幂等；同案件号有效保全唯一）
//   HOLD_RELEASED           解除保全（requestId 幂等；案件号必须匹配）
//   DESTRUCTION_PREPARED    销毁准备：枚举并哈希全部待删对象（两阶段提交的准备段）
//   DESTRUCTION_COMMITTED   提交点：签名回执入链。此前读=完整旧状态，此后读=已销毁
//   DESTRUCTION_COMPLETED   物理删除完成（业务索引/链文件/冲突材料/凭据旁车全部清除）
//   DESTRUCTION_FAILED      存储删除失败（可核对、可重试；重试不产生第二份回执）
//
// 关键不变量：
//  - 命令严格串行（同步临界区，无 await）：保全创建/解除与到期任务不会与销毁提交交错，
//    资格检查（期限已到 + 无有效保全）与提交点在同一同步区内完成，绝不误删。
//  - 提交点 = DESTRUCTION_COMMITTED 入链。提交前不删任何字节（读=完整旧状态）；
//    提交后读接口统一 410（看不到部分删除）；物理删除在提交点之后执行。
//  - 崩溃恢复：重启重放链后 —— 仅 PREPARED（尚未越过提交点，文件完整）→ 重新执行到
//    唯一结果；COMMITTED 未 COMPLETED（已提交，删除中断）→ 继续删剩余文件；
//    COMPLETED → 无操作。回执 ID 由 packageId+计划哈希派生，重复执行永远返回同一份回执。
//  - 回执只含哈希/计数/链尖/案件号等元数据，绝不含原始证据。
import {
  existsSync,
  readdirSync,
  readFileSync,
  statSync,
  unlinkSync,
  rmdirSync,
  mkdirSync,
} from 'node:fs';
import { join } from 'node:path';
import { ChainLog } from './chains.js';
import { canonicalJSON, sha256Hex, sha256Buf } from './hashing.js';
import { loadOrCreateDestructionSigner } from './crypto.js';
import { validPackageId } from './archive.js';

export const RECEIPT_SCHEMA = 'destruction-receipt/1';
const HEX64 = /^[0-9a-f]{64}$/;

function err(status, code, message, details = {}) {
  throw Object.assign(new Error(message), { code, status, details });
}

// 待删对象分类：业务索引 / 链文件 / 冲突材料 / 凭据旁车（+ 残尾旁证 / 其他）。
const CATEGORY_RULES = [
  [/^(ledger|audit)\.jsonl$/, 'chain'],
  [/^quarantine\.jsonl$/, 'conflict'],
  [/^torn-.*\.(log|meta\.json)$/, 'torn-tail'],
  [/(\.keys\.json|\.secret|\.pem|\.key)$/, 'credential'],
  [/(^index\.json$|\.idx)$/, 'index'],
];

function categorize(name) {
  for (const [re, cat] of CATEGORY_RULES) if (re.test(name)) return cat;
  return 'other';
}

function hashFile(abs) {
  const buf = readFileSync(abs);
  return { sha256: sha256Buf(buf), bytes: buf.length };
}

// 默认删除器（可注入假删除器模拟存储失败）。ENOENT 视为已删（幂等）。
const defaultDeleter = {
  unlink(abs) {
    try { unlinkSync(abs); } catch (e) { if (e.code !== 'ENOENT') throw e; }
  },
  rmdir(abs) {
    try { rmdirSync(abs); } catch (e) { if (e.code !== 'ENOENT') throw e; }
  },
};

function normInstant(v) {
  if (typeof v === 'number' && Number.isFinite(v)) return new Date(v).toISOString();
  if (typeof v === 'string' && v.trim()) {
    const ms = Date.parse(v);
    if (!Number.isNaN(ms)) return new Date(ms).toISOString();
  }
  return null;
}

function normText(v, field, { required = true, max = 256 } = {}) {
  if (v == null || v === '') {
    if (required) err(400, 'FIELD_REQUIRED', `${field} 必填`);
    return null;
  }
  if (typeof v !== 'string') err(400, 'FIELD_INVALID', `${field} 必须是字符串`);
  const t = v.trim();
  if (required && !t) err(400, 'FIELD_REQUIRED', `${field} 必填`);
  if (t.length > max) err(400, 'FIELD_INVALID', `${field} 过长（>${max}）`);
  return t;
}

// 枚举一个作业包的全部待删对象（相对路径 + 内容哈希 + 分类），确定排序。
function buildPlan(rootDir, packageId) {
  const files = [];
  const pkgDir = join(rootDir, 'packages', packageId);
  if (existsSync(pkgDir)) {
    for (const name of readdirSync(pkgDir).sort()) {
      const abs = join(pkgDir, name);
      if (!statSync(abs).isFile()) continue;
      files.push({ path: `packages/${packageId}/${name}`, category: categorize(name), ...hashFile(abs) });
    }
  }
  // 被拒信封留底（含原始被拒证据）按 targetPackageId 归属一并销毁。
  const rejDir = join(rootDir, 'rejected');
  if (existsSync(rejDir)) {
    for (const name of readdirSync(rejDir).sort()) {
      if (!name.endsWith('.json')) continue;
      const abs = join(rejDir, name);
      if (!statSync(abs).isFile()) continue;
      try {
        const parsed = JSON.parse(readFileSync(abs, 'utf8'));
        if (parsed?.targetPackageId !== packageId) continue;
      } catch { continue; }
      files.push({ path: `rejected/${name}`, category: 'conflict', ...hashFile(abs) });
    }
  }
  return files;
}

function summarizePlan(plan) {
  const s = {
    chains: 0, conflictMaterials: 0, credentialSidecars: 0, indexes: 0,
    tornTails: 0, others: 0, totalFiles: plan.length, totalBytes: 0,
    businessIndexes: { inMemoryProjections: 'evicted-on-commit', onDiskIndexFiles: 0 },
  };
  for (const f of plan) {
    s.totalBytes += f.bytes;
    if (f.category === 'chain') s.chains += 1;
    else if (f.category === 'conflict') s.conflictMaterials += 1;
    else if (f.category === 'credential') s.credentialSidecars += 1;
    else if (f.category === 'index') { s.indexes += 1; s.businessIndexes.onDiskIndexFiles += 1; }
    else if (f.category === 'torn-tail') s.tornTails += 1;
    else s.others += 1;
  }
  return s;
}

export class LifecycleStore {
  // opts.now: () => Date（可注入仿真时钟）；opts.deleter：注入故障用于演练存储删除失败；
  // opts.hooks: { snapshot(packageId), evict(packageId), listPackages(), packageExists(packageId) }
  constructor(rootDir, opts = {}) {
    this.rootDir = rootDir;
    mkdirSync(rootDir, { recursive: true });
    this._now = opts.now || (() => new Date());
    this.deleter = opts.deleter || defaultDeleter;
    this.signer = opts.signer || loadOrCreateDestructionSigner(join(rootDir, 'destruction-key.json'));
    this.hooks = opts.hooks || {};
    this.#newChain();
    this.#reset();
    this.chain.load();
    this.#replay();
  }

  setHooks(hooks) {
    Object.assign(this.hooks, hooks);
  }

  #newChain() {
    this.chain = new ChainLog(join(this.rootDir, 'lifecycle.jsonl'), {
      chainName: 'lifecycle',
      packageId: 'GLOBAL',
      quarantineDir: join(this.rootDir, 'quarantine'),
      label: 'lifecycle',
    });
  }

  #reset() {
    this.retention = new Map(); // packageId -> {retainUntil,setBy,reason,at,requestId}
    this.holds = new Map(); // holdId -> 保全（含 RELEASED 终态）
    this.holdSeq = new Map(); // packageId -> 已签发保全数（holdId 序号，重放确定）
    this.requests = new Map(); // requestId -> {contentHash, kind, result}
    this.destructions = new Map(); // packageId -> {prepared?,committed?,completed?,failed?}
    this.receipts = new Map(); // receiptId -> receipt
  }

  // 等价进程重启：丢弃投影，从链重放并恢复中断的销毁。
  reload() {
    this.#newChain();
    this.#reset();
    this.chain.load();
    this.#replay();
    return this.recover();
  }

  #replay() {
    for (const rec of this.chain.records) this.#apply(rec);
  }

  #dst(packageId) {
    if (!this.destructions.has(packageId)) this.destructions.set(packageId, {});
    return this.destructions.get(packageId);
  }

  #apply(rec) {
    switch (rec.kind) {
      case 'RETENTION_SET':
        this.retention.set(rec.packageId, {
          retainUntil: rec.retainUntil, setBy: rec.setBy,
          reason: rec.reason ?? null, at: rec.at, requestId: rec.requestId,
        });
        this.requests.set(rec.requestId, { contentHash: rec.contentHash, kind: rec.kind, result: rec.result });
        break;
      case 'HOLD_CREATED':
        this.holds.set(rec.holdId, {
          holdId: rec.holdId, packageId: rec.packageId, caseNo: rec.caseNo,
          reason: rec.reason, auditor: rec.auditor, status: 'ACTIVE',
          createdAt: rec.at, releasedAt: null, releasedBy: null, releaseReason: null,
        });
        this.holdSeq.set(rec.packageId, (this.holdSeq.get(rec.packageId) || 0) + 1);
        this.requests.set(rec.requestId, { contentHash: rec.contentHash, kind: rec.kind, result: rec.result });
        break;
      case 'HOLD_RELEASED': {
        const h = this.holds.get(rec.holdId);
        if (h) {
          h.status = 'RELEASED';
          h.releasedAt = rec.at;
          h.releasedBy = rec.releasedBy ?? null;
          h.releaseReason = rec.reason ?? null;
        }
        this.requests.set(rec.requestId, { contentHash: rec.contentHash, kind: rec.kind, result: rec.result });
        break;
      }
      case 'DESTRUCTION_PREPARED': {
        this.#dst(rec.packageId).prepared = {
          prepareId: rec.prepareId, planHash: rec.planHash, plan: rec.plan, at: rec.at,
        };
        break;
      }
      case 'DESTRUCTION_COMMITTED': {
        this.#dst(rec.packageId).committed = { receiptId: rec.receiptId, receipt: rec.receipt, at: rec.at };
        this.receipts.set(rec.receiptId, rec.receipt);
        break;
      }
      case 'DESTRUCTION_COMPLETED': {
        const d = this.#dst(rec.packageId);
        d.completed = {
          receiptId: rec.receiptId, at: rec.at,
          removedFiles: rec.removedFiles, removedBytes: rec.removedBytes,
        };
        d.failed = null;
        break;
      }
      case 'DESTRUCTION_FAILED': {
        this.#dst(rec.packageId).failed = {
          receiptId: rec.receiptId, at: rec.at,
          error: rec.error, remainingFiles: rec.remainingFiles,
        };
        break;
      }
      default:
        break; // 未知种类忽略（前向兼容）
    }
  }

  #commit(payload) {
    const rec = this.chain.append(payload); // 链隔离时抛 CHAIN_QUARANTINED（503）
    this.#apply(rec);
    return rec;
  }

  get writable() {
    return this.chain.writable;
  }

  nowMs() {
    return this._now().getTime();
  }

  #packageExists(packageId) {
    if (this.hooks.packageExists) return this.hooks.packageExists(packageId);
    return existsSync(join(this.rootDir, 'packages', packageId));
  }

  #listPackages() {
    if (this.hooks.listPackages) return this.hooks.listPackages();
    const dir = join(this.rootDir, 'packages');
    if (!existsSync(dir)) return [];
    return readdirSync(dir, { withFileTypes: true })
      .filter((d) => d.isDirectory() && validPackageId(d.name))
      .map((d) => d.name)
      .sort();
  }

  // 销毁状态：NONE（尚未开始）/ PREPARED（正在提交，崩溃残留）/ COMMITTED（已提交，删除中断）
  //           / FAILED（删除失败，可重试）/ COMPLETED（已完成）。
  destructionStatus(packageId) {
    const d = this.destructions.get(packageId);
    if (!d || (!d.prepared && !d.committed)) return { status: 'NONE' };
    if (d.completed) {
      return {
        status: 'COMPLETED', receiptId: d.completed.receiptId, at: d.completed.at,
        preparedAt: d.prepared?.at ?? null, committedAt: d.committed?.at ?? null,
        removedFiles: d.completed.removedFiles, removedBytes: d.completed.removedBytes,
      };
    }
    if (d.failed) {
      return {
        status: 'FAILED', receiptId: d.failed.receiptId, at: d.failed.at,
        preparedAt: d.prepared?.at ?? null, committedAt: d.committed?.at ?? null,
        error: d.failed.error, remainingFiles: d.failed.remainingFiles,
      };
    }
    if (d.committed) {
      return {
        status: 'COMMITTED', receiptId: d.committed.receiptId, at: d.committed.at,
        preparedAt: d.prepared?.at ?? null,
      };
    }
    return { status: 'PREPARED', at: d.prepared.at, prepareId: d.prepared.prepareId };
  }

  // 已越过提交点（读接口统一返回已销毁）。
  isDestroyed(packageId) {
    const s = this.destructionStatus(packageId).status;
    return s === 'COMMITTED' || s === 'FAILED' || s === 'COMPLETED';
  }

  activeHolds(packageId) {
    return [...this.holds.values()]
      .filter((h) => h.packageId === packageId && h.status === 'ACTIVE')
      .sort((a, b) => (a.holdId < b.holdId ? -1 : 1));
  }

  #assertPackageLive(packageId) {
    if (!validPackageId(packageId)) err(400, 'PACKAGE_ID_INVALID', `非法 packageId: ${packageId}`);
    if (this.isDestroyed(packageId)) {
      const st = this.destructionStatus(packageId);
      err(410, 'PACKAGE_DESTROYED', `作业包 ${packageId} 的证据已销毁（回执 ${st.receiptId}）`, {
        receiptId: st.receiptId, destroyedAt: st.committedAt ?? st.at,
      });
    }
    if (!this.#packageExists(packageId)) {
      err(404, 'PACKAGE_UNKNOWN', `作业包 ${packageId} 不存在（无归档证据）`);
    }
  }

  // requestId 幂等：同号同内容 → 返回首次结果；同号不同内容 → 409。
  // 只有首次执行（exec 内）才做业务校验与上链；重放直接返回链上快照。
  #runRequest(requestId, kind, content, exec) {
    const rid = normText(requestId, 'requestId', { max: 128 });
    const contentHash = sha256Hex(canonicalJSON({ kind, ...content }));
    const prior = this.requests.get(rid);
    if (prior) {
      if (prior.contentHash !== contentHash) {
        err(409, 'REQUEST_ID_CONFLICT', `requestId ${rid} 已用于不同内容的请求`, { requestId: rid });
      }
      return { replay: true, result: prior.result };
    }
    const result = exec(rid, contentHash);
    return { replay: false, result };
  }

  // ---------- 保留期限 ----------

  setRetention(packageId, { requestId, retainUntil, setBy, reason } = {}) {
    const until = normInstant(retainUntil);
    if (!until) err(400, 'RETENTION_INVALID', 'retainUntil 必须是 ISO8601 时间或毫秒时间戳');
    const who = normText(setBy, 'setBy');
    const why = normText(reason, 'reason', { required: false, max: 512 });
    return this.#runRequest(requestId, 'RETENTION_SET',
      { packageId, retainUntil: until, setBy: who, reason: why }, (rid, contentHash) => {
        this.#assertPackageLive(packageId);
        const at = this._now().toISOString();
        const result = {
          packageId, retainUntil: until, setBy: who, reason: why, setAt: at, requestId: rid,
        };
        this.#commit({
          kind: 'RETENTION_SET', packageId, retainUntil: until, setBy: who, reason: why,
          requestId: rid, contentHash, at, result,
        });
        return result;
      });
  }

  // ---------- 保全（legal hold） ----------

  createHold(packageId, { requestId, caseNo, reason, auditor } = {}) {
    const cno = normText(caseNo, 'caseNo', { max: 128 });
    const why = normText(reason, 'reason', { max: 512 });
    const who = normText(auditor, 'auditor');
    return this.#runRequest(requestId, 'HOLD_CREATED',
      { packageId, caseNo: cno, reason: why, auditor: who }, (rid, contentHash) => {
        this.#assertPackageLive(packageId);
        if (this.destructionStatus(packageId).status === 'PREPARED') {
          err(409, 'DESTRUCTION_IN_PROGRESS', '销毁正在提交，不能再发起保全');
        }
        // 审计人员只能在保留期限内发起保全；过期后不再接受新保全（保证收敛）。
        const ret = this.retention.get(packageId);
        if (ret && this.nowMs() >= Date.parse(ret.retainUntil)) {
          err(409, 'RETENTION_EXPIRED', '保留期限已过，不能再发起新保全', { retainUntil: ret.retainUntil });
        }
        const dup = this.activeHolds(packageId).find((h) => h.caseNo === cno);
        if (dup) {
          err(409, 'HOLD_CASE_ACTIVE', `案件号 ${cno} 已存在有效保全（${dup.holdId}）`, {
            holdId: dup.holdId, caseNo: cno,
          });
        }
        const seq = (this.holdSeq.get(packageId) || 0) + 1;
        const holdId = `${packageId}-H${seq}`;
        const at = this._now().toISOString();
        const result = {
          holdId, packageId, caseNo: cno, reason: why, auditor: who,
          status: 'ACTIVE', createdAt: at, requestId: rid,
        };
        this.#commit({
          kind: 'HOLD_CREATED', packageId, holdId, caseNo: cno, reason: why, auditor: who,
          requestId: rid, contentHash, at, result,
        });
        return result;
      });
  }

  releaseHold(packageId, holdId, { requestId, caseNo, releasedBy, reason } = {}) {
    const cno = normText(caseNo, 'caseNo', { max: 128 });
    const who = normText(releasedBy, 'releasedBy', { required: false });
    const why = normText(reason, 'reason', { required: false, max: 512 });
    return this.#runRequest(requestId, 'HOLD_RELEASED',
      { packageId, holdId, caseNo: cno, releasedBy: who, reason: why }, (rid, contentHash) => {
        this.#assertPackageLive(packageId);
        const h = this.holds.get(holdId);
        if (!h || h.packageId !== packageId) {
          err(404, 'HOLD_UNKNOWN', `保全 ${holdId} 不存在`);
        }
        if (h.caseNo !== cno) {
          err(409, 'CASE_NO_MISMATCH', `案件号与保全记录不符（保全登记为 ${h.caseNo}）`, {
            holdId, expectedCaseNo: h.caseNo,
          });
        }
        if (h.status !== 'ACTIVE') {
          // 并发解除：后到者安全失败，可核对首次解除时间。
          err(409, 'HOLD_ALREADY_RELEASED', `保全 ${holdId} 已解除（并发解除安全失败）`, {
            holdId, releasedAt: h.releasedAt,
          });
        }
        const at = this._now().toISOString();
        const result = {
          holdId, packageId, caseNo: h.caseNo, status: 'RELEASED',
          releasedAt: at, releasedBy: who, reason: why, requestId: rid,
        };
        this.#commit({
          kind: 'HOLD_RELEASED', packageId, holdId, caseNo: h.caseNo,
          releasedBy: who, reason: why, requestId: rid, contentHash, at, result,
        });
        return result;
      });
  }

  // ---------- 销毁（两阶段提交） ----------

  // 资格闸：期限已到 + 无有效保全。与提交点在同一同步临界区内执行，绝不误删。
  // 保全（法律约束）优先于期限（管理约束）报告：两者同时阻塞时给出保全清单。
  #assertEligible(packageId) {
    const ret = this.retention.get(packageId);
    if (!ret) err(409, 'RETENTION_NOT_SET', '尚未设置保留期限，不得销毁', { packageId });
    const active = this.activeHolds(packageId);
    if (active.length) {
      err(409, 'DESTRUCTION_BLOCKED_HOLDS', `存在 ${active.length} 个有效保全，全部解除后才可销毁`, {
        activeHolds: active.map((h) => ({
          holdId: h.holdId, caseNo: h.caseNo, auditor: h.auditor, createdAt: h.createdAt,
        })),
      });
    }
    if (this.nowMs() < Date.parse(ret.retainUntil)) {
      err(409, 'RETENTION_NOT_EXPIRED', '保留期限未到，不得销毁', {
        retainUntil: ret.retainUntil, now: this._now().toISOString(),
      });
    }
  }

  // 准备段：枚举 + 哈希全部待删对象并上链（不删任何字节）。计划相同则幂等复用。
  prepareDestruction(packageId) {
    const d = this.#dst(packageId);
    const plan = buildPlan(this.rootDir, packageId);
    if (!plan.length && !d.prepared) {
      err(404, 'PACKAGE_UNKNOWN', `作业包 ${packageId} 不存在或无任何归档文件`);
    }
    const planHash = sha256Hex(canonicalJSON(plan));
    if (d.prepared && d.prepared.planHash === planHash) return d.prepared;
    const at = this._now().toISOString();
    const prepared = { prepareId: `prp_${planHash.slice(0, 16)}`, planHash, plan, at };
    this.#commit({ kind: 'DESTRUCTION_PREPARED', packageId, ...prepared });
    return prepared;
  }

  // 提交点：生成签名回执并上链（每包至多一次；此后读=已销毁）。
  commitDestruction(packageId, { requestedBy, reason } = {}) {
    const d = this.#dst(packageId);
    if (d.committed) return d.committed.receipt; // 唯一回执：重复执行不生成第二份
    if (!d.prepared) err(409, 'DESTRUCTION_NOT_PREPARED', '销毁尚未准备（缺少 DESTRUCTION_PREPARED）');
    const at = this._now().toISOString();
    const snap = this.hooks.snapshot ? this.hooks.snapshot(packageId) : {
      reportDigest: null, chainTips: null, counts: null,
    };
    const ret = this.retention.get(packageId) || null;
    const holds = [...this.holds.values()]
      .filter((h) => h.packageId === packageId)
      .sort((a, b) => (a.holdId < b.holdId ? -1 : 1))
      .map((h) => ({
        holdId: h.holdId, caseNo: h.caseNo, auditor: h.auditor, reason: h.reason,
        createdAt: h.createdAt, status: h.status,
        releasedAt: h.releasedAt, releasedBy: h.releasedBy,
      }));
    const plan = d.prepared.plan;
    const receiptId = `dst_${sha256Hex(`destruction-receipt/1\n${packageId}\n${d.prepared.planHash}`).slice(0, 24)}`;
    const body = {
      schema: RECEIPT_SCHEMA,
      receiptId,
      packageId,
      preparedAt: d.prepared.at,
      committedAt: at,
      requestedBy: requestedBy || 'system',
      reason: reason ?? null,
      retention: ret ? {
        retainUntil: ret.retainUntil, setBy: ret.setBy, setAt: ret.at, reason: ret.reason,
      } : null,
      holds,
      evidenceSummary: snap, // 只有报告摘要/链尖/计数，绝不含原始证据
      files: plan,
      removed: summarizePlan(plan),
    };
    body.receiptHash = sha256Hex(canonicalJSON(body));
    const receipt = { ...body, keyId: this.signer.keyId, signature: this.signer.sign(body.receiptHash) };
    this.#commit({ kind: 'DESTRUCTION_COMMITTED', packageId, receiptId, receipt, at });
    // 业务索引（内存投影）随提交失效；磁盘文件在完成段删除。
    if (this.hooks.evict) this.hooks.evict(packageId);
    return receipt;
  }

  // 完成段：物理删除（链文件/冲突材料/凭据旁车/索引/残尾/被拒留底）并上链完成记录。
  // 失败 → DESTRUCTION_FAILED 上链并抛 STORAGE_DELETE_FAILED（可核对、可重试）。
  finishDestruction(packageId, { deleter } = {}) {
    const d = this.#dst(packageId);
    if (d.completed) return d.completed;
    if (!d.committed) err(409, 'DESTRUCTION_NOT_COMMITTED', '销毁尚未提交，无回执可完成');
    const receipt = d.committed.receipt;
    const del = deleter || this.deleter;
    const remaining = [];
    let firstError = null;
    for (const f of receipt.files) {
      const abs = join(this.rootDir, f.path);
      try {
        del.unlink(abs);
      } catch (e) {
        if (!firstError) firstError = e;
        remaining.push(f.path);
      }
    }
    // 包目录本身（仅当文件全部移除后；非空则视为删除失败，留待重试）。
    const pkgDir = join(this.rootDir, 'packages', packageId);
    if (existsSync(pkgDir)) {
      try {
        del.rmdir(pkgDir);
      } catch (e) {
        if (!firstError) firstError = e;
        for (const name of readdirSync(pkgDir).sort()) {
          const rel = `packages/${packageId}/${name}`;
          if (!remaining.includes(rel)) remaining.push(rel);
        }
        remaining.push(`packages/${packageId}/`);
      }
    }
    const at = this._now().toISOString();
    if (remaining.length) {
      this.#commit({
        kind: 'DESTRUCTION_FAILED', packageId, receiptId: receipt.receiptId,
        error: String(firstError?.message || '删除失败'), remainingFiles: remaining, at,
      });
      err(500, 'STORAGE_DELETE_FAILED', '存储删除失败：部分对象未能删除（已记录，可重试，不会产生第二份回执）', {
        receiptId: receipt.receiptId, remainingFiles: remaining,
      });
    }
    const removedFiles = receipt.files.length;
    const removedBytes = receipt.files.reduce((a, f) => a + f.bytes, 0);
    const completed = { receiptId: receipt.receiptId, removedFiles, removedBytes, at };
    this.#commit({ kind: 'DESTRUCTION_COMPLETED', packageId, ...completed });
    return completed;
  }

  // 立即执行销毁：资格闸 → 准备 → 提交 → 删除，单同步临界区（并发保全/解除/到期任务不会交错）。
  executeDestruction(packageId, { requestedBy, reason, deleter } = {}) {
    const d = this.destructions.get(packageId);
    if (d?.committed) {
      // 重复执行：返回原回执，绝不生成第二份。
      return {
        duplicate: true,
        status: this.destructionStatus(packageId).status,
        receipt: d.committed.receipt,
      };
    }
    if (!this.#packageExists(packageId) && !d?.prepared) {
      err(404, 'PACKAGE_UNKNOWN', `作业包 ${packageId} 不存在（无归档证据）`);
    }
    this.#assertEligible(packageId);
    this.prepareDestruction(packageId);
    const receipt = this.commitDestruction(packageId, { requestedBy, reason });
    const completed = this.finishDestruction(packageId, { deleter });
    return { duplicate: false, status: 'COMPLETED', receipt, completed };
  }

  // 失败后恢复：仅处理已提交未完成的销毁；重试不产生第二份回执。
  retryDestruction(packageId, { deleter } = {}) {
    const st = this.destructionStatus(packageId);
    if (st.status === 'COMPLETED') {
      return { duplicate: true, status: 'COMPLETED', receipt: this.destructions.get(packageId).committed.receipt };
    }
    if (st.status === 'NONE' || st.status === 'PREPARED') {
      err(409, 'DESTRUCTION_NOT_COMMITTED', '销毁尚未提交，不能重试删除（请先执行销毁）', { status: st.status });
    }
    // COMMITTED / FAILED：继续删除剩余文件。
    this.finishDestruction(packageId, { deleter });
    return {
      duplicate: false, status: 'COMPLETED',
      receipt: this.destructions.get(packageId).committed.receipt,
    };
  }

  // 启动恢复：把中断的销毁继续到唯一结果（服务开始前调用）。
  recover() {
    const resumed = [];
    for (const packageId of [...this.destructions.keys()]) {
      const st = this.destructionStatus(packageId);
      if (st.status === 'COMPLETED' || st.status === 'NONE') continue;
      if (st.status === 'COMMITTED' || st.status === 'FAILED') {
        try {
          this.finishDestruction(packageId);
          resumed.push({ packageId, from: st.status, to: 'COMPLETED' });
        } catch (e) {
          resumed.push({ packageId, from: st.status, to: 'FAILED', error: e.message });
        }
      } else if (st.status === 'PREPARED') {
        // 崩溃于提交点之前：文件完整（读仍返回完整旧状态），重新执行到唯一结果。
        try {
          this.#assertEligible(packageId); // 停机期间状态不可变，必然仍合格
          this.commitDestruction(packageId, { requestedBy: 'recovery', reason: '恢复中断的销毁提交' });
          this.finishDestruction(packageId);
          resumed.push({ packageId, from: 'PREPARED', to: 'COMPLETED' });
        } catch (e) {
          resumed.push({ packageId, from: 'PREPARED', to: this.destructionStatus(packageId).status, error: e.message });
        }
      }
    }
    return resumed;
  }

  // 到期任务：清扫全部【期限已到 且 无有效保全】的包。跳过原因可核对。
  sweep({ requestedBy = 'expiry-sweep' } = {}) {
    const now = this.nowMs();
    const destroyed = [];
    const skipped = [];
    const errors = [];
    for (const packageId of this.#listPackages()) {
      if (this.destructionStatus(packageId).status !== 'NONE') continue; // 在途/完成由 recover/retry 处理
      const ret = this.retention.get(packageId);
      if (!ret) { skipped.push({ packageId, reason: 'RETENTION_NOT_SET' }); continue; }
      if (now < Date.parse(ret.retainUntil)) {
        skipped.push({ packageId, reason: 'RETENTION_NOT_EXPIRED', retainUntil: ret.retainUntil });
        continue;
      }
      const active = this.activeHolds(packageId);
      if (active.length) {
        skipped.push({
          packageId, reason: 'HOLDS_ACTIVE',
          activeHolds: active.map((h) => ({ holdId: h.holdId, caseNo: h.caseNo })),
        });
        continue;
      }
      try {
        const out = this.executeDestruction(packageId, {
          requestedBy, reason: '保留期限到期且无有效保全（到期任务）',
        });
        destroyed.push({ packageId, receiptId: out.receipt.receiptId });
      } catch (e) {
        errors.push({ packageId, code: e.code || 'INTERNAL', error: e.message });
      }
    }
    return { at: this._now().toISOString(), destroyed, skipped, errors };
  }

  // 待销毁列表：合格（已到期无保全）/ 被保全阻塞 / 在途（提交中、失败）。
  pendingDestruction() {
    const now = this.nowMs();
    const eligible = [];
    const blocked = [];
    const inFlight = [];
    for (const packageId of this.#listPackages()) {
      const st = this.destructionStatus(packageId);
      if (st.status !== 'NONE') {
        inFlight.push({ packageId, status: st.status, receiptId: st.receiptId ?? null });
        continue;
      }
      const ret = this.retention.get(packageId);
      if (!ret || now < Date.parse(ret.retainUntil)) continue;
      const active = this.activeHolds(packageId);
      const entry = { packageId, retainUntil: ret.retainUntil, activeHoldCount: active.length };
      if (active.length) {
        blocked.push({ ...entry, holds: active.map((h) => ({ holdId: h.holdId, caseNo: h.caseNo })) });
      } else {
        eligible.push(entry);
      }
    }
    return { now: this._now().toISOString(), eligible, blocked, inFlight };
  }

  // 单包生命周期视图（期限/保全/销毁状态/资格），供页面与接口核对。
  packageLifecycleView(packageId) {
    const exists = this.#packageExists(packageId);
    const ret = this.retention.get(packageId) || null;
    const now = this.nowMs();
    const holds = [...this.holds.values()]
      .filter((h) => h.packageId === packageId)
      .sort((a, b) => (a.holdId < b.holdId ? -1 : 1));
    const active = holds.filter((h) => h.status === 'ACTIVE');
    const destruction = this.destructionStatus(packageId);
    const blockers = [];
    if (!exists) blockers.push('PACKAGE_UNKNOWN');
    if (destruction.status !== 'NONE') blockers.push(`DESTRUCTION_${destruction.status}`);
    if (!ret) blockers.push('RETENTION_NOT_SET');
    else if (now < Date.parse(ret.retainUntil)) blockers.push('RETENTION_NOT_EXPIRED');
    if (active.length) blockers.push('HOLDS_ACTIVE');
    const eligible = exists && destruction.status === 'NONE' && Boolean(ret)
      && now >= Date.parse(ret.retainUntil) && active.length === 0;
    return {
      packageId,
      exists,
      now: this._now().toISOString(),
      retention: ret ? { ...ret, expired: now >= Date.parse(ret.retainUntil) } : null,
      holds,
      activeHoldCount: active.length,
      destruction,
      eligible,
      blockers,
    };
  }

  listReceipts() {
    return [...this.receipts.values()]
      .map((r) => ({
        receiptId: r.receiptId,
        packageId: r.packageId,
        committedAt: r.committedAt,
        requestedBy: r.requestedBy,
        removed: r.removed,
        status: this.destructionStatus(r.packageId).status,
      }))
      .sort((a, b) => (a.committedAt < b.committedAt ? -1 : 1));
  }

  receiptOf(receiptId) {
    return this.receipts.get(receiptId) || null;
  }

  receiptForPackage(packageId) {
    const d = this.destructions.get(packageId);
    return d?.committed?.receipt || null;
  }

  // 回执验签：哈希自洽 + Ed25519 签名 + 链锚定 + 结构不含原始证据。
  verifyReceipt(receiptId) {
    const receipt = this.receipts.get(receiptId);
    if (!receipt) return null;
    const { signature, keyId, receiptHash, ...body } = receipt;
    const recomputed = sha256Hex(canonicalJSON(body));
    const fileKeysOk = receipt.files.every((f) => {
      const keys = Object.keys(f).sort();
      return keys.join(',') === 'bytes,category,path,sha256' && HEX64.test(f.sha256);
    });
    const checks = {
      receiptHashOk: recomputed === receipt.receiptHash,
      signatureOk: this.signer.verify(receipt.receiptHash, signature),
      keyIdOk: keyId === this.signer.keyId,
      filesHashed: receipt.files.every((f) => HEX64.test(f.sha256)),
      noRawEvidence: fileKeysOk
        && !('records' in receipt) && !('entries' in receipt)
        && receipt.evidenceSummary != null && !('timeline' in (receipt.evidenceSummary || {})),
      chainAnchored: this.chain.records.some((r) => r.kind === 'DESTRUCTION_COMMITTED' && r.receiptId === receiptId),
      chainOk: this.chain.verify().ok,
    };
    return {
      ok: Object.values(checks).every(Boolean),
      checks,
      receiptId,
      packageId: receipt.packageId,
      keyId,
      publicKeyPem: this.signer.publicKeyPem,
      note: '独立验签：receiptHash = sha256(canonicalJSON(回执去掉 signature/keyId/receiptHash))；signature = Ed25519(公钥, receiptHash hex 文本)',
    };
  }
}
