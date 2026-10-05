// 资格闸只增 JSONL 哈希链（data/gate/gate.log）。
//
// 记录：{ seq, ts, type, payload, prevHash, hash }
// hash = sha256(canonicalJSON({seq,ts,type,payload,prevHash}))
// genesis = sha256("gate-chain-v1|ledger")，跨服务调换记录即断链。
//
// 所有状态变化都以“命令”形式追加（设备/事件/规则版本/申请/裁决/复核/冻结/密钥发布），
// 当前状态是链的纯投影：重启逐行重放后，裁决顺序（seq）、规则版本链、批次绑定逐字节复原。
//
// 恢复契约（与主编排/证据服务一致）：
//  - 完整记录异常（序号/断链/哈希不符/结构损坏）→ 只读隔离 QUARANTINED，文件原样保留；
//  - 仅文件末尾一条未写完且无终止换行的残尾（断电）→ 原样归档到 quarantine/ 后截断续链。
import {
  existsSync,
  mkdirSync,
  appendFileSync,
  writeFileSync,
  truncateSync,
  readFileSync,
  chmodSync,
} from 'node:fs';
import { dirname, join } from 'node:path';
import { createHash } from 'node:crypto';
import { canonicalJSON, sha256Hex } from './util.js';

export function gateGenesis() {
  return sha256Hex('gate-chain-v1|ledger');
}

const HASH_RE = /^[0-9a-f]{64}$/;

export class ChainQuarantineError extends Error {
  constructor(recovery) {
    super(`资格闸账本已隔离（只读）：${recovery?.reason ?? '未知原因'}`);
    this.code = 'CHAIN_QUARANTINED';
    this.status = 503;
    this.recovery = recovery;
  }
}

function hashRecord(rec) {
  const { hash, ...rest } = rec;
  void hash;
  return sha256Hex(canonicalJSON(rest));
}

export class GateChain {
  // file 为 null 时纯内存（测试 / GATE_MEMORY=1）。
  constructor(file = null) {
    this.file = file;
    this.records = [];
    this.seq = 0;
    this.tipHash = gateGenesis();
    this.mode = 'OK';
    this.recovery = null;
    if (file && dirname(file) && dirname(file) !== '.') {
      mkdirSync(dirname(file), { recursive: true, mode: 0o700 });
      try { chmodSync(dirname(file), 0o700); } catch { /* 已存在目录权限收紧失败不阻断 */ }
    }
  }

  get writable() {
    return this.mode !== 'QUARANTINED';
  }

  append(type, payload, ts) {
    if (this.mode === 'QUARANTINED') throw new ChainQuarantineError(this.recovery);
    const rec = {
      seq: this.seq + 1,
      ts: ts ?? null,
      type,
      payload: payload ?? {},
      prevHash: this.tipHash,
    };
    rec.hash = hashRecord(rec);
    this.records.push(rec);
    this.seq = rec.seq;
    this.tipHash = rec.hash;
    if (this.file) {
      const existed = existsSync(this.file);
      appendFileSync(this.file, JSON.stringify(rec) + '\n', { mode: 0o600 });
      if (!existed) { try { chmodSync(this.file, 0o600); } catch { /* 忽略 */ } }
    }
    return rec;
  }

  all() {
    return this.records;
  }

  truncate() {
    this.records = [];
    this.seq = 0;
    this.tipHash = gateGenesis();
    this.mode = 'OK';
    this.recovery = null;
    if (this.file) writeFileSync(this.file, '');
  }

  static #problem(rec, expectedSeq, prevHash) {
    if (rec === null || typeof rec !== 'object' || Array.isArray(rec)) return '记录不是合法 JSON 对象';
    if (rec.seq !== expectedSeq) return `序号异常：期望 ${expectedSeq}，实际 ${JSON.stringify(rec.seq)}`;
    if (typeof rec.type !== 'string' || !rec.type) return '记录缺少合法 type';
    if (!('payload' in rec) || rec.payload === null || typeof rec.payload !== 'object') {
      return '记录缺少合法 payload';
    }
    if (!HASH_RE.test(rec.prevHash)) return '记录缺少合法 prevHash';
    if (!HASH_RE.test(rec.hash)) return '记录缺少合法 hash';
    if (rec.prevHash !== prevHash) return 'prevHash 不衔接（链断裂）';
    if (hashRecord(rec) !== rec.hash) return '记录内容与哈希不符（记录被改写）';
    return null;
  }

  verify() {
    const base = { mode: this.mode, writable: this.writable, recovery: this.recovery };
    if (this.mode === 'QUARANTINED') {
      return { ...base, ok: false, length: this.records.length, tipHash: this.tipHash, ...(this.recovery || {}) };
    }
    let prev = gateGenesis();
    for (let i = 0; i < this.records.length; i++) {
      const r = this.records[i];
      const problem = GateChain.#problem(r, i + 1, prev);
      if (problem) {
        return { ...base, ok: false, length: this.records.length, tipHash: this.tipHash, brokenAt: r.seq, reason: problem };
      }
      prev = r.hash;
    }
    return { ...base, ok: true, length: this.records.length, tipHash: this.tipHash };
  }

  load() {
    if (!this.file || !existsSync(this.file)) return this.verify();
    const buf = readFileSync(this.file);
    // 幂等：允许重复 load（如测试先 load 再交给内核 init）。从 genesis 重置投影，
    // 避免把已读记录再次叠加导致“序号异常”误隔离。
    this.records = [];
    this.seq = 0;
    this.tipHash = gateGenesis();
    this.mode = 'OK';
    this.recovery = null;
    if (!buf.length) return this.verify();

    const lines = [];
    let start = 0;
    for (let i = 0; i < buf.length; i++) {
      if (buf[i] === 0x0a) {
        lines.push({ start, end: i, complete: true });
        start = i + 1;
      }
    }
    if (start < buf.length) lines.push({ start, end: buf.length, complete: false });

    let prev = gateGenesis();
    let torn = null;
    for (let li = 0; li < lines.length; li++) {
      const ln = lines[li];
      const raw = buf.subarray(ln.start, ln.end);
      const text = raw.toString('utf8').replace(/\r$/, '').trim();
      if (!text) continue;
      let rec;
      try {
        rec = JSON.parse(text);
      } catch {
        const isLastLine = li === lines.length - 1;
        const bytesAfter = buf.length - ln.end - (ln.complete ? 1 : 0);
        if (isLastLine && bytesAfter === 0 && !ln.complete) {
          torn = { line: ln, raw };
          break;
        }
        return this.#quarantine({
          kind: 'corrupt',
          brokenAt: this.records.length + 1,
          lineNo: li + 1,
          byteOffset: ln.start,
          reason: ln.complete
            ? '损坏的链行：物理行完整（含换行）但无法解析为 JSON'
            : '文件中部存在无法解析的链行（残尾之后仍有内容）',
        });
      }
      const expectedSeq = this.records.length + 1;
      const problem = GateChain.#problem(rec, expectedSeq, prev);
      if (problem) {
        return this.#quarantine({
          kind: 'corrupt', brokenAt: expectedSeq, foundSeq: rec?.seq,
          lineNo: li + 1, byteOffset: ln.start, reason: problem,
        });
      }
      this.records.push(rec);
      this.seq = rec.seq;
      this.tipHash = rec.hash;
      prev = rec.hash;
    }

    if (torn) this.#recoverTornTail(buf, torn.raw, torn.line);
    return this.verify();
  }

  #recoverTornTail(buf, rawTail, line) {
    const dir = this.file ? dirname(this.file) : '.';
    const qdir = join(dir, 'quarantine');
    mkdirSync(qdir, { recursive: true });
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    const base = `torn-gate-${stamp}-${process.pid}`;
    const archivePath = join(qdir, `${base}.log`);
    const metaPath = join(qdir, `${base}.meta.json`);
    const tailSha256 = createHash('sha256').update(rawTail).digest('hex');
    let truncatedAt = line.start;
    if (truncatedAt > 0 && buf[truncatedAt - 1] !== 0x0a) {
      appendFileSync(this.file, '\n');
      truncatedAt += 1;
    }
    writeFileSync(archivePath, rawTail, { mode: 0o600 });
    writeFileSync(metaPath, JSON.stringify({
      kind: 'torn-tail',
      recoveredAt: new Date().toISOString(),
      sourceLog: this.file,
      truncatedAt,
      tailBytes: rawTail.length,
      tailSha256,
      lastGoodSeq: this.seq,
      lastGoodHash: this.tipHash,
    }, null, 2) + '\n');
    truncateSync(this.file, truncatedAt);
    this.recovery = {
      kind: 'torn-tail-recovered',
      reason: '账本末尾检测到单条不完整记录（断电残尾），已归档并截断，从最后一条完好记录续链',
      brokenAt: this.seq + 1,
      tailBytes: rawTail.length,
      tailSha256,
      archivePath,
      archiveMetaPath: metaPath,
      recoveredAt: new Date().toISOString(),
    };
  }

  #quarantine(info) {
    this.mode = 'QUARANTINED';
    this.recovery = info;
    return this.verify();
  }
}
