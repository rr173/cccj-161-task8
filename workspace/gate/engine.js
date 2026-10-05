// 灵活负荷资格闸 · 领域内核（事件溯源 + 哈希链投影，零依赖）。
//
// 职责：
//   - 调度员维护“按设备 / 地区 / 生效日期组合”的资格规则；规则版本只增不可变，
//     支持定时生效、撤销、回滚（回滚 = 追加一个内容等同旧版的新版本，旧记录字节不动）。
//   - 聚合商用一个申请号提交一批设备参加指定响应事件；服务对每台设备独立裁决
//     （准入/拒绝 + 逐项拒绝原因），裁决绑定【当时的规则版本全文与版本摘要】并逐设备 Ed25519 签名。
//   - 同一申请号 + 相同正文 → 原样返回首次裁决；同一申请号 + 不同正文 → 409。
//   - 已生成批次永远锚定生成时版本，后续规则发布/撤销/回滚不追改历史裁决。
//   - 命令经单写队列严格串行，按到达次序落账（seq 即全局裁决次序）；状态全部由链重放重建。
import { canonicalJSON, sha256Hex, iso, startOfDay } from './util.js';
import { verifyBytes } from './crypto.js';

export const ZERO_HASH = '0'.repeat(64);
export const DAY_MS = 86400_000;

// 固定仿真起点（UTC）。时间只由 SEED_CLOCK / SIM_TICK 改变，保证演示与测试可重复。
export const SEED_NOW = Date.UTC(2026, 9, 5, 8, 0, 0); // 2026-10-05T08:00:00Z

export function err(code, message, status = 400, details = {}) {
  return Object.assign(new Error(message), { code, status, details });
}

// ---------------------------------------------------------------------------
// 纯函数：逐设备资格评估（试算与正式裁决共用，无副作用，便于单测）。
//
// 入参：
//   device 注册表设备（含 region/tags/status），未知设备传 null
//   event  响应事件 {region,startMs,...}
//   rules  当前规则视图：Map(ruleId → {current: 版本|null})（版本为已发布、含状态标记）
//   atMs   裁决时刻（决定定时生效/过期/最短提前期）
// 返回：{ outcome:'ADMITTED'|'REJECTED', reasons:[{code,message,detail}], rule: 版本快照|null }
// ---------------------------------------------------------------------------
export function evaluateDevice(device, event, rules, atMs) {
  if (!device) {
    // 未知设备：注册表之外无地区/标签可查，只给这一条终局原因。
    return {
      outcome: 'REJECTED',
      reasons: [{ code: 'UNKNOWN_DEVICE', message: '设备未在资格闸注册（未知设备）' }],
      rule: null,
    };
  }

  const reasons = [];

  // 1) 跨区域：设备归属地区与响应事件地区不一致（独立检查，可与其他原因并列）。
  if (event.region !== device.region) {
    reasons.push({
      code: 'CROSS_REGION',
      message: `跨区域申报：设备属 ${device.region}，事件在 ${event.region}`,
      detail: { deviceRegion: device.region, eventRegion: event.region },
    });
  }

  // 2) 已被暂停（独立检查）。
  if (device.status === 'SUSPENED' || device.status === 'SUSPENDED') {
    reasons.push({
      code: 'DEVICE_SUSPENDED',
      message: '设备已被暂停参与需求响应',
      detail: { suspendedAt: device.suspendedAt ?? null, reason: device.suspendReason ?? null },
    });
  }

  // 3) 规则选择（按设备归属地区 + 事件日期匹配，与跨区域判定互不掩盖）。
  const date = event.date;
  const active = [];
  const revoked = [];
  const expired = [];
  const pending = [];

  for (const r of rules.values()) {
    const v = r.current;
    if (!v) {
      // 当前无有效版本（规则被撤销）：检查其最近版本的适用面/日期窗是否本应覆盖
      // 本设备+事件日期，用于在“没有任何有效规则”时给出 RULE_REVOKED 而非笼统的 NO_RULE。
      const last = r.list?.at(-1);
      if (last && last.status === 'REVOKED' && scopeCovers(last.scope, device) && windowCovers(last, date)) {
        revoked.push(last);
      }
      continue;
    }
    if (!scopeCovers(v.scope, device)) continue;
    if (!windowCovers(v, date)) continue;
    const phase = versionPhase(v, atMs);
    if (phase === 'ACTIVE') active.push(v);
    else if (phase === 'PENDING') pending.push(v);
    else if (phase === 'EXPIRED') expired.push(v);
  }

  let chosen = null;
  if (active.length === 0) {
    // 没有任何现行规则时，原因有明确优先级：撤销 > 过期 > 未到生效 > 从无规则。
    if (revoked.length) {
      reasons.push({
        code: 'RULE_REVOKED',
        message: '唯一适用的资格规则版本已被撤销，尚无替代版本',
        detail: { rules: revoked.map(ruleRef) },
      });
    } else if (expired.length) {
      reasons.push({
        code: 'RULE_EXPIRED',
        message: '适用的资格规则已过有效期（过期规则）',
        detail: { rules: expired.map(ruleRef) },
      });
    } else if (pending.length) {
      const soon = pending.map((v) => v.effectiveFrom).sort()[0];
      reasons.push({
        code: 'RULE_PENDING',
        message: `适用的资格规则尚未到生效日（${soon} 起生效）`,
        detail: { effectiveFrom: soon, rules: pending.map(ruleRef) },
      });
    } else {
      reasons.push({
        code: 'NO_QUALIFICATION_RULE',
        message: `地区 ${device.region} 在 ${date} 没有覆盖该设备的资格规则`,
      });
    }
  } else {
    // 同适用面多条规则：先按特异性（设备级 > 地区级），再按调度员设定的 priority（小者优先），
    // 仍同优先级且不止一条 → 判定为重叠规则，拒绝并列出全部碰撞版本（不替调度员猜）。
    const topSpec = Math.max(...active.map((v) => specificity(v.scope)));
    let layer = active.filter((v) => specificity(v.scope) === topSpec);
    const topPriority = Math.min(...layer.map((v) => v.priority));
    const winners = layer.filter((v) => v.priority === topPriority);
    layer = winners;
    if (winners.length > 1) {
      const collide = winners
        .map(ruleRef)
        .sort((a, b) => a.ruleId.localeCompare(b.ruleId));
      reasons.push({
        code: 'RULE_OVERLAP',
        message: '同一设备/地区/日期命中多条同优先级的重叠资格规则，需调度员明确优先级',
        detail: { specificity: topSpec, priority: topPriority, rules: collide },
      });
    } else {
      chosen = winners[0];
    }
  }

  // 互斥标签与最短提前期依赖唯一中选规则；规则缺失/重叠时不再继续（原因已给）。
  if (chosen) {
    const hit = (device.tags || []).filter((t) => (chosen.mutexTags || []).includes(t));
    if (hit.length) {
      reasons.push({
        code: 'MUTEX_TAG',
        message: `设备命中互斥标签：${hit.join('、')}`,
        detail: { tags: hit, ruleId: chosen.ruleId, version: chosen.version },
      });
    }
    const actualMin = Math.floor((event.startMs - atMs) / 60000);
    if (actualMin < chosen.minLeadMinutes) {
      reasons.push({
        code: 'LEAD_TIME_TOO_SHORT',
        message: `不满足最短提前期：要求 ${chosen.minLeadMinutes} 分钟，实际仅剩 ${actualMin} 分钟`,
        detail: {
          requiredMinutes: chosen.minLeadMinutes,
          actualMinutes: actualMin,
          eventStartMs: event.startMs,
          atMs,
          ruleId: chosen.ruleId,
          version: chosen.version,
        },
      });
    }
  }

  return {
    outcome: reasons.length ? 'REJECTED' : 'ADMITTED',
    reasons,
    rule: chosen ? ruleSnapshot(chosen) : null,
  };
}

function scopeCovers(scope, device) {
  if (scope.deviceId) {
    return scope.deviceId === device.deviceId && scope.region === device.region;
  }
  return scope.region === device.region;
}

function windowCovers(v, date) {
  if (v.effectiveFrom && date < v.effectiveFrom) return false;
  if (v.effectiveTo && date > v.effectiveTo) return false;
  return true;
}

// 规则在裁决时刻的生命周期相位：PENDING（未到生效日）/ ACTIVE / EXPIRED（已过失效日）。
function versionPhase(v, atMs) {
  if (atMs < startOfDay(v.effectiveFrom)) return 'PENDING';
  if (v.effectiveTo && atMs >= startOfDay(v.effectiveTo) + DAY_MS) return 'EXPIRED';
  return 'ACTIVE';
}

function specificity(scope) {
  return scope.deviceId ? 2 : 1;
}

function ruleRef(v) {
  return { ruleId: v.ruleId, version: v.version, versionHash: v.versionHash, priority: v.priority };
}

// 钉入裁决的规则版本快照（后续规则变更绝不影响该对象）。
function ruleSnapshot(v) {
  return {
    ruleId: v.ruleId,
    version: v.version,
    versionHash: v.versionHash,
    prevVersionHash: v.prevVersionHash,
    scope: v.scope,
    effectiveFrom: v.effectiveFrom,
    effectiveTo: v.effectiveTo,
    minLeadMinutes: v.minLeadMinutes,
    mutexTags: v.mutexTags,
    priority: v.priority,
  };
}

// 逐设备签名载荷（schema 固定；任何实现按 canonicalJSON 重算即可独立验签）。
export function decisionPayload(input) {
  return {
    schema: 'gate-decision/v1',
    applicationNo: input.applicationNo,
    eventId: input.eventId,
    aggregatorId: input.aggregatorId,
    ordinal: input.ordinal,
    deviceId: input.deviceId,
    deviceRegion: input.deviceRegion,
    outcome: input.outcome,
    reasons: input.reasons,
    rule: input.rule,
    decidedAt: input.decidedAt,
  };
}

// 冻结批次清单载荷。
export function manifestPayload(input) {
  return {
    schema: 'gate-batch-manifest/v1',
    applicationNo: input.applicationNo,
    eventId: input.eventId,
    aggregatorId: input.aggregatorId,
    bodyHash: input.bodyHash,
    frozenAt: input.frozenAt,
    frozenBy: input.frozenBy,
    items: input.items,
  };
}

// ---------------------------------------------------------------------------
// 内核
// ---------------------------------------------------------------------------
export class GateEngine {
  // chain: GateChain；keys: GateKeyStore；nowMs 仅测试用（正常走种子时钟）。
  constructor(chain, keys, { nowMs = null } = {}) {
    this.chain = chain;
    this.keys = keys;
    this.#queue = Promise.resolve();
    this.s = {
      nowMs: nowMs ?? SEED_NOW,
      seeded: false,
      devices: new Map(),
      events: new Map(),
      rules: new Map(),
      apps: new Map(),
      bodyIndex: new Map(),
    };
  }

  #queue;

  now() {
    return this.s.nowMs;
  }

  // 重放整条链重建投影；签名不重算（历史签名是链上事实）。
  #replay() {
    for (const rec of this.chain.all()) this.#project(rec);
  }

  // 启动：从磁盘加载并校验哈希链（残尾续链/损坏隔离在 ChainLog 内完成），
  // 再从空投影重放；空库则确定性播种（追加即投影）；最后确保签发密钥。
  async init() {
    return this.#enqueue(() => {
      this.chain.load();
      this.#freshState();
      this.#replay();
      if (this.chain.seq === 0) this.#seed();
      this.#ensureKey();
    });
  }

  // 所有写命令经单写队列串行：到达顺序 === 落账顺序 === 裁决 seq 顺序。
  dispatch(cmd) {
    return this.#enqueue(() => this.#handle(cmd));
  }

  #enqueue(job) {
    const run = this.#queue.then(job);
    // 不让单个失败污染整条队列。
    this.#queue = run.then(() => {}, () => {});
    return run;
  }

  #append(type, payload, ts = null) {
    const rec = this.chain.append(type, payload, ts ?? iso(this.s.nowMs));
    // 追加即投影：命令路径下内存状态与链实时一致；重启时另由 #replay 从空投影重建。
    this.#project(rec);
    return rec;
  }

  #ensureKey() {
    const need = !this.keys.current;
    if (need) {
      const pub = this.keys.rotate(iso(this.s.nowMs));
      this.#append('GATE_KEY_PUBLISHED', pub);
    }
  }

  // 轮换签发密钥：只追加新版本（旧 keyId 永不删除，历史批次仍按旧公钥复验）；
  // 新裁决自动改用新 keyId。公钥上链，私钥只落 sidecar。
  #rotateKey(cmd) {
    const pub = this.keys.rotate(iso(this.s.nowMs));
    const rec = this.#append('GATE_KEY_PUBLISHED', { ...pub, rotatedBy: cmd.by ?? null });
    return { ...pub, seq: rec.seq, totalKeys: this.keys.listPublic().length };
  }

  // -------------------------------------------------------------------------
  // 投影
  // -------------------------------------------------------------------------
  #project(rec) {
    const p = rec.payload;
    switch (rec.type) {
      case 'SEED_CLOCK':
      case 'SIM_TICK':
        this.s.nowMs = p.nowMs;
        break;
      case 'SEED_DEVICE':
      case 'DEVICE_REGISTERED':
        this.s.devices.set(p.deviceId, { ...p });
        break;
      case 'DEVICE_SUSPENDED': {
        const d = this.s.devices.get(p.deviceId);
        if (d) Object.assign(d, { status: 'SUSPENDED', suspendedAt: p.at, suspendReason: p.reason ?? null });
        break;
      }
      case 'DEVICE_RESUMED': {
        const d = this.s.devices.get(p.deviceId);
        if (d) Object.assign(d, { status: 'ACTIVE', suspendedAt: null, suspendReason: null });
        break;
      }
      case 'SEED_EVENT':
      case 'EVENT_REGISTERED':
        this.s.events.set(p.eventId, { ...p });
        break;
      case 'GATE_KEY_PUBLISHED':
        this.keys.reconcile(p);
        break;
      case 'SEED_RULE':
      case 'RULE_VERSION_PUBLISHED':
        this.#projectVersion(p);
        break;
      case 'RULE_VERSION_REVOKED': {
        const r = this.s.rules.get(p.ruleId);
        const v = r?.versions.get(p.version);
        if (v) {
          v.status = 'REVOKED';
          v.revokedAt = p.at;
          v.revokeReason = p.reason ?? null;
          v.revokedBy = p.by ?? null;
          r.current = null;
        }
        break;
      }
      case 'RULE_ROLLED_BACK':
        this.#projectVersion(p.version, { rolledBackFrom: p.targetVersion, rollbackReason: p.reason ?? null });
        break;
      case 'APPLICATION_ACCEPTED':
        this.s.apps.set(p.applicationNo, appFromRecord({ ...p, seq: rec.seq }));
        this.s.bodyIndex.set(p.bodyHash, p.applicationNo);
        break;
      case 'ITEM_REVIEWED': {
        const app = this.s.apps.get(p.applicationNo);
        const d = app?.decisions.find((x) => x.deviceId === p.deviceId);
        if (d) {
          d.review = {
            reviewer: p.reviewer,
            disposition: p.disposition,
            note: p.note ?? null,
            at: p.at,
            seq: rec.seq,
            reviewSeq: p.reviewSeq,
          };
        }
        break;
      }
      case 'BATCH_FROZEN': {
        const app = this.s.apps.get(p.applicationNo);
        if (app) {
          app.frozen = {
            at: p.at,
            by: p.by ?? null,
            manifest: p.manifest,
            manifestDigest: p.manifestDigest,
            keyId: p.keyId,
            signature: p.signature,
            seq: rec.seq,
          };
        }
        break;
      }
      default:
        break;
    }
  }

  #projectVersion(v, extra = {}) {
    let r = this.s.rules.get(v.ruleId);
    if (!r) {
      r = { ruleId: v.ruleId, current: null, versions: new Map(), list: [] };
      this.s.rules.set(v.ruleId, r);
    }
    const stored = { ...v, ...extra };
    r.versions.set(v.version, stored);
    r.list.push(stored);
    r.current = stored;
  }

  // -------------------------------------------------------------------------
  // 命令处理
  // -------------------------------------------------------------------------
  #handle(cmd) {
    if (!this.chain.writable) {
      const e = new Error('资格闸账本已隔离（只读）');
      e.code = 'CHAIN_QUARANTINED';
      e.status = 503;
      e.recovery = this.chain.recovery;
      throw e;
    }
    switch (cmd.type) {
      case 'TICK': return this.#tick(cmd);
      case 'RESET': return this.#reset();
      case 'REGISTER_DEVICE': return this.#registerDevice(cmd);
      case 'SUSPEND_DEVICE': return this.#setSuspended(cmd, true);
      case 'RESUME_DEVICE': return this.#setSuspended(cmd, false);
      case 'REGISTER_EVENT': return this.#registerEvent(cmd);
      case 'ROTATE_GATE_KEY': return this.#rotateKey(cmd);
      case 'PUBLISH_RULE': return this.#publishRule(cmd);
      case 'REVOKE_RULE': return this.#revokeRule(cmd);
      case 'ROLLBACK_RULE': return this.#rollbackRule(cmd);
      case 'SUBMIT_APPLICATION': return this.#submitApplication(cmd);
      case 'REVIEW_ITEM': return this.#reviewItem(cmd);
      case 'FREEZE_BATCH': return this.#freezeBatch(cmd);
      default:
        throw err('UNKNOWN_COMMAND', `未知命令：${cmd.type}`, 400);
    }
  }

  #tick({ minutes }) {
    const m = Number(minutes);
    if (!Number.isFinite(m) || m <= 0) throw err('BAD_REQUEST', 'minutes 必须为正数');
    this.s.nowMs += m * 60000;
    const rec = this.#append('SIM_TICK', { nowMs: this.s.nowMs, advancedMinutes: m });
    return { ok: true, nowMs: this.s.nowMs, now: iso(this.s.nowMs), seq: rec.seq };
  }

  #reset() {
    this.chain.truncate();
    this.keys.reset?.();
    this.#freshState();
    this.#seed();
    this.#ensureKey();
    return this.stateView();
  }

  #freshState() {
    this.s = {
      nowMs: SEED_NOW,
      seeded: false,
      devices: new Map(),
      events: new Map(),
      rules: new Map(),
      apps: new Map(),
      bodyIndex: new Map(),
    };
  }

  #registerDevice(cmd) {
    const deviceId = reqStr(cmd, 'deviceId');
    const region = reqStr(cmd, 'region');
    if (this.s.devices.has(deviceId)) throw err('DEVICE_EXISTS', `设备 ${deviceId} 已注册`, 409);
    const device = {
      deviceId,
      region,
      name: cmd.name ?? null,
      capacityKw: numOrNull(cmd.capacityKw),
      tags: normalizeTags(cmd.tags),
      status: 'ACTIVE',
      registeredAt: iso(this.s.nowMs),
    };
    this.#append('DEVICE_REGISTERED', device);
    return device;
  }

  #setSuspended(cmd, suspended) {
    const device = this.requireDevice(cmd.deviceId);
    if (suspended && device.status === 'SUSPENDED') {
      throw err('DEVICE_ALREADY_SUSPENDED', `设备 ${device.deviceId} 已处于暂停状态`, 409);
    }
    if (!suspended && device.status !== 'SUSPENDED') {
      throw err('DEVICE_NOT_SUSPENDED', `设备 ${device.deviceId} 未暂停`, 409);
    }
    if (suspended) {
      const at = iso(this.s.nowMs);
      this.#append('DEVICE_SUSPENDED', { deviceId: device.deviceId, at, reason: cmd.reason ?? null, by: cmd.by ?? null });
      return { deviceId: device.deviceId, status: 'SUSPENDED', suspendedAt: at };
    }
    const at = iso(this.s.nowMs);
    this.#append('DEVICE_RESUMED', { deviceId: device.deviceId, at, by: cmd.by ?? null });
    return { deviceId: device.deviceId, status: 'ACTIVE', resumedAt: at };
  }

  #registerEvent(cmd) {
    const eventId = reqStr(cmd, 'eventId');
    const region = reqStr(cmd, 'region');
    const date = reqDay(cmd.effectiveDate ?? cmd.date, 'date');
    const startMs = reqNum(cmd, 'startMs');
    if (this.s.events.has(eventId)) throw err('EVENT_EXISTS', `事件 ${eventId} 已存在`, 409);
    if (startMs < startOfDay(date) || startMs >= startOfDay(date) + DAY_MS) {
      throw err('BAD_REQUEST', `事件开始时刻必须落在响应日期 ${date} 当日（UTC）`);
    }
    const ev = {
      eventId,
      region,
      date,
      startMs,
      startIso: iso(startMs),
      title: cmd.title ?? null,
      registeredAt: iso(this.s.nowMs),
    };
    this.#append('EVENT_REGISTERED', ev);
    return ev;
  }

  #normalizeRuleBody(cmd) {
    const scope = this.#normalizeScope(cmd.scope);
    const effectiveFrom = reqDay(cmd.effectiveFrom, 'effectiveFrom');
    const effectiveTo = cmd.effectiveTo == null || cmd.effectiveTo === ''
      ? null
      : reqDay(cmd.effectiveTo, 'effectiveTo');
    if (effectiveTo && effectiveTo < effectiveFrom) {
      throw err('BAD_REQUEST', 'effectiveTo 不得早于 effectiveFrom');
    }
    const minLeadMinutes = reqNonNegInt(cmd, 'minLeadMinutes');
    const mutexTags = normalizeTags(cmd.mutexTags);
    const priority = cmd.priority == null ? 100 : reqNonNegInt({ ...cmd, x: cmd.priority }, 'x');
    return {
      scope,
      effectiveFrom,
      effectiveTo,
      minLeadMinutes,
      mutexTags,
      priority,
      note: cmd.note ?? null,
    };
  }

  #normalizeScope(scope) {
    if (!scope || typeof scope !== 'object') throw err('SCOPE_INVALID', 'scope 必须为 {region, deviceId?}');
    const region = reqStr(scope, 'region');
    const deviceId = scope.deviceId == null || scope.deviceId === '' ? null : String(scope.deviceId);
    if (deviceId) {
      const d = this.s.devices.get(deviceId);
      if (!d) throw err('DEVICE_NOT_FOUND', `设备级规则引用了未知设备：${deviceId}`, 404);
      if (d.region !== region) {
        throw err(
          'SCOPE_REGION_MISMATCH',
          `设备级规则地区 ${region} 与设备归属地区 ${d.region} 不一致`,
          422,
          { deviceId, deviceRegion: d.region },
        );
      }
    }
    return { region, deviceId };
  }

  // 重叠检测只预警【真正会造成裁决歧义】的情形：
  //   - 地区级 vs 设备级：特异性不同，裁决时设备级优先，属于正常层次，不报；
  //   - 同适用面层级、日期窗重叠：
  //       * priority 不同 -> 可确定唯一中选，作为 advisory 提示（不阻断）；
  //       * priority 相同 -> 歧义重叠，发布即 409（除非 forceOverlap，此时裁决仍会拒绝命中设备）。
  #overlaps(excludeRuleId, scope, from, to) {
    const out = [];
    for (const [ruleId, r] of this.s.rules) {
      if (ruleId === excludeRuleId) continue;
      const v = r.current;
      if (!v) continue;
      if (sameScopeLevel(scope, v.scope) && sameRegionOrDevice(scope, v.scope)
        && dateWindowsOverlap(from, to, v.effectiveFrom, v.effectiveTo)) {
        out.push({
          ruleId,
          version: v.version,
          scope: v.scope,
          effectiveFrom: v.effectiveFrom,
          effectiveTo: v.effectiveTo,
          priority: v.priority,
        });
      }
    }
    return out;
  }

  #publishRule(cmd) {
    const body = this.#normalizeRuleBody(cmd);
    const ruleId = cmd.ruleId ? String(cmd.ruleId) : `RULE-${sha256Hex(canonicalJSON(body)).slice(0, 8)}`;
    const existing = this.s.rules.get(ruleId);
    const overlaps = this.#overlaps(ruleId, body.scope, body.effectiveFrom, body.effectiveTo);
    const ambiguous = overlaps.filter((o) => o.priority === body.priority);
    const advisory = overlaps.filter((o) => o.priority !== body.priority);
    if (ambiguous.length && !cmd.forceOverlap) {
      throw err(
        'RULE_OVERLAP_DETECTED',
        `规则与 ${ambiguous.length} 条同层级、同优先级、日期窗重叠的现行规则冲突，会造成裁决歧义；调整优先级或带 forceOverlap=true 发布`,
        409,
        { conflicts: ambiguous, advisory },
      );
    }

    let version;
    let prevVersionHash = ZERO_HASH;
    let wasRevoked = false;
    if (existing) {
      // 乐观并发控制：改版（含撤销后“复活”发版）必须显式声明基于的版本。
      //   expectedVersion 为数字 -> 必须等于当前有效版本；
      //   expectedVersion === 'REVOKED' -> 仅允许当前无有效版本（撤销后重试发版）。
      const baseVersion = existing.current ? existing.current.version : null;
      if (cmd.expectedVersion == null) {
        throw err('RULE_VERSION_CONFLICT', '改版必须携带 expectedVersion（乐观并发控制）', 409, {
          currentVersion: baseVersion,
          currentState: existing.current ? 'ACTIVE' : 'REVOKED',
        });
      }
      if (existing.current) {
        if (Number(cmd.expectedVersion) !== existing.current.version) {
          throw err('RULE_VERSION_CONFLICT', '规则版本冲突：expectedVersion 与当前版本不一致', 409, {
            expectedVersion: Number(cmd.expectedVersion),
            currentVersion: existing.current.version,
          });
        }
      } else if (String(cmd.expectedVersion) !== 'REVOKED') {
        throw err('RULE_VERSION_CONFLICT', '规则当前已撤销：请以 expectedVersion="REVOKED" 发布替代版本', 409, {
          currentVersion: null,
          currentState: 'REVOKED',
        });
      } else {
        wasRevoked = true;
      }
      version = existing.list.at(-1).version + 1;
      prevVersionHash = existing.list.at(-1).versionHash;
    } else {
      version = 1;
    }

    const v = {
      ruleId,
      version,
      prevVersionHash,
      status: 'ACTIVE',
      publishedAt: iso(this.s.nowMs),
      publishedBy: cmd.by ?? null,
      ...body,
    };
    v.versionHash = sha256Hex(canonicalJSON(versionBodyForHash(v)));

    const rec = this.#append('RULE_VERSION_PUBLISHED', v);
    return {
      rule: this.ruleView(ruleId),
      ambiguous,
      advisory,
      forced: !!cmd.forceOverlap && ambiguous.length > 0,
      // 在追加投影前判定：该规则之前存在但当前无有效版本 = 撤销后复活。
      revived: !!(existing && wasRevoked),
      seq: rec.seq,
    };
  }

  #revokeRule(cmd) {
    const r = this.requireRule(cmd.ruleId);
    if (!r.current) throw err('RULE_REVOKED_STATE', `规则 ${cmd.ruleId} 当前无有效版本（已撤销）`, 409);
    if (cmd.expectedVersion != null && Number(cmd.expectedVersion) !== r.current.version) {
      throw err('RULE_VERSION_CONFLICT', '规则版本冲突：expectedVersion 与当前版本不一致', 409, {
        expectedVersion: Number(cmd.expectedVersion),
        currentVersion: r.current.version,
      });
    }
    const at = iso(this.s.nowMs);
    const payload = {
      ruleId: r.ruleId,
      version: r.current.version,
      versionHash: r.current.versionHash,
      at,
      reason: cmd.reason ?? null,
      by: cmd.by ?? null,
    };
    const rec = this.#append('RULE_VERSION_REVOKED', payload);
    return { ...payload, seq: rec.seq };
  }

  // 回滚：以一个【新版本】复刻历史版本正文（append-only，旧版本与中间版本原样保留）。
  #rollbackRule(cmd) {
    const r = this.requireRule(cmd.ruleId);
    if (!r.current) throw err('RULE_REVOKED_STATE', `规则 ${cmd.ruleId} 已撤销，不能回滚；请重新发布`, 409);
    if (cmd.expectedVersion != null && Number(cmd.expectedVersion) !== r.current.version) {
      throw err('RULE_VERSION_CONFLICT', '规则版本冲突：expectedVersion 与当前版本不一致', 409, {
        expectedVersion: Number(cmd.expectedVersion),
        currentVersion: r.current.version,
      });
    }
    const targetVersion = Number(cmd.targetVersion ?? cmd.toVersion);
    if (!Number.isInteger(targetVersion) || !r.versions.has(targetVersion)) {
      throw err('VERSION_NOT_FOUND', `目标版本 ${targetVersion} 不存在`, 404);
    }
    const target = r.versions.get(targetVersion);
    // 回滚 = 用历史版本正文发布全新版本；即使目标版本曾被撤销，其正文仍可作为回滚内容。
    const newVersionNumber = r.current.version + 1;
    const v = {
      ruleId: r.ruleId,
      version: newVersionNumber,
      prevVersionHash: r.current.versionHash,
      status: 'ACTIVE',
      publishedAt: iso(this.s.nowMs),
      publishedBy: cmd.by ?? null,
      scope: target.scope,
      effectiveFrom: target.effectiveFrom,
      effectiveTo: target.effectiveTo,
      minLeadMinutes: target.minLeadMinutes,
      mutexTags: target.mutexTags,
      priority: target.priority,
      note: cmd.note ?? target.note,
    };
    v.versionHash = sha256Hex(canonicalJSON(versionBodyForHash(v)));
    const payload = {
      ruleId: r.ruleId,
      targetVersion,
      targetVersionHash: target.versionHash,
      reason: cmd.reason ?? null,
      by: cmd.by ?? null,
      at: iso(this.s.nowMs),
      version: v,
    };
    const rec = this.#append('RULE_ROLLED_BACK', payload);
    return {
      ruleId: r.ruleId,
      newVersion: this.ruleView(r.ruleId),
      rolledBackFrom: targetVersion,
      seq: rec.seq,
    };
  }

  // -------------------------------------------------------------------------
  // 申请 / 裁决 / 复核 / 冻结
  // -------------------------------------------------------------------------
  #submitApplication(cmd) {
    const applicationNo = reqStr(cmd, 'applicationNo');
    const eventId = reqStr(cmd, 'eventId');
    const aggregatorId = reqStr(cmd, 'aggregatorId');
    const event = this.s.events.get(eventId);
    if (!event) throw err('EVENT_NOT_FOUND', `响应事件 ${eventId} 不存在`, 404);
    const rawItems = Array.isArray(cmd.items) ? cmd.items : null;
    if (!rawItems) throw err('BAD_REQUEST', 'items 必须为数组（空批次用 []）');

    const normItems = [];
    const seen = new Set();
    for (const it of rawItems) {
      const deviceId = reqStr(it, 'deviceId');
      if (seen.has(deviceId)) throw err('DUPLICATE_ITEM', `批次内设备重复：${deviceId}`, 422);
      seen.add(deviceId);
      normItems.push({ deviceId, bidKw: numOrNull(it.bidKw) });
    }

    // 幂等指纹只取业务正文（不含 trial/头信息），规范化保证字段顺序无关。
    const bodyHash = sha256Hex(canonicalJSON({ applicationNo, eventId, aggregatorId, items: normItems }));
    const prior = this.s.apps.get(applicationNo);
    if (prior) {
      if (prior.bodyHash === bodyHash) {
        return { idempotent: true, application: this.appView(applicationNo) };
      }
      throw err(
        'APPLICATION_NO_CONFLICT',
        `申请号 ${applicationNo} 已用于不同正文（409）；原裁决原样保留，不会重算`,
        409,
        { existingBodyHash: prior.bodyHash, bodyHash, existingSeq: prior.seq },
      );
    }

    const decidedAt = iso(this.s.nowMs);
    const keyId = this.keys.currentKeyId;
    if (!keyId) {
      throw err('GATE_KEY_UNAVAILABLE', '资格闸签发密钥尚未就绪', 503);
    }

    const decisions = normItems.map((item, ordinal) => {
      const device = this.s.devices.get(item.deviceId) ?? null;
      const verdict = evaluateDevice(device, event, this.s.rules, this.s.nowMs);
      const payload = decisionPayload({
        applicationNo,
        eventId,
        aggregatorId,
        ordinal,
        deviceId: item.deviceId,
        deviceRegion: device?.region ?? null,
        outcome: verdict.outcome,
        reasons: verdict.reasons,
        rule: verdict.rule,
        decidedAt,
      });
      const canonical = canonicalJSON(payload);
      const digest = sha256Hex(canonical);
      const signature = this.keys.signWith(keyId, canonical);
      return {
        ordinal,
        deviceId: item.deviceId,
        bidKw: item.bidKw,
        deviceRegion: payload.deviceRegion,
        outcome: verdict.outcome,
        reasons: verdict.reasons,
        rule: verdict.rule,
        payload,
        decisionDigest: digest,
        keyId,
        signature,
        review: null,
      };
    });

    const admitted = decisions.filter((d) => d.outcome === 'ADMITTED').length;
    const record = {
      applicationNo,
      eventId,
      aggregatorId,
      bodyHash,
      submittedAt: iso(this.s.nowMs),
      decidedAt,
      keyId,
      items: normItems,
      decisions: decisions.map(serializeDecision),
      counts: { total: decisions.length, admitted, rejected: decisions.length - admitted },
    };
    const rec = this.#append('APPLICATION_ACCEPTED', record);
    void rec;
    return { idempotent: false, application: this.appView(applicationNo) };
  }

  #reviewItem(cmd) {
    const app = this.requireApp(cmd.applicationNo);
    const deviceId = reqStr(cmd, 'deviceId');
    const decision = app.decisions.find((d) => d.deviceId === deviceId);
    if (!decision) throw err('ITEM_NOT_FOUND', `批次 ${cmd.applicationNo} 中没有设备 ${deviceId}`, 404);
    if (app.frozen) throw err('BATCH_FROZEN', '批次已冻结，不可再追加复核', 409);
    if (decision.review) throw err('ITEM_ALREADY_REVIEWED', '该设备已复核（逐项复核仅可作出一次）', 409);
    const reviewer = reqStr(cmd, 'reviewer');
    const disposition = String(cmd.disposition || '').toUpperCase();
    if (!['CONFIRMED', 'OVERRULED'].includes(disposition)) {
      throw err('BAD_REQUEST', 'disposition 必须为 CONFIRM 或 OVERRULED 之一（维持初裁/标注异议）');
    }
    const reviewSeq = app.decisions.filter((d) => d.review).length + 1;
    const at = iso(this.s.nowMs);
    const payload = {
      applicationNo: app.applicationNo,
      deviceId,
      reviewer,
      disposition,
      note: cmd.note ?? null,
      at,
      reviewSeq,
    };
    const rec = this.#append('ITEM_REVIEWED', payload);
    // 复核只形成复核层：初裁 outcome / 签名载荷绝不改变（投影已由 append 完成）。
    return { ...payload, outcome: decision.outcome, seq: rec.seq };
  }

  #freezeBatch(cmd) {
    const app = this.requireApp(cmd.applicationNo);
    if (app.frozen) {
      return { idempotent: true, frozen: freezeView(app) };
    }
    const at = iso(this.s.nowMs);
    const keyId = this.keys.currentKeyId;
    const items = app.decisions.map((d) => ({
      ordinal: d.ordinal,
      deviceId: d.deviceId,
      outcome: d.outcome,
      reasons: d.reasons.map((x) => x.code),
      ruleVersion: d.rule ? { ruleId: d.rule.ruleId, version: d.rule.version, versionHash: d.rule.versionHash } : null,
      decisionDigest: d.decisionDigest,
      keyId: d.keyId,
      signature: d.signature,
      review: d.review ? { disposition: d.review.disposition, reviewer: d.review.reviewer } : null,
    }));
    const manifest = manifestPayload({
      applicationNo: app.applicationNo,
      eventId: app.eventId,
      aggregatorId: app.aggregatorId,
      bodyHash: app.bodyHash,
      frozenAt: at,
      frozenBy: cmd.by ?? null,
      items,
    });
    const canonical = canonicalJSON(manifest);
    const manifestDigest = sha256Hex(canonical);
    const signature = this.keys.signWith(keyId, canonical);
    const payload = {
      applicationNo: app.applicationNo,
      at,
      by: cmd.by ?? null,
      manifest,
      manifestDigest,
      keyId,
      signature,
    };
    const rec = this.#append('BATCH_FROZEN', payload);
    void rec;
    return { idempotent: false, frozen: freezeView(this.requireApp(app.applicationNo)) };
  }

  // -------------------------------------------------------------------------
  // 试算（只读，不写链、不签名）
  // -------------------------------------------------------------------------
  trial(cmd) {
    const event = this.s.events.get(reqStr(cmd, 'eventId'));
    if (!event) throw err('EVENT_NOT_FOUND', `响应事件 ${cmd.eventId} 不存在`, 404);
    if (!Array.isArray(cmd.items)) throw err('BAD_REQUEST', 'items 必须为数组（空批次用 []）');
    const atMs = cmd.atMs == null ? this.s.nowMs : Number(cmd.atMs);
    if (!Number.isFinite(atMs)) throw err('BAD_REQUEST', 'atMs 必须为毫秒时间戳数字');
    const decisions = [];
    const seen = new Set();
    cmd.items.forEach((it, ordinal) => {
      const deviceId = reqStr(it, 'deviceId');
      if (seen.has(deviceId)) throw err('DUPLICATE_ITEM', `试算设备重复：${deviceId}`, 422);
      seen.add(deviceId);
      const device = this.s.devices.get(deviceId) ?? null;
      const verdict = evaluateDevice(device, event, this.s.rules, atMs);
      decisions.push({
        ordinal,
        deviceId,
        deviceRegion: device?.region ?? null,
        known: !!device,
        outcome: verdict.outcome,
        reasons: verdict.reasons,
        rule: verdict.rule,
        evaluatedAt: iso(atMs),
        trial: true,
      });
    });
    return {
      trial: true,
      eventId: event.eventId,
      evaluatedAt: iso(atMs),
      count: decisions.length,
      admitted: decisions.filter((d) => d.outcome === 'ADMITTED').length,
      decisions,
    };
  }

  // -------------------------------------------------------------------------
  // 查询视图
  // -------------------------------------------------------------------------
  requireDevice(id) {
    const d = this.s.devices.get(String(id));
    if (!d) throw err('DEVICE_NOT_FOUND', `设备 ${id} 不存在`, 404);
    return d;
  }

  requireRule(id) {
    const r = this.s.rules.get(String(id));
    if (!r) throw err('RULE_NOT_FOUND', `规则 ${id} 不存在`, 404);
    return r;
  }

  requireApp(id) {
    const a = this.s.apps.get(String(id));
    if (!a) throw err('APPLICATION_NOT_FOUND', `申请批次 ${id} 不存在`, 404);
    return a;
  }

  listDevices() {
    return [...this.s.devices.values()];
  }

  listEvents() {
    return [...this.s.events.values()];
  }

  listRules() {
    return [...this.s.rules.keys()].map((id) => this.ruleView(id));
  }

  ruleView(ruleId) {
    const r = this.requireRule(ruleId);
    const v = r.current;
    return {
      ruleId: r.ruleId,
      currentVersion: v ? v.version : null,
      currentStatus: v ? versionPhase(v, this.s.nowMs) : 'REVOKED',
      current: v ? versionView(v, this.s.nowMs) : null,
      versions: r.list.map((x) => versionView(x, this.s.nowMs)),
    };
  }

  listApps() {
    return [...this.s.apps.values()].map((a) => ({
      applicationNo: a.applicationNo,
      eventId: a.eventId,
      aggregatorId: a.aggregatorId,
      submittedAt: a.submittedAt,
      seq: a.seq,
      keyId: a.keyId,
      counts: a.counts,
      frozen: a.frozen
        ? { at: a.frozen.at, manifestDigest: a.frozen.manifestDigest, keyId: a.frozen.keyId }
        : null,
      bodyHash: a.bodyHash,
    })).sort((a, b) => a.seq - b.seq);
  }

  appView(applicationNo) {
    const a = this.requireApp(applicationNo);
    return {
      applicationNo: a.applicationNo,
      eventId: a.eventId,
      aggregatorId: a.aggregatorId,
      submittedAt: a.submittedAt,
      decidedAt: a.decidedAt,
      seq: a.seq,
      bodyHash: a.bodyHash,
      keyId: a.keyId,
      counts: a.counts,
      decisions: a.decisions.map(decisionView),
      frozen: a.frozen ? freezeView(a) : null,
    };
  }

  // 独立验签：重算逐设备裁决的规范化字节、摘要，并用登记公钥验签。
  verifyDecision(applicationNo, deviceId) {
    const a = this.requireApp(applicationNo);
    const d = a.decisions.find((x) => x.deviceId === deviceId);
    if (!d) throw err('ITEM_NOT_FOUND', `批次中没有设备 ${deviceId}`, 404);
    const canonical = canonicalJSON(d.payload);
    const digest = sha256Hex(canonical);
    const valid = this.keys.verifyWith(d.keyId, canonical, d.signature);
    return {
      kind: 'decision',
      applicationNo,
      deviceId,
      keyId: d.keyId,
      publicKeyPem: this.keys.publicKey(d.keyId),
      canonical,
      digest,
      storedDigest: d.decisionDigest,
      digestMatches: digest === d.decisionDigest,
      signature: d.signature,
      valid,
    };
  }

  verifyManifest(applicationNo) {
    const a = this.requireApp(applicationNo);
    if (!a.frozen) throw err('BATCH_NOT_FROZEN', '批次尚未冻结，无清单可验', 409);
    const canonical = canonicalJSON(a.frozen.manifest);
    const digest = sha256Hex(canonical);
    const valid = this.keys.verifyWith(a.frozen.keyId, canonical, a.frozen.signature);
    return {
      kind: 'manifest',
      applicationNo,
      keyId: a.frozen.keyId,
      publicKeyPem: this.keys.publicKey(a.frozen.keyId),
      canonical,
      digest,
      storedDigest: a.frozen.manifestDigest,
      digestMatches: digest === a.frozen.manifestDigest,
      signature: a.frozen.signature,
      valid,
    };
  }

  // 用登记 keyId 或调用方自带公钥离线验任意签名。
  verifyOffline({ keyId, publicKeyPem, canonical, signature }) {
    const pem = publicKeyPem ?? this.keys.publicKey(keyId);
    const valid = verifyBytes(pem, String(canonical), String(signature));
    return { valid, keyId: keyId ?? null, digest: sha256Hex(String(canonical)) };
  }

  stateView() {
    return {
      service: 'flexible-load-qualification-gate',
      nowMs: this.s.nowMs,
      now: iso(this.s.nowMs),
      chain: this.chain.verify(),
      keys: this.keys.listPublic(),
      counts: {
        devices: this.s.devices.size,
        events: this.s.events.size,
        rules: this.s.rules.size,
        applications: this.s.apps.size,
      },
      devices: this.listDevices(),
      events: this.listEvents(),
      rules: this.listRules(),
      applications: this.listApps(),
    };
  }

  // -------------------------------------------------------------------------
  // 确定性种子
  // -------------------------------------------------------------------------
  #seed() {
    const at = iso(SEED_NOW);
    this.#append('SEED_CLOCK', { nowMs: SEED_NOW });

    const devices = [
      { deviceId: 'DEV-1001', region: 'ZJ', name: '杭州 1 号空调群', capacityKw: 120, tags: ['HVAC'] },
      { deviceId: 'DEV-1002', region: 'ZJ', name: '宁波关键负荷空调', capacityKw: 80, tags: ['HVAC', 'CRITICAL'] },
      { deviceId: 'DEV-1003', region: 'ZJ', name: '温州储能（检修暂停）', capacityKw: 200, tags: ['STORAGE'] },
      { deviceId: 'DEV-1004', region: 'JS', name: '苏州空调群', capacityKw: 150, tags: ['HVAC'] },
      { deviceId: 'DEV-1005', region: 'ZJ', name: '舟山海岛微网机组', capacityKw: 60, tags: ['ISLAND'] },
    ];
    for (const d of devices) {
      this.#append('SEED_DEVICE', {
        ...d,
        status: 'ACTIVE',
        suspendedAt: null,
        suspendReason: null,
        registeredAt: at,
      });
    }
    // DEV-1003 检修暂停。
    this.#append('DEVICE_SUSPENDED', {
      deviceId: 'DEV-1003',
      at,
      reason: '计划检修（种子）',
      by: 'seeder',
    });

    const events = [
      {
        eventId: 'EV-1008-ZJ', region: 'ZJ', date: '2026-10-08',
        startMs: Date.UTC(2026, 9, 8, 12, 0), title: '浙江 10/08 午峰响应',
      },
      {
        eventId: 'EV-1006-JS', region: 'JS', date: '2026-10-06',
        startMs: Date.UTC(2026, 9, 6, 12, 0), title: '江苏 10/06 午峰响应',
      },
      {
        eventId: 'EV-1005-FAST-ZJ', region: 'ZJ', date: '2026-10-05',
        startMs: Date.UTC(2026, 9, 5, 10, 0), title: '浙江 10/05 紧急两小时响应',
      },
    ];
    for (const e of events) {
      this.#append('SEED_EVENT', { ...e, startIso: iso(e.startMs), registeredAt: at });
    }

    const seedRules = [
      {
        ruleId: 'RULE-ZJ-GENERAL',
        scope: { region: 'ZJ', deviceId: null },
        effectiveFrom: '2026-10-01', effectiveTo: '2026-10-31',
        minLeadMinutes: 120, mutexTags: ['CRITICAL'], priority: 100,
        note: '浙江 10 月通用资格：提前 2 小时申报；关键负荷互斥',
      },
      {
        ruleId: 'RULE-JS-GENERAL',
        scope: { region: 'JS', deviceId: null },
        effectiveFrom: '2026-10-01', effectiveTo: '2026-10-31',
        minLeadMinutes: 120, mutexTags: [], priority: 100,
        note: '江苏 10 月通用资格：提前 2 小时申报',
      },
      {
        ruleId: 'RULE-ZJ-SEPT',
        scope: { region: 'ZJ', deviceId: null },
        effectiveFrom: '2026-09-01', effectiveTo: '2026-09-30',
        minLeadMinutes: 60, mutexTags: [], priority: 100,
        note: '浙江 9 月规则（演示：已过期）',
      },
      {
        ruleId: 'RULE-ZJ-NOV',
        scope: { region: 'ZJ', deviceId: null },
        effectiveFrom: '2026-11-01', effectiveTo: '2026-11-30',
        minLeadMinutes: 240, mutexTags: [], priority: 100,
        note: '浙江 11 月规则（演示：定时生效）',
      },
      {
        ruleId: 'RULE-DEV-1005',
        scope: { region: 'ZJ', deviceId: 'DEV-1005' },
        effectiveFrom: '2026-10-01', effectiveTo: '2026-10-31',
        minLeadMinutes: 60, mutexTags: ['ISLAND'], priority: 50,
        note: '海岛微网专用规则（演示：设备自带 ISLAND 互斥标签将被拒）',
      },
    ];
    for (const body of seedRules) {
      const v = {
        ruleId: body.ruleId,
        version: 1,
        prevVersionHash: ZERO_HASH,
        status: 'ACTIVE',
        publishedAt: at,
        publishedBy: 'seeder',
        scope: body.scope,
        effectiveFrom: body.effectiveFrom,
        effectiveTo: body.effectiveTo,
        minLeadMinutes: body.minLeadMinutes,
        mutexTags: body.mutexTags,
        priority: body.priority,
        note: body.note,
      };
      v.versionHash = sha256Hex(canonicalJSON(versionBodyForHash(v)));
      this.#append('SEED_RULE', v);
    }
    this.s.seeded = true;
  }
}

// ---------------------------------------------------------------------------
// 视图 / 序列化辅助
// ---------------------------------------------------------------------------
function versionView(v, nowMs) {
  return {
    ruleId: v.ruleId,
    version: v.version,
    versionHash: v.versionHash,
    prevVersionHash: v.prevVersionHash,
    scope: v.scope,
    effectiveFrom: v.effectiveFrom,
    effectiveTo: v.effectiveTo,
    minLeadMinutes: v.minLeadMinutes,
    mutexTags: v.mutexTags,
    priority: v.priority,
    note: v.note,
    publishedAt: v.publishedAt,
    publishedBy: v.publishedBy,
    status: v.status, // ACTIVE / REVOKED（管理生命周期）
    phase: v.status === 'REVOKED' ? 'REVOKED' : versionPhase(v, nowMs), // PENDING/ACTIVE/EXPIRED
    revokedAt: v.revokedAt ?? null,
    revokeReason: v.revokeReason ?? null,
    rolledBackFrom: v.rolledBackFrom ?? null,
  };
}

function decisionView(d) {
  return {
    ordinal: d.ordinal,
    deviceId: d.deviceId,
    deviceIdMasked: maskId(d.deviceId),
    bidKw: d.bidKw,
    deviceRegion: d.deviceRegion,
    outcome: d.outcome,
    reasons: d.reasons,
    rule: d.rule,
    decisionDigest: d.decisionDigest,
    keyId: d.keyId,
    signature: d.signature,
    review: d.review ? {
      reviewer: d.review.reviewer,
      disposition: d.review.disposition,
      note: d.review.note,
      at: d.review.at,
      reviewSeq: d.review.reviewSeq,
    } : null,
  };
}

function freezeView(a) {
  if (!a.frozen) return null;
  return {
    at: a.frozen.at,
    by: a.frozen.by,
    keyId: a.frozen.keyId,
    manifestDigest: a.frozen.manifestDigest,
    signature: a.frozen.signature,
    counts: a.counts,
    manifest: a.frozen.manifest,
  };
}

function serializeDecision(d) {
  return {
    ordinal: d.ordinal,
    deviceId: d.deviceId,
    bidKw: d.bidKw,
    deviceRegion: d.deviceRegion,
    outcome: d.outcome,
    reasons: d.reasons,
    rule: d.rule,
    payload: d.payload,
    decisionDigest: d.decisionDigest,
    keyId: d.keyId,
    signature: d.signature,
  };
}

function appFromRecord(p) {
  return {
    applicationNo: p.applicationNo,
    eventId: p.eventId,
    aggregatorId: p.aggregatorId,
    bodyHash: p.bodyHash,
    submittedAt: p.submittedAt,
    decidedAt: p.decidedAt,
    keyId: p.keyId,
    seq: p.seq ?? null,
    counts: p.counts,
    decisions: (p.decisions || []).map((d) => ({ ...d, review: null })),
    frozen: null,
  };
}

function versionBodyForHash(v) {
  // 版本摘要只对版本事实正文计算（不含 status/revokedAt 等后续状态标记，
  // 撤销是独立链上事件；回滚出的新版本 prevVersionHash 自然不同）。
  return {
    ruleId: v.ruleId,
    version: v.version,
    prevVersionHash: v.prevVersionHash,
    scope: v.scope,
    effectiveFrom: v.effectiveFrom,
    effectiveTo: v.effectiveTo,
    minLeadMinutes: v.minLeadMinutes,
    mutexTags: [...(v.mutexTags || [])].sort(),
    priority: v.priority,
    publishedAt: v.publishedAt,
    publishedBy: v.publishedBy,
    note: v.note,
    rolledBackFrom: v.rolledBackFrom ?? null,
  };
}

function sameScopeLevel(a, b) {
  return !!a.deviceId === !!b.deviceId;
}

function sameRegionOrDevice(a, b) {
  // 调用方已保证同层级：同为设备级需同一设备（地区也必然相同），同为地区级需同一地区。
  if (a.deviceId) return a.deviceId === b.deviceId;
  return a.region === b.region;
}

function dateWindowsOverlap(from1, to1, from2, to2) {
  return from1 <= (to2 ?? '9999-12-31') && from2 <= (to1 ?? '9999-12-31');
}

// ---------------------------------------------------------------------------
// 脱敏与导出
// ---------------------------------------------------------------------------
export function maskId(id) {
  const s = String(id);
  const dash = s.indexOf('-');
  const prefix = dash >= 0 ? s.slice(0, dash + 1) : '';
  const tail = s.slice(prefix.length);
  if (tail.length <= 2) return `${prefix}**`;
  return `${prefix}${'*'.repeat(4)}${tail.slice(-2)}`;
}

const REASON_CN = {
  UNKNOWN_DEVICE: '未知设备',
  CROSS_REGION: '跨区域',
  DEVICE_SUSPENDED: '设备已暂停',
  MUTEX_TAG: '命中互斥标签',
  LEAD_TIME_TOO_SHORT: '提前期不足',
  RULE_OVERLAP: '重叠规则',
  NO_QUALIFICATION_RULE: '无适用资格规则',
  RULE_EXPIRED: '规则已过期',
  RULE_REVOKED: '规则已撤销',
  RULE_PENDING: '规则未到生效日',
};

export function reasonCn(code) {
  return REASON_CN[code] || code;
}

function csvCell(v) {
  const s = v == null ? '' : String(v);
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

// 冻结批次的脱敏清单（CSV，带 UTF-8 BOM 便于 Excel 打开）。
export function redactedCsv(app) {
  const header = [
    '申请号', '事件', '聚合商(脱敏)', '序号', '设备(脱敏)', '地区',
    '裁决', '拒绝原因', '规则', '版本', '规则版本摘要', '裁决摘要', '复核',
  ];
  const rows = app.decisions.map((d) => [
    app.applicationNo,
    app.eventId,
    maskId(app.aggregatorId),
    d.ordinal + 1,
    maskId(d.deviceId),
    d.deviceRegion ?? '',
    d.outcome === 'ADMITTED' ? '准入' : '拒绝',
    d.reasons.map((r) => reasonCn(r.code)).join('；'),
    d.rule?.ruleId ?? '',
    d.rule?.version ?? '',
    d.rule?.versionHash ? `${d.rule.versionHash.slice(0, 16)}…` : '',
    `${d.decisionDigest.slice(0, 16)}…`,
    d.review ? `已复核(${d.review.disposition === 'CONFIRMED' ? '维持' : '异议'}/${maskId(d.review.reviewer)})` : '未复核',
  ]);
  const lines = [header, ...rows].map((r) => r.map(csvCell).join(',')).join('\r\n');
  return '﻿' + lines + '\r\n';
}

// ---------------------------------------------------------------------------
// 小校验工具
// ---------------------------------------------------------------------------
function reqStr(o, field) {
  const v = o?.[field];
  if (typeof v !== 'string' || !v.trim()) {
    throw err('BAD_REQUEST', `缺少必填字段：${field}`);
  }
  return v.trim();
}

function reqNum(o, field) {
  const v = Number(o?.[field]);
  if (!Number.isFinite(v)) throw err('BAD_REQUEST', `缺少或非法数字字段：${field}`);
  return v;
}

function reqNonNegInt(o, field) {
  const v = Number(o?.[field]);
  if (!Number.isInteger(v) || v < 0) throw err('BAD_REQUEST', `${field} 必须为非负整数`);
  return v;
}

function reqDay(v, field) {
  const s = reqStr({ [field]: v }, field);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(s)) throw err('BAD_REQUEST', `${field} 必须为 YYYY-MM-DD（UTC）`);
  // 严格校验日历日期。
  const [y, m, d] = s.split('-').map(Number);
  const dt = new Date(Date.UTC(y, m - 1, d));
  if (dt.getUTCFullYear() !== y || dt.getUTCMonth() !== m - 1 || dt.getUTCDate() !== d) {
    throw err('BAD_REQUEST', `${field} 不是合法日期：${s}`);
  }
  return s;
}

function normalizeTags(tags) {
  if (tags == null) return [];
  if (!Array.isArray(tags)) throw err('BAD_REQUEST', 'tags 必须为字符串数组');
  const out = [];
  for (const t of tags) {
    if (typeof t !== 'string' || !t.trim()) throw err('BAD_REQUEST', '标签必须为非空字符串');
    const v = t.trim();
    if (!out.includes(v)) out.push(v);
  }
  return out.sort();
}

function numOrNull(v) {
  if (v == null || v === '') return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}
