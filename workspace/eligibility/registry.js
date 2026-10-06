// 灵活负荷资格闸 · 领域内核（事件溯源投影 + 命令 + 纯函数裁决）。
//
// 与编排内核同一套只增 SHA-256 哈希链：规则发布 / 撤销 / 回滚、设备登记 / 暂停、
// 批量准入裁决、批次冻结全部是不可变记录。重启重放后：
//   - 规则版本链（全局版本号只增，内容哈希衔接）逐字节一致；
//   - 每个准入批次绑定【裁决当时】的规则版本与链尖，后续规则变更/撤销/回滚
//     都不会追改历史批次；
//   - 批量申请按到达顺序串行落账（BATCH_DECIDED.seq 即裁决顺序）。
//
// 逐设备拒绝原因（可同时命中多条，全部列出）：
//   UNKNOWN_DEVICE       未知设备（台账外）
//   CROSS_REGION         跨区域（设备所属区域 ≠ 响应事件区域）
//   DEVICE_SUSPENDED     设备已被暂停
//   NO_APPLICABLE_RULE   当日无生效规则（无规则 / 规则未生效 / 规则已过期或撤销）
//   MUTEX_TAG            命中规则互斥标签
//   LEAD_TIME            不满足最短提前期
import { EventStore, ZERO_HASH } from '../src/store.js';
import { PackageKeyStore } from '../src/package-crypto.js';
import { Clock } from '../src/clock.js';
import { canonicalJSON, sha256Hex, iso, dayKey, dateOfDayKey, uid } from '../src/util.js';

export class GateError extends Error {
  constructor(code, message, details = {}) {
    super(message);
    this.code = code;
    this.details = details;
  }
}

export const GATE_NOW = Date.UTC(2026, 9, 6, 1, 30); // 2026-10-06 01:30 UTC（仿真当前时刻）

// 规则全局版本变动的记录类型（版本号只增；其余记录不占用规则版本号）。
const RULE_MUTATIONS = new Set(['RULE_PUBLISHED', 'RULE_REVOKED', 'RULE_ROLLED_BACK']);

// 逐设备拒绝原因的规范展示顺序
export const REASON_CODES = [
  'UNKNOWN_DEVICE',
  'CROSS_REGION',
  'DEVICE_SUSPENDED',
  'NO_APPLICABLE_RULE',
  'MUTEX_TAG',
  'LEAD_TIME',
];

export function dayStart(key) {
  return dateOfDayKey(key).getTime();
}

// 日期区间是否重叠（含端点；相邻：a 末日 < b 首日 即不重叠）。
export function daysOverlap(aFrom, aUntil, bFrom, bUntil) {
  return !(dayStart(aUntil) < dayStart(bFrom) || dayStart(bUntil) < dayStart(aFrom));
}

// 规则内容指纹：只含可复算字段（规范化 JSON，键名排序）。
export function ruleContentHash(scope, body, validFrom, validUntil, ruleVersion) {
  return sha256Hex(canonicalJSON({
    scope: { deviceId: scope.deviceId ?? null, region: scope.region },
    denyTags: [...(body.denyTags || [])].map(String).sort(),
    minLeadMinutes: Number(body.minLeadMinutes ?? 0),
    validFrom,
    validUntil,
    ruleVersion,
  }));
}

function normTags(tags) {
  return [...new Set((tags || []).map((t) => String(t).trim()).filter(Boolean))].sort();
}

function normScope(scope) {
  if (!scope || typeof scope !== 'object') {
    throw new GateError('BAD_REQUEST', '规则作用域 scope 必填');
  }
  const region = String(scope.region || '').trim();
  if (!region) throw new GateError('BAD_REQUEST', '规则作用域必须指定 region（地区）');
  const deviceId = scope.deviceId == null || scope.deviceId === '' ? null : String(scope.deviceId);
  return { deviceId, region };
}

function normBody(body) {
  const minLeadMinutes = Number(body?.minLeadMinutes ?? 0);
  if (!Number.isFinite(minLeadMinutes) || minLeadMinutes < 0) {
    throw new GateError('BAD_REQUEST', 'minLeadMinutes 必须是非负数（分钟）');
  }
  return { denyTags: normTags(body?.denyTags), minLeadMinutes };
}

// 确定性种子：2 聚合商 / 2 地区 / 4 设备（含一台暂停设备）/ 一条地区默认生效规则。
export function seedGate(store, now = GATE_NOW) {
  store.append('SEED_CLOCK', { now }, now);
  [
    { id: 'AGG-A', name: '北星能源聚合' },
    { id: 'AGG-B', name: '南网负荷聚合' },
  ].forEach((a) => store.append('SEED_AGGREGATOR', a, now));
  [
    { code: 'RG-EAST', name: '浦东灵活负荷区' },
    { code: 'RG-WEST', name: '松江灵活负荷区' },
  ].forEach((r) => store.append('SEED_REGION', r, now));

  const devices = [
    { deviceId: 'GFD-1', name: '中央空调机组 A', region: 'RG-EAST', tags: ['HVAC'], suspended: false },
    { deviceId: 'GFD-2', name: '冷库压缩机 B', region: 'RG-EAST', tags: ['COLD', 'CRITICAL'], suspended: false },
    { deviceId: 'GFD-3', name: '产线可调负荷 C', region: 'RG-WEST', tags: ['LINE'], suspended: false },
    { deviceId: 'GFD-4', name: '暂停中的蓄冰空调 D', region: 'RG-EAST', tags: ['HVAC'], suspended: true, reason: '检修暂停（种子）' },
  ];
  devices.forEach((d) => store.append('DEVICE_REGISTERED', { ...d, at: now }, now));

  // 地区默认规则：互斥标签 CRITICAL、最短提前期 30 分钟；本月全月生效。
  store.append('RULE_PUBLISHED', {
    version: 1,
    ruleId: 'RULE-EAST-DEFAULT',
    ruleVersion: 1,
    scope: { deviceId: null, region: 'RG-EAST' },
    body: { denyTags: ['CRITICAL'], minLeadMinutes: 30 },
    validFrom: '2026-10-01',
    validUntil: '2026-10-31',
    comment: '种子：浦东地区默认准入规则',
    createdBy: '系统种子',
    restoredFromVersion: null,
    contentHash: ruleContentHash(
      { deviceId: null, region: 'RG-EAST' },
      { denyTags: ['CRITICAL'], minLeadMinutes: 30 },
      '2026-10-01', '2026-10-31', 1,
    ),
  }, now);
  store.append('RULE_PUBLISHED', {
    version: 2,
    ruleId: 'RULE-WEST-DEFAULT',
    ruleVersion: 1,
    scope: { deviceId: null, region: 'RG-WEST' },
    body: { denyTags: [], minLeadMinutes: 15 },
    validFrom: '2026-10-01',
    validUntil: '2026-10-31',
    comment: '种子：松江地区默认准入规则',
    createdBy: '系统种子',
    restoredFromVersion: null,
    contentHash: ruleContentHash(
      { deviceId: null, region: 'RG-WEST' },
      { denyTags: [], minLeadMinutes: 15 },
      '2026-10-01', '2026-10-31', 1,
    ),
  }, now);
}

export class EligibilityRegistry {
  constructor(store, { keys = null, boot = true } = {}) {
    this.store = store;
    this.clock = new Clock(GATE_NOW);
    this.keys = keys || new PackageKeyStore(null);
    if (boot) this.bootstrap();
  }

  static freshMemory(now = GATE_NOW) {
    const store = new EventStore(null);
    seedGate(store, now);
    return new EligibilityRegistry(store);
  }

  bootstrap() {
    if (this.store.all().length === 0 && this.store.writable) seedGate(this.store, GATE_NOW);
    this.replay();
    this.ensureKey();
  }

  reset() {
    this.store.truncate();
    this.keys.reset();
    seedGate(this.store, GATE_NOW);
    this.clock = new Clock(GATE_NOW);
    this.replay();
    this.ensureKey();
  }

  // 签发密钥：链上只发布公钥（GATE_KEY_PUBLISHED）；私钥在 sidecar。
  ensureKey() {
    if (!this.store.writable) return;
    if (this.keys.currentKeyId) return;
    const pub = this.keys.rotate(iso(this.now()));
    this.store.append('GATE_KEY_PUBLISHED', pub, this.now());
    this.apply(this.store.all().at(-1));
  }

  replay() {
    this.s = {
      aggregators: new Map(),
      regions: new Map(),
      devices: new Map(),
      ruleVersion: 0, // 全局规则版本号（只增）
      ruleTipHash: ZERO_HASH, // 最近一条规则变动记录的哈希（版本链尖）
      ruleByVersion: new Map(), // 全局版本 -> 规则文档投影
      ruleHead: new Map(), // ruleId -> 最新文档
      requests: new Map(), // requestId -> {op, bodyHash, batchId}
      batches: new Map(), // batchId -> 批次投影
    };
    this.clock = new Clock(GATE_NOW);
    for (const rec of this.store.all()) this.apply(rec);
  }

  now() {
    return this.clock.now();
  }

  // ---------- 投影 ----------

  apply(rec) {
    const s = this.s;
    const p = rec.payload;
    switch (rec.type) {
      case 'SEED_CLOCK':
        this.clock.set(p.now);
        break;
      case 'SIM_TICK':
        this.clock.set(p.to);
        break;
      case 'SEED_AGGREGATOR':
        s.aggregators.set(p.id, { id: p.id, name: p.name });
        break;
      case 'SEED_REGION':
        s.regions.set(p.code, { code: p.code, name: p.name });
        break;
      case 'DEVICE_REGISTERED':
        s.devices.set(p.deviceId, {
          deviceId: p.deviceId,
          name: p.name,
          region: p.region,
          tags: normTags(p.tags),
          suspended: !!p.suspended,
          suspendedReason: p.reason ?? null,
        });
        break;
      case 'DEVICE_UPDATED': {
        const d = s.devices.get(p.deviceId);
        if (d) {
          if (p.name != null) d.name = p.name;
          if (p.region != null) d.region = p.region;
          if (p.tags != null) d.tags = normTags(p.tags);
        }
        break;
      }
      case 'DEVICE_SUSPENDED': {
        const d = s.devices.get(p.deviceId);
        if (d) {
          d.suspended = !!p.suspended;
          d.suspendedReason = p.suspended ? (p.reason ?? null) : null;
        }
        break;
      }
      case 'GATE_KEY_PUBLISHED':
        this.keys.reconcile(p);
        break;
      case 'RULE_PUBLISHED':
      case 'RULE_ROLLED_BACK': {
        const doc = {
          version: p.version,
          ruleId: p.ruleId,
          ruleVersion: p.ruleVersion,
          restoredFromVersion: p.restoredFromVersion ?? null,
          scope: { ...p.scope },
          body: { denyTags: normTags(p.body.denyTags), minLeadMinutes: Number(p.body.minLeadMinutes) },
          validFrom: p.validFrom,
          validUntil: p.validUntil,
          comment: p.comment ?? null,
          createdBy: p.createdBy ?? '运营方',
          createdAt: p.at ?? rec.ts,
          contentHash: p.contentHash,
          recordSeq: rec.seq,
          recordHash: rec.hash,
          revoked: false,
          revokedAt: null,
          revokeReason: null,
          revokeEffectiveFrom: null,
          supersededByVersion: null,
        };
        // 同一 ruleId 的旧头被新版本接替（旧文档保留在 ruleByVersion，历史批次仍可复验）
        const prevHead = s.ruleHead.get(p.ruleId);
        if (prevHead) prevHead.supersededByVersion = p.version;
        s.ruleByVersion.set(p.version, doc);
        s.ruleHead.set(p.ruleId, doc);
        s.ruleVersion = p.version;
        s.ruleTipHash = rec.hash;
        break;
      }
      case 'RULE_REVOKED': {
        // 撤销记录本身占用下一个全局版本号（版本链含撤销），但被撤销的是该 ruleId 的头版本
        const doc = s.ruleHead.get(p.ruleId);
        if (doc) {
          doc.revoked = true;
          doc.revokedAt = p.at;
          doc.revokeReason = p.reason ?? null;
          // 撤销本身是【不可变记录】，但对裁决的影响按 effectiveFrom 定时生效：
          // 生效日之前规则仍在版可用（resolveRule 判断日键），生效日起退出候选。
          doc.revokeEffectiveFrom = p.effectiveFrom ?? dayKey(p.at);
        }
        s.ruleVersion = p.version;
        s.ruleTipHash = rec.hash;
        break;
      }
      case 'GATE_REQUEST_INDEXED':
        // 幂等台账随链重放重建（requestId -> {op,bodyHash,batchId}）
        s.requests.set(p.requestId, { op: p.op, bodyHash: p.bodyHash, batchId: p.batchId });
        break;
      case 'BATCH_DECIDED':
        s.batches.set(p.batchId, {
          ...p,
          items: p.items.map((it) => ({ ...it })),
          status: 'OPEN',
          frozenAt: null,
          recordSeq: rec.seq,
        });
        break;
      case 'BATCH_FROZEN': {
        const b = s.batches.get(p.batchId);
        if (b) {
          b.status = 'FROZEN';
          b.frozenAt = p.at;
        }
        break;
      }
      default:
        break;
    }
  }

  // ---------- 设备台账 ----------

  registerDevice(cmd, now) {
    const deviceId = String(cmd.deviceId || '').trim();
    if (!deviceId) throw new GateError('BAD_REQUEST', 'deviceId 必填');
    const region = String(cmd.region || '').trim();
    if (!this.s.regions.has(region)) {
      throw new GateError('BAD_REQUEST', `地区 ${region} 未登记`, { region });
    }
    if (this.s.devices.has(deviceId)) {
      throw new GateError('DEVICE_EXISTS', `设备 ${deviceId} 已登记`, { deviceId });
    }
    const payload = {
      deviceId,
      name: String(cmd.name || deviceId),
      region,
      tags: normTags(cmd.tags),
      suspended: !!cmd.suspended,
      reason: cmd.suspended ? (String(cmd.reason || '') || null) : null,
      at: now,
    };
    this.store.append('DEVICE_REGISTERED', payload, now);
    this.apply(this.store.all().at(-1));
    return { device: this.deviceView(deviceId) };
  }

  suspendDevice(cmd, now) {
    const deviceId = String(cmd.deviceId || '').trim();
    const d = this.s.devices.get(deviceId);
    if (!d) throw new GateError('DEVICE_NOT_FOUND', `设备 ${deviceId} 未登记`, { deviceId });
    const suspended = !!cmd.suspended;
    if (d.suspended === suspended) {
      return { device: this.deviceView(deviceId), idempotent: true };
    }
    const payload = {
      deviceId,
      suspended,
      reason: suspended ? (String(cmd.reason || '') || null) : null,
      at: now,
    };
    this.store.append('DEVICE_SUSPENDED', payload, now);
    this.apply(this.store.all().at(-1));
    return { device: this.deviceView(deviceId), idempotent: false };
  }

  deviceView(deviceId) {
    const d = this.s.devices.get(deviceId);
    return d ? { ...d, tags: [...d.tags] } : null;
  }

  // ---------- 规则版本链 ----------

  #validateRange(validFrom, validUntil) {
    const re = /^\d{4}-\d{2}-\d{2}$/;
    if (!re.test(validFrom) || !re.test(validUntil)) {
      throw new GateError('BAD_REQUEST', '生效日期必须为 YYYY-MM-DD');
    }
    if (dayStart(validUntil) < dayStart(validFrom)) {
      throw new GateError('BAD_REQUEST', 'validUntil 不能早于 validFrom');
    }
  }

  #checkExpectedVersion(expectedVersion) {
    if (expectedVersion == null) return;
    const expected = Number(expectedVersion);
    if (expected !== this.s.ruleVersion) {
      throw new GateError('RULE_VERSION_CONFLICT', '规则版本已被他人更新（乐观锁冲突）', {
        expected, current: this.s.ruleVersion,
      });
    }
  }

  // 新规则：同作用域（设备专属 / 地区默认）与任一【在版生效规则】日期重叠即 409；
  // 日期相邻（前规则末日 < 新规则首日）允许。同一 ruleId 的更新走接替语义（不判重叠）。
  #checkOverlapForNewRule(scope, validFrom, validUntil, ruleId, now) {
    for (const doc of this.s.ruleByVersion.values()) {
      if (doc.ruleId === ruleId) continue;
      if (doc.supersededByVersion) continue;
      // 已到撤销生效日才视为退出；尚未生效的定时撤销仍是在版规则，照样阻挡重叠
      if (doc.revoked && dayKey(now) >= doc.revokeEffectiveFrom) continue;
      const ds = doc.scope;
      const sameScope = ds.deviceId === scope.deviceId && ds.region === scope.region;
      if (!sameScope) continue;
      if (daysOverlap(validFrom, validUntil, doc.validFrom, doc.validUntil)) {
        throw new GateError('RULE_OVERLAP',
          `与同作用域在版规则 ${doc.ruleId}（v${doc.ruleVersion}，${doc.validFrom}..${doc.validUntil}）日期重叠`,
          { conflictingRuleId: doc.ruleId, conflictingVersion: doc.version });
      }
    }
  }

  publishRule(cmd, now) {
    const scope = normScope(cmd.scope);
    const body = normBody(cmd.body);
    const validFrom = String(cmd.validFrom || '');
    const validUntil = String(cmd.validUntil || '');
    this.#validateRange(validFrom, validUntil);
    this.#checkExpectedVersion(cmd.expectedVersion);

    const ruleId = cmd.ruleId ? String(cmd.ruleId) : uid('RULE');
    const head = this.s.ruleHead.get(ruleId);
    if (head && head.revoked) {
      // 已撤销规则不可直接改；必须用回滚生成新版本
      throw new GateError('RULE_REVOKED', `规则 ${ruleId} 已撤销，请回滚生成新版本后再发布`, { ruleId });
    }
    if (!head) {
      // 全新规则：检查同作用域重叠
      this.#checkOverlapForNewRule(scope, validFrom, validUntil, ruleId, now);
    }

    const ruleVersion = head ? head.ruleVersion + 1 : 1;
    const version = this.s.ruleVersion + 1;
    const contentHash = ruleContentHash(scope, body, validFrom, validUntil, ruleVersion);
    const payload = {
      version,
      ruleId,
      ruleVersion,
      scope,
      body,
      validFrom,
      validUntil,
      comment: cmd.comment ? String(cmd.comment) : null,
      createdBy: cmd.createdBy ? String(cmd.createdBy) : '运营方',
      restoredFromVersion: null,
      at: now,
      contentHash,
    };
    this.store.append('RULE_PUBLISHED', payload, now);
    this.apply(this.store.all().at(-1));
    return { rule: this.ruleView(ruleId), chainTip: this.chainTip() };
  }

  revokeRule(cmd, now) {
    const ruleId = String(cmd.ruleId || '');
    const head = this.s.ruleHead.get(ruleId);
    if (!head) throw new GateError('RULE_NOT_FOUND', `规则 ${ruleId} 不存在`, { ruleId });
    if (head.revoked) {
      throw new GateError('RULE_ALREADY_REVOKED', `规则 ${ruleId} 已撤销`, {
        ruleId, revokedAt: head.revokedAt,
      });
    }
    this.#checkExpectedVersion(cmd.expectedVersion);
    const effectiveFrom = cmd.effectiveFrom ? String(cmd.effectiveFrom) : dayKey(now);
    if (!/^\d{4}-\d{2}-\d{2}$/.test(effectiveFrom)) {
      throw new GateError('BAD_REQUEST', 'effectiveFrom 必须为 YYYY-MM-DD');
    }
    if (dayStart(effectiveFrom) < dayStart(dayKey(now))) {
      throw new GateError('BAD_REQUEST', '撤销生效日不能早于今天');
    }
    const version = this.s.ruleVersion + 1;
    const payload = {
      version,
      ruleId,
      at: now,
      reason: cmd.reason ? String(cmd.reason) : '运营方撤销',
      effectiveFrom,
    };
    this.store.append('RULE_REVOKED', payload, now);
    this.apply(this.store.all().at(-1));
    return { rule: this.ruleView(ruleId), chainTip: this.chainTip() };
  }

  // 回滚：取历史全局版本 fromVersion 的规则内容，作为该 ruleId 的新版本重新在版。
  // 撤销后的回滚是恢复准入的正规路径；回滚永不删除或改写任何历史记录。
  rollbackRule(cmd, now) {
    const fromVersion = Number(cmd.fromVersion);
    const source = this.s.ruleByVersion.get(fromVersion);
    if (!source) {
      throw new GateError('RULE_VERSION_NOT_FOUND', `规则版本 ${fromVersion} 不存在`, { fromVersion });
    }
    this.#checkExpectedVersion(cmd.expectedVersion);

    const ruleId = source.ruleId;
    const head = this.s.ruleHead.get(ruleId);
    const ruleVersion = (head ? head.ruleVersion : source.ruleVersion) + 1;
    const version = this.s.ruleVersion + 1;
    const validFrom = cmd.validFrom ? String(cmd.validFrom) : dayKey(now);
    const validUntil = cmd.validUntil ? String(cmd.validUntil) : source.validUntil;
    this.#validateRange(validFrom, validUntil);
    if (!head) {
      this.#checkOverlapForNewRule(source.scope, validFrom, validUntil, ruleId, now);
    }
    const body = source.body;
    const contentHash = ruleContentHash(source.scope, body, validFrom, validUntil, ruleVersion);
    const payload = {
      version,
      ruleId,
      ruleVersion,
      scope: source.scope,
      body,
      validFrom,
      validUntil,
      comment: cmd.comment ? String(cmd.comment) : `回滚自版本 ${fromVersion}`,
      createdBy: cmd.createdBy ? String(cmd.createdBy) : '运营方',
      restoredFromVersion: fromVersion,
      at: now,
      contentHash,
    };
    this.store.append('RULE_ROLLED_BACK', payload, now);
    this.apply(this.store.all().at(-1));
    return {
      rule: this.ruleView(ruleId),
      restoredFrom: this.ruleVersionView(fromVersion),
      chainTip: this.chainTip(),
    };
  }

  // 某日某台设备的适用规则（纯函数）：设备专属优先于地区默认；同优先级取全局版本更大者。
  // draftRule 非空时作为试算草案覆盖同作用域解析（不落盘）。
  resolveRule(device, day, at = this.now(), draftRule = null) {
    const candidates = [];
    for (const doc of this.s.ruleByVersion.values()) {
      if (doc.supersededByVersion) continue;
      if (!(doc.validFrom <= day && day <= doc.validUntil)) continue;
      // 撤销按 revokeEffectiveFrom 定时生效：生效日当天起退出候选，之前仍可裁决
      if (doc.revoked && day >= doc.revokeEffectiveFrom) continue;
      const exact = doc.scope.deviceId === device.deviceId;
      const regional = doc.scope.deviceId === null && doc.scope.region === device.region;
      if (!exact && !regional) continue;
      candidates.push({ doc, specificity: exact ? 1 : 0 });
    }
    candidates.sort((a, b) => (b.specificity - a.specificity) || (b.doc.version - a.doc.version));
    let picked = candidates[0]?.doc ?? null;

    if (draftRule) {
      const scope = draftRule.scope;
      const exact = scope.deviceId === device.deviceId;
      const regional = scope.deviceId === null && scope.region === device.region;
      if ((exact || regional) && draftRule.validFrom <= day && day <= draftRule.validUntil) {
        return { doc: this.#draftDoc(draftRule), specificity: exact ? 1 : 0, draft: true };
      }
    }
    return picked ? { doc: picked, specificity: candidates[0].specificity, draft: false } : null;
  }

  #draftDoc(draftRule) {
    const body = normBody(draftRule.body);
    const scope = normScope(draftRule.scope);
    return {
      version: null,
      ruleId: '@draft',
      ruleVersion: null,
      scope,
      body,
      validFrom: draftRule.validFrom,
      validUntil: draftRule.validUntil,
      contentHash: ruleContentHash(scope, body, draftRule.validFrom, draftRule.validUntil, 0),
      draft: true,
    };
  }

  // 逐设备裁决（纯函数）：返回 {decision, reasons[], rule}，reasons 命中多条全部列出。
  judgeDevice(deviceId, event, at, draftRule = null) {
    const d = this.s.devices.get(deviceId);
    if (!d) {
      return { deviceId, decision: 'REJECTED', reasons: ['UNKNOWN_DEVICE'], rule: null };
    }
    const reasons = [];
    if (d.region !== event.region) reasons.push('CROSS_REGION');
    if (d.suspended) reasons.push('DEVICE_SUSPENDED');

    const day = dayKey(event.startMs);
    const resolved = this.resolveRule(d, day, at, draftRule);
    if (!resolved) {
      reasons.push('NO_APPLICABLE_RULE');
      return {
        deviceId, decision: 'REJECTED',
        reasons: REASON_CODES.filter((c) => reasons.includes(c)), rule: null,
      };
    }
    const rule = resolved.doc;
    if (rule.body.denyTags.some((t) => d.tags.includes(t))) reasons.push('MUTEX_TAG');
    const leadMs = event.startMs - at;
    if (leadMs < rule.body.minLeadMinutes * 60000) reasons.push('LEAD_TIME');

    const ordered = REASON_CODES.filter((c) => reasons.includes(c));
    return {
      deviceId,
      decision: ordered.length ? 'REJECTED' : 'APPROVED',
      reasons: ordered,
      rule: this.ruleRef(rule),
    };
  }

  ruleRef(rule) {
    if (!rule) return null;
    return {
      ruleId: rule.ruleId,
      ruleVersion: rule.ruleVersion,
      version: rule.version,
      contentHash: rule.contentHash,
      validFrom: rule.validFrom,
      validUntil: rule.validUntil,
      ...(rule.draft ? { draft: true } : {}),
    };
  }

  chainTip() {
    return { version: this.s.ruleVersion, hash: this.s.ruleTipHash };
  }

  // ---------- 批量申请（按序落账 + 幂等 + 版本绑定） ----------

  #requestGate(cmd, op) {
    const requestId = String(cmd.requestId || '').trim();
    if (!requestId) throw new GateError('BAD_REQUEST', '客户请求号 requestId 必填（作为幂等键）');
    const bodyHash = sha256Hex(canonicalJSON(cmd));
    const seen = this.s.requests.get(requestId);
    if (seen && seen.bodyHash !== bodyHash) {
      throw new GateError('REQUEST_ID_CONFLICT', '同一申请号已被不同正文使用（正文变更冲突 409）', { requestId });
    }
    return { requestId, bodyHash, seen: seen || null };
  }

  #normalizeEvent(evt) {
    const eventId = String(evt?.eventId || '').trim();
    const region = String(evt?.region || '').trim();
    const startMs = Number(evt?.startMs);
    if (!eventId) throw new GateError('BAD_REQUEST', 'event.eventId 必填');
    if (!region) throw new GateError('BAD_REQUEST', 'event.region 必填');
    if (!Number.isFinite(startMs)) throw new GateError('BAD_REQUEST', 'event.startMs 必须是毫秒时间戳');
    return { eventId, region, startMs };
  }

  decideBatch(cmd, now) {
    const gate = this.#requestGate(cmd, 'SUBMIT_APPLICATION');
    if (gate.seen) {
      const existing = this.s.batches.get(gate.seen.batchId);
      return { batch: this.batchView(existing.batchId), idempotent: true };
    }
    const aggregatorId = String(cmd.aggregatorId || '').trim();
    if (!this.s.aggregators.has(aggregatorId)) {
      throw new GateError('BAD_REQUEST', `聚合商 ${aggregatorId} 未登记`, { aggregatorId });
    }
    const event = this.#normalizeEvent(cmd.event);
    const deviceIds = [...(cmd.deviceIds || [])].map((x) => String(x));
    // 逐设备裁决，保持申请内顺序；未知设备不影响其他设备裁决
    const items = deviceIds.map((deviceId, order) => ({
      order,
      ...this.judgeDevice(deviceId, event, now),
    }));
    const tip = this.chainTip();
    const batchId = uid('BATCH');
    const base = {
      batchId,
      requestId: gate.requestId,
      bodyHash: gate.bodyHash,
      aggregatorId,
      event,
      decidedAt: now,
      ruleChainTip: tip,
      items,
    };
    const signature = this.#signBatch(base);
    const payload = { ...base, keyId: signature.keyId, batchDigest: signature.batchDigest, signature: signature.signature };
    this.store.append('BATCH_DECIDED', payload, now);
    this.apply(this.store.all().at(-1));
    // 幂等台账也随链落账（requestId -> batchId），重启后重放重建
    this.store.append('GATE_REQUEST_INDEXED', {
      requestId: gate.requestId, op: 'SUBMIT_APPLICATION', bodyHash: gate.bodyHash, batchId,
    }, now);
    this.apply(this.store.all().at(-1));
    return { batch: this.batchView(batchId), idempotent: false };
  }

  // 批次签名范围（规范化 JSON）：任何实现都可独立复算。
  static batchCanonical(base) {
    return canonicalJSON({
      batchId: base.batchId,
      requestId: base.requestId,
      aggregatorId: base.aggregatorId,
      event: base.event,
      decidedAt: base.decidedAt,
      ruleChainTip: base.ruleChainTip,
      items: base.items.map((it) => ({
        order: it.order,
        deviceId: it.deviceId,
        decision: it.decision,
        reasons: [...it.reasons],
        rule: it.rule ? {
          ruleId: it.rule.ruleId,
          ruleVersion: it.rule.ruleVersion,
          version: it.rule.version,
          contentHash: it.rule.contentHash,
        } : null,
      })),
    });
  }

  #signBatch(base) {
    const canonical = EligibilityRegistry.batchCanonical(base);
    const keyId = this.keys.currentKeyId;
    if (!keyId) throw new GateError('GATE_KEY_UNAVAILABLE', '资格闸签发密钥不可用');
    const signature = this.keys.signManifest(keyId, canonical);
    return { keyId, batchDigest: sha256Hex(canonical), signature };
  }

  freezeBatch(cmd, now) {
    const batchId = String(cmd.batchId || '');
    const b = this.s.batches.get(batchId);
    if (!b) throw new GateError('BATCH_NOT_FOUND', `批次 ${batchId} 不存在`, { batchId });
    if (b.status === 'FROZEN') return { batch: this.batchView(batchId), idempotent: true };
    this.store.append('BATCH_FROZEN', { batchId, at: now, by: cmd.by ? String(cmd.by) : '运营方' }, now);
    this.apply(this.store.all().at(-1));
    return { batch: this.batchView(batchId), idempotent: false };
  }

  // 独立验签：重算规范化摘要、用链上公钥验 Ed25519，并核对每条绑定的规则版本指纹。
  verifyBatch(batchId) {
    const b = this.s.batches.get(batchId);
    if (!b) return null;
    const base = {
      batchId: b.batchId, requestId: b.requestId, aggregatorId: b.aggregatorId,
      event: b.event, decidedAt: b.decidedAt, ruleChainTip: b.ruleChainTip, items: b.items,
    };
    const canonical = EligibilityRegistry.batchCanonical(base);
    const recomputedDigest = sha256Hex(canonical);
    let signatureValid = false;
    let publicKeyPem = null;
    try {
      publicKeyPem = this.keys.publicKey(b.keyId);
      signatureValid = this.keys.verifyManifest(b.keyId, canonical, b.signature);
    } catch {
      signatureValid = false;
    }
    const ruleChecks = b.items
      .filter((it) => it.rule && it.rule.version != null)
      .map((it) => {
        const doc = this.s.ruleByVersion.get(it.rule.version);
        return {
          deviceId: it.deviceId,
          version: it.rule.version,
          ruleId: it.rule.ruleId,
          storedHash: it.rule.contentHash,
          chainHash: doc?.contentHash ?? null,
          intact: !!doc && doc.contentHash === it.rule.contentHash,
        };
      });
    // 批次绑定的版本链尖必须仍是那条规则变动记录的哈希（历史批次不被后续版本追改）
    const tipIntact = b.ruleChainTip.version === 0
      ? b.ruleChainTip.hash === ZERO_HASH
      : this.#hashOfRuleVersion(b.ruleChainTip.version) === b.ruleChainTip.hash;
    return {
      batchId,
      status: b.status,
      recordSeq: b.recordSeq,
      keyId: b.keyId,
      publicKeyPem,
      // 供第三方离线独立复验：对 canonical 做 sha256 应得 storedDigest，再用公钥 Ed25519 验 signature
      canonical,
      digestAlgorithm: 'SHA-256(canonicalJSON)',
      signatureAlgorithm: 'Ed25519',
      storedDigest: b.batchDigest,
      recomputedDigest,
      digestMatches: recomputedDigest === b.batchDigest,
      signature: b.signature,
      signatureValid,
      ruleChainTip: b.ruleChainTip,
      tipIntact,
      ruleChecks,
      valid: signatureValid && recomputedDigest === b.batchDigest && tipIntact && ruleChecks.every((c) => c.intact),
    };
  }

  #hashOfRuleVersion(version) {
    return this.store.all().filter((r) => RULE_MUTATIONS.has(r.type))[version - 1]?.hash ?? null;
  }

  // ---------- 规则试算（不落盘） ----------

  trial(cmd) {
    const at = cmd.at != null ? Number(cmd.at) : this.now();
    if (!Number.isFinite(at)) throw new GateError('BAD_REQUEST', 'at 必须是毫秒时间戳');
    const event = this.#normalizeEvent(cmd.event);
    let draftRule = null;
    if (cmd.draftRule) {
      const scope = normScope(cmd.draftRule.scope);
      const body = normBody(cmd.draftRule.body);
      const validFrom = String(cmd.draftRule.validFrom || dayKey(at));
      const validUntil = String(cmd.draftRule.validUntil || '2999-12-31');
      this.#validateRange(validFrom, validUntil);
      draftRule = { scope, body, validFrom, validUntil };
    }
    const deviceIds = [...(cmd.deviceIds || [])].map((x) => String(x));
    const items = deviceIds.map((deviceId, order) => ({
      order, ...this.judgeDevice(deviceId, event, at, draftRule),
    }));
    return {
      trial: true,
      at,
      atIso: iso(at),
      event,
      draft: !!draftRule,
      approved: items.filter((i) => i.decision === 'APPROVED').length,
      rejected: items.filter((i) => i.decision === 'REJECTED').length,
      items,
    };
  }

  // ---------- 视图 ----------

  ruleDocView(doc) {
    const day = dayKey(this.now());
    let lifecycle = 'ACTIVE';
    if (doc.revoked && day >= (doc.revokeEffectiveFrom || doc.validFrom)) lifecycle = 'REVOKED';
    else if (doc.supersededByVersion) lifecycle = 'SUPERSEDED';
    else if (day < doc.validFrom) lifecycle = 'SCHEDULED';
    else if (day > doc.validUntil) lifecycle = 'EXPIRED';
    else if (doc.revoked) lifecycle = 'REVOKE_SCHEDULED';
    return {
      version: doc.version,
      ruleId: doc.ruleId,
      ruleVersion: doc.ruleVersion,
      scope: doc.scope,
      body: doc.body,
      validFrom: doc.validFrom,
      validUntil: doc.validUntil,
      lifecycle,
      restoredFromVersion: doc.restoredFromVersion,
      comment: doc.comment,
      createdBy: doc.createdBy,
      createdAt: doc.createdAt,
      contentHash: doc.contentHash,
      recordSeq: doc.recordSeq,
      revoked: doc.revoked,
      revokedAt: doc.revokedAt,
      revokeReason: doc.revokeReason,
      revokeEffectiveFrom: doc.revokeEffectiveFrom,
      supersededByVersion: doc.supersededByVersion,
    };
  }

  ruleView(ruleId) {
    const head = this.s.ruleHead.get(ruleId);
    if (!head) return null;
    const history = [...this.s.ruleByVersion.values()]
      .filter((d) => d.ruleId === ruleId)
      .sort((a, b) => a.version - b.version)
      .map((d) => this.ruleDocView(d));
    return { ruleId, head: this.ruleDocView(head), history };
  }

  ruleVersionView(version) {
    const doc = this.s.ruleByVersion.get(Number(version));
    return doc ? this.ruleDocView(doc) : null;
  }

  listRules({ scope = null, lifecycle = null } = {}) {
    const heads = [...this.s.ruleHead.values()].map((d) => this.ruleDocView(d));
    let out = heads;
    if (scope) {
      out = out.filter((d) =>
        d.scope.region === scope.region &&
        (scope.deviceId == null || d.scope.deviceId === scope.deviceId));
    }
    if (lifecycle) out = out.filter((d) => d.lifecycle === lifecycle);
    return out.sort((a, b) => a.version - b.version);
  }

  batchView(batchId) {
    const b = this.s.batches.get(batchId);
    if (!b) return null;
    return {
      batchId: b.batchId,
      requestId: b.requestId,
      bodyHash: b.bodyHash,
      aggregatorId: b.aggregatorId,
      event: b.event,
      decidedAt: b.decidedAt,
      decidedAtIso: iso(b.decidedAt),
      status: b.status,
      frozenAt: b.frozenAt,
      keyId: b.keyId,
      batchDigest: b.batchDigest,
      signature: b.signature,
      ruleChainTip: b.ruleChainTip,
      recordSeq: b.recordSeq,
      counts: {
        total: b.items.length,
        approved: b.items.filter((i) => i.decision === 'APPROVED').length,
        rejected: b.items.filter((i) => i.decision === 'REJECTED').length,
      },
      items: b.items.map((it) => ({ ...it })),
    };
  }

  listBatches({ aggregatorId = null, status = null } = {}) {
    let out = [...this.s.batches.values()];
    if (aggregatorId) out = out.filter((b) => b.aggregatorId === aggregatorId);
    if (status) out = out.filter((b) => b.status === status);
    return out.map((b) => this.batchView(b.batchId)).sort((a, b) => a.recordSeq - b.recordSeq);
  }

  // 脱敏清单（CSV，仅冻结批次）：设备号打码（前缀+短指纹），不含签名/原始设备全名。
  redactedCsv(batchId) {
    const b = this.s.batches.get(batchId);
    if (!b) return null;
    if (b.status !== 'FROZEN') throw new GateError('BATCH_NOT_FROZEN', '批次冻结后才允许下载脱敏清单', { batchId });
    const mask = (deviceId) => {
      const prefix = String(deviceId).split('-')[0].slice(0, 4);
      return `${prefix}-****-${sha256Hex(deviceId).slice(0, 8)}`;
    };
    const esc = (v) => {
      const s = v == null ? '' : String(v);
      return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
    };
    const rows = [
      ['order', 'deviceMasked', 'decision', 'reasons', 'ruleVersion', 'decidedDate'].join(','),
      ...b.items.map((it) => [
        it.order,
        mask(it.deviceId),
        it.decision,
        it.reasons.join('|'),
        it.rule?.version ?? '',
        dayKey(b.decidedAt),
      ].map(esc).join(',')),
    ];
    return rows.join('\n') + '\n';
  }

  stateView() {
    const chain = this.store.verify();
    return {
      now: this.now(),
      nowIso: iso(this.now()),
      mode: chain.mode,
      readOnly: !chain.writable,
      recovery: chain.recovery,
      aggregators: [...this.s.aggregators.values()],
      regions: [...this.s.regions.values()],
      devices: [...this.s.devices.values()].map((d) => this.deviceView(d.deviceId)),
      rules: this.listRules(),
      ruleChain: { ...this.chainTip(), length: this.store.all().filter((r) => RULE_MUTATIONS.has(r.type)).length },
      batches: this.listBatches().map((b) => ({ ...b, items: undefined })),
      keys: this.store.all()
        .filter((r) => r.type === 'GATE_KEY_PUBLISHED')
        .map((r) => ({ keyId: r.payload.keyId, publicKeyPem: r.payload.publicKeyPem, rotatedAt: r.payload.rotatedAt })),
      chain,
    };
  }
}
