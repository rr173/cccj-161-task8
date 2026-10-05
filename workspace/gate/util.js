// 资格闸模块通用基础工具：规范化 JSON、哈希、日键、时间比较（全部 UTC）。
// 与主编排服务 src/util.js 保持同一套“键名字典序 + 无多余空白”规范化约定，
// 使任何外部实现都能独立重算摘要与验签。
import { createHash } from 'node:crypto';

export function pad2(n) {
  return String(n).padStart(2, '0');
}

// 形如 2026-10-05 的 UTC 日键（“生效日期”按日粒度）。
export function dayKey(ts) {
  const d = new Date(ts);
  return `${d.getUTCFullYear()}-${pad2(d.getUTCMonth() + 1)}-${pad2(d.getUTCDate())}`;
}

export function dateOfDayKey(key) {
  const [y, m, d] = String(key).split('-').map(Number);
  if (!y || !m || !d) throw Object.assign(new Error(`非法日键：${key}`), { code: 'BAD_DAY_KEY', status: 400 });
  return new Date(Date.UTC(y, m - 1, d));
}

// 某 UTC 日的起始（00:00Z）毫秒时间戳。
export function startOfDay(key) {
  return dateOfDayKey(key).getTime();
}

export function iso(ts) {
  return new Date(ts).toISOString();
}

// 键按字典序稳定排序的规范化 JSON（用于哈希 / 签名 / 幂等指纹）。
export function canonicalJSON(value) {
  return JSON.stringify(sortValue(value));
}

function sortValue(v) {
  if (Array.isArray(v)) return v.map(sortValue);
  if (v && typeof v === 'object') {
    const out = {};
    for (const k of Object.keys(v).sort()) out[k] = sortValue(v[k]);
    return out;
  }
  return v;
}

export function sha256Hex(s) {
  return createHash('sha256').update(s).digest('hex');
}

// 取一批字符串/数字的稳定短标识（仅用于可读性，链上身份以显式 id 为准）。
export function shortHash(s, len = 12) {
  return sha256Hex(String(s)).slice(0, len);
}
