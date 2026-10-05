# 灵活负荷资格闸（Flexible-Load Qualification Gate）

调度员维护**按设备 / 地区 / 生效日期组合**的资格规则；聚合商提交一批设备参加指定响应事件时，
服务返回**逐设备**的准入裁决、命中的**规则版本（含版本摘要）**与 **Ed25519 签名摘要**。

- 设备若命中**互斥标签**、**已被暂停**、**跨区域**或**不满足最短提前期**，分别列出拒绝原因（一台设备可同时命中多条）。
- **同一申请号 + 相同正文**重送：原样返回首次裁决（幂等，不新增记录、不重算）；**同一申请号 + 不同正文**：`409`，原裁决保留。
- 规则可**定时生效、撤销、回滚**；已生成的准入批次**永远绑定生成时的规则版本全文与摘要**，后续规则变更绝不追改。
- 并发更新与申请按到达顺序**串行落账**；服务重启后**裁决顺序（seq）与版本链逐字节不变**。
- 网页与接口覆盖：**规则试算、批量申请、逐项复核、批次冻结、脱敏清单下载、独立验签**；
  并覆盖未知设备、重叠规则、过期规则、版本冲突、撤销后重试与空批次结果。

零依赖、纯 Node.js（≥ 20），与主编排服务同一套**事件溯源 + SHA-256 哈希链 + Ed25519 sidecar** 纪律。

```bash
npm run gate               # 服务 + 调度台 → http://127.0.0.1:8093/
GATE_MEMORY=1 npm run gate # 纯内存（不落盘）
npm run test:e2e:gate      # 57 项真实 HTTP 端到端断言（含真实进程重启）
node --test test/gate.test.js test/gate-restart.test.js   # 26 项领域/恢复单测
```

## 数据与信任模型

所有状态变化都是 `data/gate/gate.log` 上的只增记录：

```
SEED_CLOCK / SEED_DEVICE / DEVICE_REGISTERED / DEVICE_SUSPENDED / DEVICE_RESUMED
SEED_EVENT / EVENT_REGISTERED / GATE_KEY_PUBLISHED
SEED_RULE / RULE_VERSION_PUBLISHED / RULE_VERSION_REVOKED / RULE_ROLLED_BACK
APPLICATION_ACCEPTED / ITEM_REVIEWED / BATCH_FROZEN / SIM_TICK
```

每条记录 `{seq,ts,type,payload,prevHash,hash}`，
`hash = sha256(canonicalJSON({seq,ts,type,payload,prevHash}))`，
genesis = `sha256("gate-chain-v1|ledger")`。任何历史篡改都会断链 → 服务进入**只读隔离（503）**；
文件末尾单条断电残尾会原样归档到 `data/gate/quarantine/` 后截断续链（与主编排服务恢复契约一致）。

- **签发密钥**：Ed25519，私钥只在账本旁 sidecar `data/gate/gate-keys.json`（权限 0600）；
  公钥随 `GATE_KEY_PUBLISHED` 上链分发，`GET /api/keys` 公开。密钥可轮换（只增新版本），
  历史批次永远用生成时的 `keyId` 复验。
- **当前状态是链的纯投影**：重启逐行重放重建，裁决顺序/规则版本链/批次绑定/签名逐字节复原。

## 规则模型与裁决

规则（每个版本不可变）：

```jsonc
{
  "ruleId": "RULE-ZJ-GENERAL",
  "scope": { "region": "ZJ", "deviceId": null }, // deviceId 非空 = 设备级（优先于地区级）
  "effectiveFrom": "2026-10-01", "effectiveTo": "2026-10-31", // UTC 日；effectiveTo 可空=长期
  "minLeadMinutes": 120,       // 事件开始前必须剩余的最短申报时间
  "mutexTags": ["CRITICAL"],   // 设备标签命中其一即拒
  "priority": 100              // 同层级多条规则时小者优先
}
```

版本链：每次发布/改版/回滚都追加新版本，含 `version`、`prevVersionHash`、`versionHash`；
撤销是独立事件（`RULE_VERSION_REVOKED`），版本记录字节不动。

逐设备裁决（顺序执行，原因可并列）：

| 检查 | 拒绝码 |
| --- | --- |
| 设备未注册 | `UNKNOWN_DEVICE`（终局，仅这一条） |
| 设备地区 ≠ 事件地区 | `CROSS_REGION` |
| 设备状态为暂停 | `DEVICE_SUSPENDED` |
| 无任何覆盖设备/事件日期的规则 | `NO_QUALIFICATION_RULE` |
| 唯一适用规则已撤销且无替代 | `RULE_REVOKED` |
| 适用规则已过失效日 | `RULE_EXPIRED` |
| 适用规则未到生效日（定时生效） | `RULE_PENDING` |
| 同层级多条同优先级规则同时命中 | `RULE_OVERLAP`（列出全部碰撞版本） |
| 设备标签 ∈ 规则互斥标签 | `MUTEX_TAG` |
| 剩余申报时间 < 规则最短提前期 | `LEAD_TIME_TOO_SHORT`（含要求/实际分钟） |

规则选择：先按特异性（**设备级 > 地区级**），再按 `priority`（小者优先）；仍同优先级且不止一条
→ `RULE_OVERLAP`。发布规则时，同层级 + 日期窗重叠 + 同优先级会被 `RULE_OVERLAP_DETECTED(409)` 拦下
（`forceOverlap=true` 可强行保留，但裁决时命中设备仍会被 `RULE_OVERLAP` 拒绝）；优先级不同只作
advisory 提示，地区级与设备级是正常层次、不报冲突。

## 逐设备签名与冻结清单

- 逐设备签名载荷 schema 固定为 `gate-decision/v1`：
  `{schema,applicationNo,eventId,aggregatorId,ordinal,deviceId,deviceRegion,outcome,reasons,rule,decidedAt}`，
  其中 `rule` 是**钉入裁决的版本快照**。对 `canonicalJSON(载荷)` 直接 Ed25519 签名（PureEdDSA，
  不二次哈希），并返回 `decisionDigest = sha256(canonical)`。
- 冻结批次生成 `gate-batch-manifest/v1` 清单（含逐项 outcome、原因码、绑定规则版本三元组、
  逐项摘要与签名），对清单规范化字节签名；冻结幂等，空批次也可冻结。
- **任何第三方**只需公钥 PEM + canonical + hex 签名即可离线复验（脚本中用 Node `crypto.verify`
  做了脱离服务接口的真·第三方验证）。

## HTTP API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/api/state` | 完整视图（时钟/设备/事件/规则版本链/批次/链校验/公钥） |
| POST | `/api/sim/tick` `{minutes}` | 推进仿真时钟（可重复演示定时生效/提前期） |
| POST | `/api/sim/reset` | 截断账本并重建确定性种子 |
| GET/POST | `/api/devices` | 设备列表 / 注册 |
| POST | `/api/devices/:id/suspend` `/resume` | 暂停 / 恢复（独立闸） |
| GET/POST | `/api/events` | 响应事件列表 / 注册 `{eventId,region,effectiveDate,startMs}` |
| GET/POST | `/api/rules` | 规则列表（含全部版本）/ 发布或改版（`expectedVersion` 乐观锁；撤销后重发用 `"REVOKED"`；`forceOverlap`） |
| GET | `/api/rules/:id` | 规则版本链详情 |
| POST | `/api/rules/:id/revoke` | 撤销当前版本（可带 `expectedVersion`） |
| POST | `/api/rules/:id/rollback` | `{targetVersion}` 回滚 = 追加复刻旧正文的新版本 |
| POST | `/api/trial` | **只读试算** `{eventId,items,atMs?}`：不落账、不签名 |
| POST | `/api/applications` | **批量申请** `{applicationNo,eventId,aggregatorId,items[]}`（幂等 200 / 新裁 201 / 冲突 409） |
| GET | `/api/applications` | 批次列表（按 seq） |
| GET | `/api/applications/:no` | 批次详情（逐设备裁决 + 复核层 + 冻结） |
| POST | `/api/applications/:no/items/:deviceId/review` | 逐项复核 `{reviewer,disposition:CONFIRMED\|OVERRULED,note}`（仅一次；冻结后拒绝） |
| POST | `/api/applications/:no/freeze` | 批次冻结（幂等） |
| GET | `/api/applications/:no/redacted.csv` | **脱敏清单下载**（仅冻结批次，否则 409） |
| GET | `/api/applications/:no/items/:deviceId/verify` | 复验逐设备裁决（canonical/摘要/公钥/签名） |
| GET | `/api/applications/:no/manifest` `/manifest/verify` | 冻结清单与复验 |
| POST | `/api/verify` | 完全离线验签 `{keyId?|publicKeyPem,canonical,signature}` |
| GET | `/api/keys` | 签发公钥列表（轮换历史） |
| POST | `/api/keys/rotate` | 轮换签发密钥（新裁决用新 keyId，旧批次仍按旧公钥复验） |
| GET | `/api/chain/verify` `/api/log?type=&limit=` | 哈希链校验 / 原始账本记录 |

### 错误码 → HTTP

- 400：`BAD_REQUEST`（含非法日键/枚举）、`UNKNOWN_COMMAND`、`DUPLICATE_ITEM`(422)
- 404：`DEVICE_NOT_FOUND` / `EVENT_NOT_FOUND` / `RULE_NOT_FOUND` / `VERSION_NOT_FOUND` /
  `APPLICATION_NOT_FOUND` / `ITEM_NOT_FOUND`
- 409：`APPLICATION_NO_CONFLICT`、`RULE_VERSION_CONFLICT`、`RULE_OVERLAP_DETECTED`、
  `RULE_REVOKED_STATE`、`DEVICE_EXISTS`、`EVENT_EXISTS`、`ITEM_ALREADY_REVIEWED`、`BATCH_FROZEN`、
  `BATCH_NOT_FROZEN`（下载/验清单时）、`DEVICE_ALREADY_SUSPENDED` / `DEVICE_NOT_SUSPENDED`
- 422：`SCOPE_REGION_MISMATCH`、`DUPLICATE_ITEM`
- 503：`CHAIN_QUARANTINED`（账本隔离，所有写入拒绝）、`GATE_KEY_UNAVAILABLE`

## 脱敏策略

CSV 只在**批次冻结后**导出，设备号/聚合商/复核人按“前缀 + `****` + 尾 2 位”打码
（如 `DEV-1001 → DEV-****01`、`AGG-LANKE → AGG-****KE`）；
列含裁决、拒绝原因中文、命中规则号/版本/版本摘要头、裁决摘要头、复核状态；
导出与任何响应都不包含私钥、HMAC 或上传密钥材料。

## 确定性种子（演示用）

仿真起点 `2026-10-05T08:00:00Z`。设备 `DEV-1001..1005`（ZJ/JS，含 CRITICAL 互斥、ISLAND、
一台暂停），事件 `EV-1008-ZJ`（浙江，提前 3 天）、`EV-1006-JS`、`EV-1005-FAST-ZJ`
（当天 10:00，仅 2 小时，演示最短提前期临界）；规则覆盖浙江/江苏 10 月、9 月（过期）、
11 月（定时生效）与 `DEV-1005` 设备级专用规则。调度台七个页签对应规则维护、试算、申请、
复核/冻结、脱敏下载、独立验签、账本/密钥。

## 文件

```
gate/
  server.js   HTTP API + 静态页面（端口 8093）
  engine.js   领域内核：规则版本链 / 评估纯函数 / 申请幂等 / 逐设备签名 / 复核 / 冻结 / 脱敏 CSV
  chain.js    只增 JSONL 哈希链（genesis 域隔离 / 残尾续链 / 篡改只读隔离）
  crypto.js   Ed25519 签发密钥 sidecar（0600），轮换只增、重放核对
  util.js     canonicalJSON / sha256 / UTC 日键
  public/     调度台（index.html + app.js，零依赖）
test/gate.test.js          21 项领域单测
test/gate-restart.test.js  5 项重启/篡改/残尾/确定性单测
scripts/gate-e2e.mjs       57 项真实 HTTP 断言（含真实进程重启与第三方独立验签）
```
