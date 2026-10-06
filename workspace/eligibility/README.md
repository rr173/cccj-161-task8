# 灵活负荷资格闸（Flexible Load Eligibility Gate）

调度员维护按 **设备 / 地区 / 生效日期** 组合的资格规则（可定时生效、撤销、回滚，全局规则版本链只增）；
聚合商就某个**响应事件**提交一批设备，服务返回**逐设备**准入裁决、命中的**规则版本**与
**Ed25519 签名 + 内容摘要**。

- 零依赖、纯 Node.js（≥ 20），复用编排内核的只增 SHA-256 哈希链（`src/store.js`）与 Ed25519/HMAC 原语。
- 独立进程（默认端口 **8093**），自有日志 `data/eligibility.log` 与签发密钥 sidecar
  `data/eligibility-keys.json`（0600，链上只有公钥）。
- 事件溯源：规则发布/撤销/回滚、设备登记/暂停、批次裁决/冻结全部只增；**历史批次绑定裁决当时的
  规则版本与链尖，后续任何规则变更/撤销/回滚都不追改**。
- 命令同步串行落账；真实进程重启后裁决顺序（recordSeq）、规则版本链、幂等台账与逐字节摘要完全一致。

```bash
npm run gate                 # 服务 + 运营台 → http://localhost:8093/
npm run test:e2e:eligibility # 41 项真实 HTTP 断言（含真实进程重启、版本钉死、脱敏核对）
# 领域契约
node --test test/eligibility.test.js   # 23 个单测
# 可选：PORT=8093 GATE_MEMORY=1 node eligibility/server.js  纯内存不落盘
```

## 逐设备裁决

按申请内顺序逐台裁决，单台拒绝不影响其他设备。全部检查独立执行，命中的拒绝原因**全部列出**
（规范顺序如下）：

| 原因码 | 含义 |
| --- | --- |
| `UNKNOWN_DEVICE` | 设备不在台账（未知设备），单独拒绝，无规则版本 |
| `CROSS_REGION` | 跨区域：设备所属地区 ≠ 响应事件地区 |
| `DEVICE_SUSPENDED` | 设备已被暂停 |
| `NO_APPLICABLE_RULE` | 事件日无生效规则（无规则 / 未到生效日 / 已过期 / 撤销已生效） |
| `MUTEX_TAG` | 设备标签命中规则的互斥（deny）标签集合 |
| `LEAD_TIME` | 距事件开始不足规则的最短提前期（边界相等视为满足） |

规则解析（事件日当天在版的规则）：**设备专属规则优先于地区默认规则**；同优先级取全局版本更大者。
跨区域设备仍解析其**本地区**规则并回传版本，但因 `CROSS_REGION` 被拒。

## 规则版本链 / 生效 / 撤销 / 回滚

- 每条规则 `RULE_PUBLISHED / RULE_REVOKED / RULE_ROLLED_BACK` 占用一个**全局只增版本号**，
  链尖为最近一条规则变动记录的哈希；同一规则多次发布其 `ruleVersion` 递增，旧版本永不删除
  （历史批次据此复验）。
- **定时生效**：`validFrom / validUntil` 为 UTC 日键（`YYYY-MM-DD`）；事件日落在区间内才适用。
- **撤销**：`effectiveFrom` 可为未来日（定时撤销）。撤销是不可变记录；生效日之前规则仍可裁决，
  当天起退出候选。已撤销规则不能直接改（`RULE_REVOKED`），必须**回滚**生成新版本。
- **回滚**：`{fromVersion}` 取某个历史版本内容，作为该 ruleId 的新版本重新在版
  （`restoredFromVersion` 留痕），不删改任何历史记录。
- **重叠规则**：新建规则与同作用域（同为某设备专属、或同为某地区默认）的任一在版规则日期重叠即
  `RULE_OVERLAP(409)`；日期相邻（前规则末日 < 新规则首日）允许。同 ruleId 发新版本为接替语义。
- **乐观并发**：发布/撤销可带 `expectedVersion`，与当前全局版本不符即 `RULE_VERSION_CONFLICT(409)`。

## 申请幂等与批次

- 每个写命令需 `requestId`。**同申请号 + 同正文 → 返回原批次**（不新增记录，状态 200）；
  **同申请号 + 不同正文 → 409 `REQUEST_ID_CONFLICT`**。台账（`GATE_REQUEST_INDEXED`）随链重放。
- 批次 `OPEN` 时可**冻结**（`BATCH_FROZEN`，幂等）；冻结后可下载**脱敏清单 CSV**
  （设备号打码 `前缀-****-短指纹`，不含名称/签名），未冻结下载 `BATCH_NOT_FROZEN(409)`。
- **空批次**合法：计数为 0、仍生成摘要与签名、可冻结下载。

## 签名与独立验签

批次签名范围为规范化 JSON（键名排序、无空白），任何语言按同一规则可复算：

```
canonical = canonicalJSON({
  batchId, requestId, aggregatorId, event, decidedAt, ruleChainTip,
  items: [{ order, deviceId, decision, reasons,
            rule: { ruleId, ruleVersion, version, contentHash } | null }]
})
batchDigest = sha256(canonical)
signature   = Ed25519(运营私钥, canonical)   # hex；公钥随 GATE_KEY_PUBLISHED 上链
```

`GET /api/batches/:id/verify` 独立重算摘要、用链上公钥验签、核对批次绑定的版本链尖仍指向那条
规则变动记录、并逐条核对回传的规则内容指纹。历史篡改任一字节都会使 `valid=false`。

## HTTP API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/api/state` | 完整视图（设备/规则/批次/版本链/密钥/链校验） |
| POST | `/api/devices` | 登记设备 `{deviceId,name,region,tags[],suspended?}` |
| POST | `/api/devices/:id/suspend` | `{suspended,reason?}`（恢复传 false） |
| POST | `/api/rules` | 发布/发新版本 `{ruleId?,scope:{region,deviceId?},body:{denyTags[],minLeadMinutes},validFrom,validUntil,expectedVersion?}` |
| GET | `/api/rules?region=&deviceId=&lifecycle=` | 规则头列表 |
| GET | `/api/rules/:ruleId` | 规则头 + 完整版本历史 |
| GET | `/api/rule-versions/:v` | 指定全局版本 |
| POST | `/api/rules/:ruleId/revoke` | `{reason,effectiveFrom?,expectedVersion?}` |
| POST | `/api/rules/rollback` | `{fromVersion,validFrom?,validUntil?}` → 新版本 |
| POST | `/api/rules/trial` | 试算不落盘 `{at?,event,deviceIds[],draftRule?}` |
| POST | `/api/applications` | 批量申请 `{requestId,aggregatorId,event:{eventId,region,startMs},deviceIds[]}`（201 新裁决 / 200 幂等重放） |
| GET | `/api/batches?aggregatorId=&status=` | 批次列表 |
| GET | `/api/batches/:id` | 批次详情（逐设备裁决/原因/绑定版本） |
| POST | `/api/batches/:id/freeze` | 冻结（幂等） |
| GET | `/api/batches/:id/verify` | 独立验签（摘要/签名/版本链尖/逐条规则指纹） |
| GET | `/api/batches/:id/redacted.csv` | 脱敏清单下载（仅冻结批次） |
| GET | `/api/chain/verify` | 哈希链 + 规则版本链尖校验 |
| GET | `/api/log?type=&limit=` | 原始 JSONL 记录 |
| POST | `/api/sim/tick` | `{minutes}` 推进仿真时钟 |
| POST | `/api/sim/reset` | 截断并重建种子 |

## 记录类型

```
SEED_CLOCK · SEED_AGGREGATOR · SEED_REGION · DEVICE_REGISTERED · DEVICE_UPDATED ·
DEVICE_SUSPENDED · GATE_KEY_PUBLISHED · GATE_REQUEST_INDEXED ·
RULE_PUBLISHED · RULE_REVOKED · RULE_ROLLED_BACK ·
BATCH_DECIDED · BATCH_FROZEN · SIM_TICK
```

每条记录：`{seq,ts,type,payload,prevHash,hash}`，
`hash = sha256(canonicalJSON({seq,ts,type,payload,prevHash}))`。
日志损坏的恢复契约（只读隔离 / 末尾断电残尾归档续链）与编排内核完全一致，见 `src/store.js`。

## 目录

```
eligibility/
  registry.js       领域内核：规则版本链 / 逐设备裁决纯函数 / 批次签名 / 冻结 / 脱敏 / 投影重放
  server.js         HTTP API + 运营台静态文件（端口 8093）
  public/           index.html + app.js（设备台账、规则维护、试算、批量申请、逐项复核、冻结/下载/验签）
test/eligibility.test.js     23 个领域单测
scripts/e2e-eligibility.mjs  41 项真实 HTTP 端到端断言（含真实进程重启）
```
