# 证据归档与冲突核验模块（现场网关离线作业包）

断网期间多个现场网关各自保存**同一作业包**的清单、围栏变更、分段回执与检查点。运营人员通过
网页或 HTTP 接口导入这些**带签名的证据包**；模块校验规范化签名与哈希链后，按 `packageId` 归档，
并生成**可阅读、可下载的核验报告**。零依赖，纯 Node.js ≥ 20，独立进程（默认端口 **8092**）。

```bash
npm run evidence                 # 启动服务 → http://localhost:8092/
npm run demo:evidence            # 一键演示 9 个场景（有效/重复/冲突/多围栏/倒退/篡改/错签）+ 保全销毁
npm run demo:evidence -- --print # 输出可直接粘到网页的示例信封（含两个网关公钥）
npm run test:e2e:evidence        # 88 项真实 HTTP 断言（含真实进程重启）
npm run test:e2e:evidence-destroy # 90 项保全与销毁 HTTP 断言（含真实进程重启与中断态注入）
```

## 信任模型与密钥纪律

- **网关私钥（Ed25519）只存在于网关/制包工具侧**，服务从不接收；注册接口只收 SPKI 公钥 PEM，
  收到私钥材料直接 `PRIVATE_KEY_REJECTED`。
- **upload secret** 用于导入鉴权，仅经请求头 `X-Upload-Secret` 传输，常量时间比较；
  存于 `data/evidence/upload-secret.json`（**0600**；环境变量 `EVIDENCE_UPLOAD_SECRET` 优先），
  任何响应、页面、日志、导出报告都**不回显**该值。
- 被拒绝的信封原样落盘到 `data/evidence/rejected/`（**0600**，仅审计用），不进入证据链。

## 证据信封（可独立复算）

```jsonc
{
  "schema": "offline-evidence/1",
  "packageId": "PKG-001",
  "gatewayId": "gw-A",
  "keyId": "gw-key-1",
  "records": [ /* manifest / fence / segment / checkpoint */ ],
  "envelopeHash": "<sha256(canonicalJSON({schema,packageId,gatewayId,keyId,records}))>",
  "signature": "<Ed25519 网关私钥对 envelopeHash hex 文本的签名>"
}
```

规范化规则：键名字典序、无多余空白（见 `hashing.js#canonicalJSON`，任意语言可复算）。
记录字段有**严格白名单**，夹带未知字段整包拒绝。四类记录：

| kind | 关键字段 |
| --- | --- |
| `manifest` | `manifest.entries[{seq,deviceId}]`、`issuedAt`、`validUntil`、`manifestHash`（内容不自洽即 `MANIFEST_HASH_MISMATCH`） |
| `fence` | `fenceId`、`version`（全局只增、必须连续）、`action: CREATED/REVISED/CLOSED`、`prevVersion` |
| `segment` | `fenceId`、`fenceVersion`、`segSeq`（同围栏严格递增）、`entries[{seq,deviceId,outcome,note?}]`（序号/设备必须与清单一致） |
| `checkpoint` | `fenceVersion`、`lastSeq`、`counts{EXECUTED,SKIPPED,FAILED}` |

## 裁决流水线（严格顺序）

1. **结构**：信封/记录形状、字段白名单；
2. **信封哈希**：规范化复算，任何字节被改 → `ENVELOPE_HASH_MISMATCH`；
3. **注册表 + Ed25519 验签**：未知网关 `GATEWAY_UNKNOWN`，keyId 不符 `SIGNATURE_KEY_MISMATCH`，
   签名失败 `SIGNATURE_INVALID`（**先验签后查重复**，错签信封不能借"同哈希重复"放行）；
4. **重复导入**：同一 `envelopeHash` 返回**首次裁决原结果**（同 `importId`、同首次时间、同 disposition）；
5. **业务规则**：manifest 首位、序号/设备范围、围栏版本连续（`FENCE_VERSION_GAP`）、
   引用围栏存在（`FENCE_UNKNOWN`）、分段号递增；
6. **槽位裁决（原子）**：
   - 同槽位（manifest / `fence:id:v#` / `segment:id:v#:seg#` / `checkpoint:id:v#`）**同语义指纹** → 幂等跳过；
   - **不同指纹 → 冲突隔离**：原证据写入 `quarantine.jsonl`（保留外来+已存双指纹），
     **已存证据绝不覆盖**；
   - 检查点跨围栏**不倒退**：新版本 `lastSeq` 低于历史最高 → `CHECKPOINT_REGRESSED` 隔离；
   - `CLOSED` 是围栏生命周期推进（独立槽），重复 CLOSED 幂等。

> **语义指纹**只覆盖业务字段（不含 `ts`、网关身份、信封哈希），所以同内容由不同网关、
> 不同时刻重传判为**重复**而非冲突；同分段号但 outcome/note 不同则判**冲突**。

## 落盘与重启（摘要不变）

每个包目录 `data/evidence/packages/<packageId>/` 下三条独立 SHA-256 哈希链（各自 genesis 锚定
`packageId`，跨包/跨链调换即断）：

```
ledger.jsonl      已接受证据（只增，永不覆盖/删除）
quarantine.jsonl  冲突隔离的原证据（含已存证据指纹）
audit.jsonl       每次导入裁决（ACCEPTED / DUPLICATE / CONFLICTS）
```

- 进程重启时逐行重放重建全部投影；**报告摘要 `reportDigest`、冲突列表、链尖重启前后完全一致**。
- 链文件**中途损坏/断链/哈希不符** → 该链只读隔离（503 `CHAIN_QUARANTINED`），文件原样保留；
- 仅文件**末尾单条无换行残尾**（断电）→ 原始字节归档到同目录旁证后截断续链。

## 核验报告

- **确定性时间线**：按 `(围栏版本, 事件类别, 分段序号, ts, ledgerSeq)` 排序，
  围栏创建/关闭、分段回执、检查点交错呈现；
- **多围栏合并**：当前围栏=最高版本；当前检查点从高版本向低版本取第一个有效水位，
  高版本尚无检查点时**沿用上一围栏水位（carried）**，绝不因新围栏把水位归零；
- **旧围栏证据仍可查询**（`GET .../fences/:version`），但显式标注"不得作为当前进度"；
- 报告导出三种格式，**全部经递归脱敏**（敏感键名、私钥 PEM、密钥字面量一律打码）：
  - `GET /api/packages/:id/report.json`（下载，带 `redaction.applied`）
  - `GET /api/packages/:id/report.txt`（可阅读文本）
  - `GET /api/packages/:id/report.html`（可内嵌 HTML 片段）
- `reportDigest = sha256(canonicalJSON(确定性语义字段 + 三链链尖 + 时间线 + 冲突 + 裁决))`，
  不含生成时间/接收时间等易变项——重复导入与重启都不改变它。

## 证据保全与到期销毁（legal hold & expiry destruction）

运营人员为作业包设置**保留期限**；审计人员在期限内发起带**原因 + 案件号**的**保全**；
一个作业包可同时被多个有效保全约束，**只有全部解除且期限已到才允许销毁**。
全部生命周期事实写入全局哈希链 `data/evidence/lifecycle.jsonl`（genesis 锚定 GLOBAL）——
包目录被物理删除后，期限/保全/解除/回执历史仍可独立核验。

- **期限设置**：`POST /api/packages/:id/retention`（`requestId` 幂等：同号同文返原结果，
  同号异文 `409 REQUEST_ID_CONFLICT`）；未设期限的包永不自动销毁。
- **保全**：`POST /api/packages/:id/holds`（`caseNo/reason/auditor` 必填；**仅期限内**可发起，
  过期 `409 RETENTION_EXPIRED`；同案件号有效保全唯一 `409 HOLD_CASE_ACTIVE`）。
- **解除**：`POST /api/packages/:id/holds/:holdId/release`；**错误案件号** `409 CASE_NO_MISMATCH`；
  **并发解除**安全失败 `409 HOLD_ALREADY_RELEASED`（同 `requestId` 重放仍返原结果）。
- **两阶段提交销毁**（全程同步临界区，保全创建/解除/到期任务不会与提交交错，绝不误删）：
  1. `DESTRUCTION_PREPARED`：枚举并哈希全部待删对象（**不删任何字节**）；
  2. `DESTRUCTION_COMMITTED`：**提交点**——签名回执入链，业务索引（内存投影）随提交失效。
     **提交前读接口返回完整旧状态，提交后统一 `410 PACKAGE_DESTROYED`，看不到部分删除**；
  3. 物理删除：链文件（ledger/audit）、冲突材料（quarantine + rejected 留底）、
     凭据旁车（`*.keys.json` 等）、索引文件、残尾旁证，随后 `DESTRUCTION_COMPLETED`；
     删除失败记 `DESTRUCTION_FAILED`（`500 STORAGE_DELETE_FAILED` + 剩余文件清单），
     `POST /api/packages/:id/destruction/retry` 重试，**绝不产生第二份回执**。
- **崩溃恢复**：重启重放生命周期链即可区分 **尚未开始（NONE）/ 正在提交（PREPARED）/
  已提交删除中（COMMITTED）/ 已完成（COMPLETED）**，并继续到唯一结果：
  仅 PREPARED（提交前断电，文件完整）→ 重新执行；COMMITTED 未 COMPLETED → 继续删剩余文件。
  回执 ID 由 `packageId + 计划哈希` 派生，重复执行/恢复永远得到同一份回执。
- **签名销毁回执**（`destruction-receipt/1`，**不含原始证据**）：只有文件哈希/计数/链尖/
  报告摘要/案件号等元数据；Ed25519 签名（私钥 sidecar `destruction-key.json` 0600，
  公钥经 `GET /api/destructions/key` 公开）。独立验签：
  `receiptHash = sha256(canonicalJSON(回执去掉 signature/keyId/receiptHash))`，
  签名为对该 hex 文本的 Ed25519 签名；`GET /api/destructions/:receiptId/verify` 一键复验。
- **到期任务**：服务每 `EVIDENCE_SWEEP_MS`（默认 60s，`0` 关闭）清扫合格包；
  也可 `POST /api/destructions/sweep` 手动触发；`GET /api/destructions/pending`
  给出 合格/被保全阻塞/在途 三类待销毁视图。

## HTTP API

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/api/gateways` | 登记网关公钥（需 `X-Upload-Secret`；拒收私钥） |
| GET | `/api/gateways` | 已登记网关列表 |
| POST | `/api/packages/:id/import` | 导入证据信封（201 ACCEPTED / 200 CONFLICTS或DUPLICATE；拒绝 4xx） |
| GET | `/api/packages` | 包列表（摘要/当前围栏/水位/冲突数） |
| GET | `/api/packages/:id/report` | 完整脱敏报告（JSON） |
| GET | `/api/packages/:id/report.{json,txt,html}` | 下载/预览脱敏报告 |
| GET | `/api/packages/:id/timeline` | 确定性时间线 |
| GET | `/api/packages/:id/conflicts` | 冲突隔离清单 |
| GET | `/api/packages/:id/fences/:version` | 指定围栏证据（旧围栏标注"不充当进度"） |
| GET | `/api/packages/:id/imports` | 导入裁决历史 |
| GET | `/api/packages/:id/verify` | 三包哈希链校验 |
| GET | `/api/chain/verify` | 全部包链 + 生命周期链校验 |
| POST | `/api/admin/restart` | 丢弃内存投影并从磁盘重放（等价进程重启，便于页面核对） |
| POST | `/api/packages/:id/retention` | 设置保留期限 `{requestId, retainUntil, setBy, reason?}`（幂等；同号异文 409） |
| GET | `/api/packages/:id/lifecycle` | 期限/保全/销毁状态/资格视图（可核对阻塞项） |
| POST | `/api/packages/:id/holds` | 发起保全 `{requestId, caseNo, reason, auditor}`（期限内；幂等） |
| GET | `/api/packages/:id/holds` | 保全列表（销毁后仍可查） |
| POST | `/api/packages/:id/holds/:holdId/release` | 解除保全 `{requestId, caseNo, releasedBy?, reason?}`（案件号必须匹配） |
| GET | `/api/packages/:id/destruction` | 销毁状态（NONE/PREPARED/COMMITTED/FAILED/COMPLETED + 回执） |
| POST | `/api/packages/:id/destroy` | 立即执行销毁 `{requestedBy, reason?}`（两阶段提交；重复执行返原回执） |
| POST | `/api/packages/:id/destruction/retry` | 存储删除失败后恢复重试（不产生第二份回执） |
| GET | `/api/destructions/pending` | 待销毁列表（合格/被保全阻塞/在途） |
| POST | `/api/destructions/sweep` | 到期任务：清扫全部合格包（跳过原因可核对） |
| GET | `/api/destructions` | 全部销毁回执列表 |
| GET | `/api/destructions/:receiptId` | 回执详情（不含原始证据） |
| GET | `/api/destructions/:receiptId/verify` | 回执验签（哈希自洽/签名/链锚定/结构检查） |
| GET | `/api/destructions/key` | 销毁签名公钥（Ed25519，独立验签用） |

环境变量：`EVIDENCE_PORT`（默认 8092）、`EVIDENCE_HOST`、`EVIDENCE_DIR`
（默认 `data/evidence`）、`EVIDENCE_UPLOAD_SECRET`、`EVIDENCE_DEMO=1`（开启本机密钥对演示接口）、
`EVIDENCE_SWEEP_MS`（到期任务周期，默认 60000，`0` 关闭）。

## 目录

```
evidence/
  hashing.js   规范化 JSON / 记录哈希 / 语义指纹 / 槽位 / 递归脱敏 / 安全日志字段
  crypto.js    Ed25519 验签、upload secret sidecar(0600)、网关公钥注册表、销毁签名密钥、常量时间比较
  pack.js      网关侧制包 SDK（buildEnvelope/R.manifest/R.fence/...），供任意实现对照
  chains.js    通用 JSONL 哈希链（残尾恢复 / 损坏只读隔离）
  archive.js   归档内核：校验流水线、槽位去重/冲突、三链落账、ArchiveManager
  lifecycle.js 保全与销毁：保留期限/案件保全/两阶段提交销毁/签名回执/崩溃恢复/到期任务
  report.js    报告纯函数投影 + 确定性摘要 + JSON/TXT/HTML 脱敏渲染
  server.js    HTTP API + 网页 + 脱敏结构化日志
  demo.mjs     9 场景一键演示 + 保全销毁演示 / --print 输出示例信封
  public/      运营页面（index.html + app.js，含保全与销毁面板）
scripts/evidence-e2e.mjs         88 项真实 HTTP 端到端断言（含真实进程重启）
scripts/evidence-destroy-e2e.mjs 90 项保全与销毁 HTTP 断言（含中断态注入与真实进程重启）
test/evidence.test.js            22 个领域单测
test/evidence-lifecycle.test.js  20 个保全与销毁单测
```
