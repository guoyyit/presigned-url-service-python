# Presigned Temporary Access Service (Python)

在**不暴露长期身份凭据**的前提下，把短时且受限的资源读取权限安全地交给第三方：
签发、校验、消费状态持久化、撤销与审计相互独立。基于 FastAPI + SQLite(WAL) 实现，
HMAC-SHA256 签名，无外部服务依赖，提供确定性的本地验收方式。

- 签名与全部约束参数随 URL 携带，过期或任一参数被篡改即拒绝
- 时钟偏移容忍可配置；过期重放、参数篡改一律失败
- 单次 / 有限次使用；并发（线程与多进程）累计次数绝不超过授权上限
- 按资源路径前缀、操作类型、调用方身份限定签发与消费
- 签名密钥可轮换；旧密钥签发的地址在可配置宽限期内仍可校验，宽限期结束失效
- 使用次数持久化（WAL + `BEGIN IMMEDIATE` 原子事务），重启不回退、无部分写入
- 支持单个 / 批量撤销；清理后保留**墓碑（tombstone）**，与从未签发区分
- 每个决策（成功或拒绝）都写审计日志

---

## 1. 快速开始

```bash
uv sync                                  # 安装依赖
uv run pytest -q                         # 运行全部自动化测试（44 个）
uv run python scripts/acceptance_demo.py # 确定性本地验收（FakeClock + 临时 DB）
uv run fastapi dev main.py               # 启动服务（开发态默认 token: dev-token）
```

开发态默认调用方：`caller_id=dev`，前缀 `/`，操作 `read/write/delete`，
Bearer token 为 `dev-token`。**仅限本地开发**，生产请用 `PRESIGNED_CALLERS_FILE`。

### 端到端调用示例

```bash
BASE=http://localhost:8000
AUTH='Authorization: Bearer dev-token'

# 1) 签发：/data/a/report.pdf，只读，10 分钟有效，最多使用 2 次
curl -s -X POST $BASE/grants -H "$AUTH" -H 'Content-Type: application/json' -d '{
  "resource_path": "/data/a/report.pdf",
  "operation": "read",
  "ttl_seconds": 600,
  "max_uses": 2
}'
# => {"url": "http://localhost:8000/consume?...&sig=<hex>", "grant_id": "...", ...}

# 2) 第三方消费（无需任何长期凭据，签名本身即授权凭证）
curl -s '<上面返回的 url>'

# 3) 撤销（只能撤销自己签发且在自己路径范围内的地址）
curl -s -X POST $BASE/grants/revoke -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"grant_ids": ["<grant_id>"]}'

# 4) 查询状态 / 审计
curl -s $BASE/grants/<grant_id> -H "$AUTH"
curl -s "$BASE/audit?grant_id=<grant_id>" -H "$AUTH"
```

---

## 2. HTTP 接口

| 方法 & 路径 | 鉴权 | 说明 |
|---|---|---|
| `POST /grants` | Bearer token | 签发预签名地址，按调用方 scope 校验 |
| `GET/POST /consume` | 无（签名即凭证） | 校验并原子消费一次使用次数 |
| `POST /grants/revoke` | Bearer token | 单个/批量撤销，仅本人且前缀范围内 |
| `POST /grants/cleanup` | 无（管理操作） | 把已撤销授权折叠为墓碑 |
| `GET /grants/{id}` | Bearer token | 状态：`active/revoked/tombstone/never_issued` |
| `POST /keys/rotate` | Bearer token | 轮换签名密钥 |
| `GET /audit?grant_id=&limit=` | Bearer token | 查询审计事件 |
| `GET /health` | 无 | 健康检查 |

> 消费方身份绑定：签发时传 `consumer`，则消费时必须带 `X-Consumer: <id>`，
> 否则按 `scope_denied` 拒绝并审计。

### 消费结果语义（确定性、可审计）

| 场景 | HTTP 状态 | `reason` |
|---|---|---|
| 成功 | 200 | —（返回 `used_count/max_uses`） |
| 签名无效 / 参数篡改 / 密钥宽限期结束 / 身份不符 | 403 | `invalid_signature` / `scope_denied` |
| 已过期（含超出时钟偏移） | 410 | `grant_expired` |
| 已撤销（含墓碑） | 410 | `grant_revoked` |
| 次数用尽 | 409 | `usage_exhausted` |
| 从未签发 | 404 | `grant_not_found` |

---

## 3. 预签名地址与签名算法

地址所有约束参数都在 query string 中，校验方无需额外上下文：

```
/consume?kid=<签名密钥版本>
        &gid=<授权 ID，uuid4 hex>
        &p=<资源路径，URL 编码>
        &op=<read|write|delete>
        &exp=<绝对过期 unix 秒>
        &n=<最大使用次数 | "unlimited">
        &iat=<签发 unix 秒>
        &alg=HMAC-SHA256
        &sig=<HMAC-SHA256 十六进制>
```

**规范签名串（UTF-8，换行分隔）**：

```
HMAC-SHA256
<grant_id>
<resource_path>
<operation>
<expires_at>
<max_uses 或字面量 unlimited>
<issued_at>
<key_id>
```

`sig = hex(HMAC_SHA256(secret, canonical))`，使用 `hmac.compare_digest` 做常量时间比较。
篡改任意参数（包括 `kid`、`exp`、`n`、`p`、`op`、`iat`）都会改变规范串，签名校验失败。

### 校验顺序（服务端）

1. 解析参数（缺失/重复/非整数 → `invalid_request`）。
2. 用 `kid` 找密钥并重算 HMAC（未知 `kid` / 不匹配 → `invalid_signature`）。
3. 取服务端授权记录（不存在 → `grant_not_found`；撤销/墓碑 → `grant_revoked`）。
4. 逐项比对记录与签名参数（任一不符 → `constraint_violation`），并校验消费方身份。
5. 时钟偏移内的有效期校验：`now <= exp + skew`（超出 → `grant_expired`）。
6. 密钥宽限期校验：当前密钥可用；被轮换密钥需满足 `grace > 0` 且
   `now - rotated_at <= grace`，否则 `invalid_signature`。
7. **原子消费**：`BEGIN IMMEDIATE` 事务内检查状态/上限并 `used_count+1`。
   竞争失败由数据库行的最终状态决定，返回确定的 `usage_exhausted`/`grant_revoked`。

> 即使签名者把 `exp/n/...` 改成更宽松的值，HMAC 也会立即失败；且服务端授权记录
> 会对这些字段做二次比对，签名只负责防篡改，授权状态以持久化记录为准。

---

## 4. 约束语义

- **有效期**：`ttl_seconds > 0`，存绝对时间 `exp = iat + ttl`，边界 `exp` 时刻仍可用。
- **时钟偏移**：`skew` 非负，双侧容忍；`now > exp + skew` 才判过期。
- **使用次数**：`max_uses >= 1` 或省略（不限次）。计数由 SQLite 写事务串行化，
  线程并发和多进程并发都不会超过上限；超次请求得到稳定的 `409 usage_exhausted`。
- **签发范围**：调用方必须同时满足 `path_prefixes` 前缀匹配与 `operations` 包含，
  越权签发返回 403 并写 `issue/denied` 审计。
- **消费范围**：可选绑定 `consumer`；撤销仅授权的签发者本人（且路径仍在其前缀内）。
- **撤销**：仅对 `active` 生效，重复撤销幂等（`already_revoked`）；批量接口对每个
  ID 分类返回 `revoked/not_found/already_revoked/denied`。
- **清理与墓碑**：`cleanup` 抹除撤销记录的资源/操作/密钥/计数等敏感与约束字段，
  但保留 `state='tombstone'` 行，因此清理后的 ID 仍与从未签发（无记录）区分。
- **密钥轮换宽限期**：轮换后旧密钥记录 `rotated_at`；`grace<=0` 表示旧密钥立即失效。

---

## 5. 密钥轮换与并发一致性

- 密钥仅以版本号 `kid` 出现在 URL，**密钥明文永不下发**。
- 轮换在进程内加锁串行化；新密钥 `insert` 与旧密钥 `mark_rotated` 先落库再更新内存，
  崩溃不会出现“内存里在用、库里没有”的当前密钥。
- 校验读取一致快照：当前密钥始终可用；旧密钥在宽限期内可用。并发轮换不会产生
  分叉，库中永远恰好一个 `rotated_at IS NULL` 的当前密钥（测试覆盖 8 路并发轮换）。

---

## 6. 持久化与崩溃安全

SQLite（WAL 模式，`synchronous=FULL`，`busy_timeout=30s`）三张表：

- `signing_keys(key_id, secret, created_at, rotated_at)`
- `grants(grant_id, resource_path, operation, expires_at, max_uses, used_count,
  state, key_id, issuer, consumer, created_at, revoked_at, revoke_batch_id)`
- `audit_events(id, event_time, event_type, grant_id, caller_id, resource_path,
  operation, result, reason, detail)`

消费是一条 `BEGIN IMMEDIATE` 事务：行锁内读取 → 检查 → 自增 → 提交。
事务中崩溃则整体回滚，不留部分写入；提交结果在重启后依然生效。

---

## 7. 配置项（环境变量）

| 变量 | 默认值 | 说明 |
|---|---|---|
| `PRESIGNED_DB_PATH` | `presigned.db` | SQLite 文件；`:memory:` 可用于单测 |
| `PRESIGNED_CLOCK_SKEW_SECONDS` | `0` | 过期校验时钟偏移容忍（秒，双侧） |
| `PRESIGNED_KEY_GRACE_SECONDS` | `86400` | 旧轮换密钥的校验宽限期（秒）；`0` 立即失效 |
| `PRESIGNED_SIGN_ALG` | `HMAC-SHA256` | 签名算法标签，参与签名串 |
| `PRESIGNED_BASE_URL` | `http://localhost:8000` | 生成预签名 URL 的基地址 |
| `PRESIGNED_CALLERS_FILE` | （未设置用 dev） | 调用方 token → 身份与 scope 的 JSON |

`PRESIGNED_CALLERS_FILE` 格式见 [`config/callers.example.json`](config/callers.example.json)。

生产启动示例：

```bash
export PRESIGNED_DB_PATH=/var/lib/presigned/presigned.db
export PRESIGNED_CLOCK_SKEW_SECONDS=30
export PRESIGNED_KEY_GRACE_SECONDS=86400
export PRESIGNED_BASE_URL=https://presigned.example.com
export PRESIGNED_CALLERS_FILE=$PWD/config/callers.example.json
uv run fastapi run main.py --host 0.0.0.0 --port 8000
```

---

## 8. 审计

每次签发、消费（成功/拒绝及原因）、撤销、清理、轮换都写 `audit_events`。
可按 `grant_id` 检索，重复消费会得到确定的结果且每次都有审计记录。

## 9. 项目结构

```
presigned/
  clock.py     # 可注入时钟（SystemClock / FakeClock）
  config.py    # 环境配置、调用方身份与签发范围
  crypto.py    # HMAC 原语、版本化 KeyStore（轮换/宽限期）
  signing.py   # 规范签名串、URL 构造/解析/验签
  storage.py   # SQLite：密钥/授权/原子计数/撤销/墓碑/审计
  service.py   # 编排：签发、校验消费、撤销、轮换、审计
  api.py       # FastAPI 路由与错误码映射
  models.py    # 领域模型   errors.py  # 领域错误码
scripts/acceptance_demo.py  # 可复现本地验收
tests/                      # 44 个自动化测试
```

## 10. 测试覆盖

| 文件 | 场景 |
|---|---|
| `tests/test_expiry.py` | 有效期边界、过期重放、过期审计 |
| `tests/test_clock_skew.py` | 偏移容忍边界、零偏移、任意参数篡改、签名篡改 |
| `tests/test_concurrency.py` | 16/32 线程与 20 进程并发超次、单次唯一赢家、审计完整 |
| `tests/test_key_rotation.py` | 宽限期内外、零宽限立即失效、8 路并发轮换一致性 |
| `tests/test_restart_recovery.py` | 计数/撤销/墓碑/密钥跨重启恢复、崩溃回滚无部分写入 |
| `tests/test_revocation.py` | 单个/批量/幂等撤销、清理墓碑与从未签发区分、历史保留 |
| `tests/test_scope.py` | token 鉴权、前缀/操作越权、跨人撤销、consumer 绑定 |
