# Presigned URL Service

为资源提供**预签名临时访问**能力：在不暴露长期身份凭据的前提下，把短时、受限的
读取权限安全地交给第三方。签发、校验、消费状态持久化、撤销与审计相互独立，
可各自替换实现。

## 架构

```
presign/
├── config.py    # Settings：时钟偏移、轮换宽限、存储路径、密钥、作用域
├── models.py    # IssueRequest / Scope / ConsumeResult 等数据模型
├── errors.py    # DenyReason 稳定拒绝原因码 + 领域异常
├── signing.py   # KeyStore：HMAC-SHA256 签名、密钥轮换与宽限期校验
├── store.py     # StateStore：SQLite 持久化消费计数与撤销墓碑
├── audit.py     # AuditLogger：追加式 JSONL 审计日志（fsync 落盘）
├── service.py   # PresignService：签发 / 校验+消费 / 轮换 / 撤销 / 清理
└── api.py       # FastAPI 路由：/presign/issue|access|consume|revoke|rotate
```

## 签名算法

预签名地址是一个携带**全部约束参数**与签名的 URL：

```
/presign/access?tid=<uuid>&r=<resource>&op=<op>&exp=<unix>&mu=<n|空>
               &iat=<unix>&iss=<issuer>&kid=<key-id>&sig=<hex>
```

- 算法：**HMAC-SHA256**（`hashlib.sha256`，hex 编码），密钥为服务端持有的对称密钥。
- 被签名的载荷是所有约束字段的**规范化编码**（`\n` 连接、带版本前缀 `v1`）：

  ```
  v1\ntid\nresource\nop\nexp\nmu(空=不限次)\niat\nissuer\nkid
  ```

- 校验时用 URL 中声明的参数**重建**载荷再验签：篡改任一参数（资源、操作、
  过期时间、次数、签发者、密钥 id）都会导致签名不匹配而被拒绝。
- 比较使用 `hmac.compare_digest`，避免时序侧信道。

## 约束语义

| 参数 | 语义 |
|---|---|
| `r` | 资源路径。消费时请求的资源必须与签名值**完全相等**，否则 `resource_mismatch` |
| `op` | 允许的操作（当前为 `read`）。不匹配拒绝 `operation_not_allowed` |
| `exp` | 过期时间（unix 秒）。`now > exp + clock_skew` 时拒绝 `expired` |
| `mu` | 最大使用次数；空表示有效期内不限次。超限拒绝 `usage_exhausted` |
| `iat` | 签发时间。`iat - clock_skew > now`（未来签发的地址）拒绝 `not_yet_valid` |
| `iss` | 签发者身份，参与签名，防伪造 |
| `kid` | 签名密钥 id，用于轮换后选择验签密钥 |
| `tid` | 地址唯一 id，消费计数与撤销状态的持久化键 |

**时钟偏移容忍**：`clock_skew_seconds`（默认 30s）同时应用于过期与签发时间检查，
容忍消费方时钟轻微偏移；配置为 0 即严格模式。

**限次语义**：消费计数在 SQLite 单事务内"检查并自增"（`BEGIN IMMEDIATE`），
并发请求下累计次数绝不超过 `mu`；每次消费结果确定（第 N 次成功、之后
`usage 耗尽`）并写入审计。校验失败（如资源不匹配）**不消耗**次数。

**密钥轮换**：`rotate` 后新密钥立即用于签发；旧密钥进入宽限期
（`rotation_grace_seconds`，默认 300s），宽限期内旧地址仍可校验，之后拒绝
`key_retired`。轮换与校验并发时结果一致：校验要么看到轮换前状态（成功），
要么看到轮换后状态（宽限期内仍成功）。

**持久化与恢复**：消费计数与撤销状态存于 SQLite（WAL + `synchronous=FULL`），
进程重启后已用次数不回退；消费要么整体提交要么整体回滚，不留部分写入。

**撤销**：支持单个或批量撤销。撤销在有效期内立即生效（拒绝 `revoked`）。
撤销记录是**墓碑**：`cleanup` 只清理过期且未撤销的行，因此被撤销的地址在
清理后仍可与"从未签发"（`unknown_token`）区分。

**签发作用域**：每个调用方身份绑定 `资源前缀 + 操作集合`。越权签发拒绝
`out_of_scope` 并写审计；未知身份在 HTTP 层直接 403。

## 配置项

均可用环境变量覆盖（前缀 `PRESIGN_`）：

| 环境变量 | 默认 | 说明 |
|---|---|---|
| `PRESIGN_CLOCK_SKEW_SECONDS` | `30` | 时钟偏移容忍秒数 |
| `PRESIGN_ROTATION_GRACE_SECONDS` | `300` | 旧密钥验签宽限秒数 |
| `PRESIGN_DB_PATH` | `./presign-state.db` | 消费/撤销状态 SQLite 路径 |
| `PRESIGN_AUDIT_LOG_PATH` | `./presign-audit.log` | 审计日志（JSONL）路径 |
| `PRESIGN_ACTIVE_KEY_ID` | `k1` | 当前签名密钥 id |
| `PRESIGN_SIGNING_KEYS` | `k1:dev-only-secret-change-me` | `kid:secret[,kid:secret...]` |
| `PRESIGN_SCOPES` | `alice:docs/:read` | `身份:前缀:op\|op;身份2:...` |

## HTTP 接口

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/presign/issue` | 签发；头 `X-Caller-Id` 为调用方身份，体 `{resource, operation, expires_at, max_uses?}` |
| GET | `/presign/access?...` | 预签名地址本身；访问即消费一次 |
| POST | `/presign/consume` | 显式校验：体 `{token, resource, operation}` |
| POST | `/presign/revoke` | 批量撤销：体 `{token_ids: [...]}` |
| POST | `/presign/rotate` | 轮换密钥：体 `{new_key_id, new_secret}` |
| GET | `/presign/health` | 健康检查 |

## 本地验收（可复现）

```bash
uv sync                 # 安装依赖（uv 管理 Python 3.14）
uv run pytest -q        # 40 个用例：过期/时钟偏移/并发超次/轮换/重启/撤销/越权/篡改
./scripts/acceptance.sh # 端到端演示：起服务、签发、访问、重放拒绝、撤销、轮换
```

审计日志每行一个 JSON：`issued / issue_denied / consume_allowed /
consume_denied / key_rotated / revoked / cleanup`，可用于追溯每一次决定。
