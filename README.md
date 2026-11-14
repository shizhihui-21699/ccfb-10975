# OAuth Authorization Server

统一的 OAuth 2.0 授权服务器，用于把公司各系统的登录收口到一处。Node + TypeScript 实现。

## 能力

| 能力 | 实现 |
| --- | --- |
| 授权码模式 | `GET /authorize` + `POST /token`，仅支持 `response_type=code` |
| PKCE | **强制**，仅接受 `S256`；`plain` 直接拒绝 |
| DPoP | RFC 9449，令牌绑定到客户端密钥；`dpop_jkt` 绑定授权码 |
| Refresh Token 轮换 | 每次使用即轮换，旧令牌重放 → 吊销整条令牌家族 |
| 内省 | `POST /introspect`，RFC 7662 |
| 吊销 | `POST /revoke`，RFC 7009（吊销 refresh token 连带吊销其家族内所有 access token） |
| 客户端注册 | `POST /register`，RFC 7591；回调地址严格校验 |
| 管理页 | `/admin`：客户端、令牌家族、重放记录、审计日志 |
| 发现文档 | `GET /.well-known/oauth-authorization-server`，RFC 8414 |

## 运行

```bash
npm install
npm start          # 或 npm run dev（文件变更自动重启）
npm test           # 125 个测试
npm run typecheck
```

首次启动会在数据库为空时生成演示账号与示例客户端，**明文凭据只在启动日志里出现一次**：

```json
{"message":"bootstrap_credentials_generated","users":[{"username":"alice",...}],"clients":[...]}
```

把日志中 `admin` 用户的密码拿去登录 `/login`，即可访问 `/admin`。

环境变量见 `.env.example`。要点：

- `ISSUER` 必须与外部可访问的地址一致（发现文档和 DPoP 的 `htu` 校验都依赖它）。
- `SESSION_SECRET` 生产环境必须设置；留空则每次进程启动随机生成（重启后所有会话失效，但功能正常）。
- `DATABASE_PATH` 默认 `./data/oauth.sqlite`。

## 关键设计决策

下面这些是需求里没写死、按 RFC 自行裁定的部分，一并列出理由。

### PKCE 强制、且只支持 S256

RFC 9700 §2.1.1 要求授权服务器必须缓解 PKCE 降级攻击。本项目对所有客户端（含机密客户端）一律强制 PKCE，且拒绝 `plain`——`plain` 会让截获授权请求的攻击者直接兑换授权码。`code_challenge` 缺失或 `code_challenge_method != S256` 都在授权端点直接报 `invalid_request`。

**校验失败即作废授权码**（`failed_at`），而不是让客户端重试。否则攻击者可以反复猜 `code_verifier`，或与合法客户端并发兑换。

### DPoP 的边界

按 RFC 9449 实现，几个容易做错的点：

- `typ` 必须是 `dpop+jwt`，`alg` 只接受非对称算法（`none`、`HS*` 一律拒绝），`jwk` 中只要带私钥字段（`d`/`p`/`k` …）就拒绝。
- `htu` 比较忽略 query 与 fragment，并做 scheme/host 小写、默认端口省略的归一化。
- `jti` 按 `(jkt, jti)` 单次使用；保留窗口 `DPOP_JTI_RETENTION_SECONDS`（默认 120s）。
- `iat` 双向窗口：过期容忍 `DPOP_IAT_TOLERANCE_SECONDS`（默认 60s），未来偏差 `DPOP_IAT_FUTURE_SKEW_SECONDS`（默认 5s）。
- 授权请求带 `dpop_jkt` 时，兑换阶段的 proof 必须用同一把钥匙，否则 `invalid_grant`。
- **公开客户端的 refresh token 必须绑定密钥**（RFC 9449 §5）；机密客户端已有客户端认证做 sender-constraint，所以换钥匙不会杀掉家族，但那把旧钥匙签的 access token 依然不可用。
- 传输过程中 DPoP proof 的 `jti` 在校验后立即落库，因此并发重放不可能同时成功。

### Refresh Token 轮换与家族吊销

家族（`token_families`）是一条授权授予的完整生命周期。每次刷新：

1. 原子消费旧 refresh token（`UPDATE ... WHERE used_at IS NULL`，只有一个请求能赢）；
2. 签发下一代 refresh token + 新 access token，`generation` 自增。

任一异常——旧令牌 `used_at` 非空、家族已吊销、密钥不匹配、并发竞争失败——都会**吊销整条家族**（所有 refresh token + 所有 access token），返回 `invalid_grant`。

**这里踩到一个真实 bug**：最初把吊销放在事务里再 `throw`，SQLite 回滚把吊销写入也撤掉了，测试直接抓到（`replaying a used refresh token revokes the whole family` 失败）。现在安全相关的吊销在**独立已提交事务**里完成，抛错发生在提交之后。这条经验写进了 `TokenService.rotateRefreshToken` 的注释。

被重放的令牌会写入 `replay_markers`（只存摘要），并在 `/admin/tokens` 的 "Replay detections" 表格里可见。

### 令牌形态：不透明串 + 摘要存储

access token 和 refresh token 都是 256 位随机不透明串，数据库只存 SHA-256 摘要。这样：

- 内省/吊销可以即时生效（不需要等 JWT 过期）；
- 数据库泄露拿不到可直接重放的令牌；
- 不需要维护签名密钥轮换。

`token_type` 按请求返回：带 DPoP 绑定返回 `DPoP`，否则 `Bearer`。内省响应里 `cnf.jkt` 让资源服务器做绑定校验（RFC 9449 §6.2）。

### 回调地址校验

- 必须是绝对 URI、无 fragment、无 userinfo、无通配符 `*`。
- `https` 任意主机；`http` **仅限** loopback（`localhost` / `127.0.0.1` / `[::1]`）。
- 原生应用的私有 scheme（如 `com.example.app:/oauth/callback`）允许，但必须带 path 或 host。
- `javascript:` / `data:` / `file:` 等一律拒绝。
- 匹配时**严格字符串相等**；唯一例外是 RFC 9700 §4.1.2 允许的 loopback 端口可变。
- 客户端或回调地址不可信时**绝不重定向**，改为本地渲染错误页（RFC 6749 §4.1.2.1）。

### 其他协议细节

- `redirect_uri` 在 token 端点必填，且必须与授权请求中的完全一致。
- 授权码一次性使用；二次兑换按重放处理，吊销其产生的家族。
- token 端点、内省、吊销响应均带 `Cache-Control: no-store`。
- 内省不会泄露其他客户端的令牌：一律 `active: false`；吊销其他客户端的令牌是 no-op 并返回 200（RFC 7009 §2.2）。
- 客户端认证支持 `client_secret_basic` 与 `client_secret_post`，按注册值强制匹配；`none` 客户端若提交 secret 则拒绝。未知 `client_id` 也会跑一次等价的 scrypt，避免时序枚举。
- 错误码遵循 RFC 6749 §5.2 / RFC 9449 §8：`invalid_request`、`invalid_client`、`invalid_grant`、`invalid_scope`、`unsupported_grant_type`、`unauthorized_client`、`invalid_dpop_proof`。

## 测试覆盖

```
tests/
  authorization-code.test.ts   授权码兑换、并发/重复兑换
  pkce.test.ts                 缺 challenge、plain、错误 verifier、失败后作废
  dpop.test.ts                 jti 重放、iat 前后偏差、htu/htm/typ/alg/私钥/签名/多 header
  refresh-rotation.test.ts     轮换、家族吊销、access token 连带失效、密钥绑定、scope 收窄
  introspection-revocation.test.ts  内省字段、过期、跨客户端隔离、吊销级联
  registration.test.ts         回调地址各类非法输入、loopback 端口、CSRF、state
  resource.test.ts             ath 校验、错误密钥、吊销、proof 重放
  admin.test.ts                管理页、登录、权限、发现文档
  units.test.ts                事务回滚、单赢家消费、htu 归一化、RFC 7636 测试向量
```

```
ℹ tests 125
ℹ pass 125
ℹ fail 0
```

## 结构

```
src/
  server.ts            进程入口、启动引导、定时清理、优雅退出
  app.ts               Express 装配、安全头、统一错误处理
  config.ts            环境变量与默认值
  types.ts             数据模型
  db/schema.ts         SQLite schema
  db/store.ts          全部持久化操作（事务、原子消费、家族吊销）
  oauth/pkce.ts        RFC 7636
  oauth/dpop.ts        RFC 9449 proof 校验与 htu 归一化
  oauth/tokens.ts      签发、轮换、重放检测、家族吊销
  oauth/registration.ts  客户端元数据与回调地址校验
  oauth/clientAuth.ts  客户端认证
  oauth/clients.ts     引导数据、注册落库、会话/口令
  http/*.ts            各端点与页面
tests/
  helpers/             测试服务器、浏览器会话、DPoP 造 proof
```

## 已知边界

- 单进程 SQLite。多副本部署需换成共享存储，否则 `jti` 与家族状态不共享。
- 无 PAR、无 nonce（`use_dpop_nonce`）、无 mTLS、无 OIDC 的 `id_token`——按需求范围外处理。
- 授权页是演示级 HTML，未做 i18n 与品牌化。
- 登录失败次数限制、账户锁定未实现；生产接入应放在反向代理或 WAF 层。
