# rust-http-server

一个用 Rust + [axum](https://github.com/tokio-rs/axum) 写的 HTTP 服务，带**账号注册 / 登录 /
会话**和 SQLite 存储，带 Dockerfile 和 docker-compose 配置，多阶段构建、优雅退出、健康检查。

> **关于 better-sqlite3**：Rust 生态里没有叫 `better-sqlite3` 的 crate——那是 Node.js 的包名。
> 对应的 Rust crate 是 [`rusqlite`](https://docs.rs/rusqlite)，它的 API 本来就是照着
> better-sqlite3 设计的（同步、零抽象、`Connection` 上直接 `execute`/`query`），文档里也直接
> 拿自己跟 better-sqlite3 对比。所以这里用的是 `rusqlite` + `bundled` feature：SQLite 的 C 源码
> 在构建期编进二进制，运行时不需要系统装 `libsqlite3`。

## 快速开始

```bash
docker compose up --build -d      # 构建并在后台启动，映射到宿主机 8080
```

然后在浏览器打开 **<http://localhost:8080>** —— 那是内置的测试台。页面上方有账号面板，
点「运行全部」即可把下面所有接口按顺序跑一遍（先验证未登录被拒，再注册、登录，之后受保护的
接口才可用，最后退出登录），页头会汇总通过/失败数。

```bash
curl http://localhost:8080/health
```

看日志 / 停止：

```bash
docker compose logs -f
docker compose down
```

不想用 compose 的话：

```bash
docker build --build-arg CARGO_BUILD_JOBS=4 -t rust-http-server:local .
docker run --rm -p 8080:3000 -v http-server-data:/data rust-http-server:local
```

`-v ...:/data` 是必须的：数据库文件写在 `/data/app.db`，不挂卷的话容器一换数据就没了。

## 认证

### 接口

| 方法 | 路径                 | 说明                                              |
| ---- | -------------------- | ------------------------------------------------- |
| POST | `/api/auth/register` | 注册，无需登录。已存在返回 409                    |
| POST | `/api/auth/login`    | 登录，成功返回 `Set-Cookie: session=…`（200）      |
| POST | `/api/auth/logout`   | 注销，服务端删掉这条会话（204），重复调用也是 204  |
| GET  | `/api/auth/me`       | 用 Cookie 换当前账号（200），没有会话返回 401     |

`/api/items` 整组都需要登录：没有有效会话一律 401。

### 走一遍

```bash
# 注册（用户名 3–32 字符，密码至少 8 个字符）
curl -i -X POST http://localhost:8080/api/auth/register \
  -H 'content-type: application/json' \
  -d '{"username":"alice","password":"correct-horse"}'

# 登录，把 Cookie 存进 jar
curl -s -c jar.txt -X POST http://localhost:8080/api/auth/login \
  -H 'content-type: application/json' \
  -d '{"username":"alice","password":"correct-horse"}'

# 带上 Cookie 才能访问
curl -s -b jar.txt http://localhost:8080/api/auth/me
curl -s -b jar.txt http://localhost:8080/api/items

# 注销
curl -i -X POST -b jar.txt http://localhost:8080/api/auth/logout
```

### 会话是怎么做的

服务端会话，不是 JWT：登录时用操作系统 CSPRNG 生成 32 字节随机数当令牌，放进
`HttpOnly; SameSite=Lax` 的 Cookie，**数据库里只存它的 SHA-256**。所以拿到数据库文件的人
没法反推出可用的 Cookie 令牌；令牌本身只在登录响应里出现一次。

- 有效期 `SESSION_TTL_SECS`（默认 24 小时），过期行在查会话时被顺手删掉，启动时也会清一遍；
- 所有响应带 `Cache-Control: no-store`，登录响应尤其不能被缓存；
- 删除用户会级联删掉他的会话（`ON DELETE CASCADE`）；
- 密码用 **Argon2id** 哈希存储，库里看不到明文。

### 登录失败节流

同一个用户名 60 秒内失败 5 次就锁 60 秒，返回 429 并带上剩余秒数。按用户名而不是按 IP：
服务端没有可信的客户端 IP（不采信 `X-Forwarded-For`），按 IP 限流反而容易误伤 NAT 后面的人。
计数只存在内存里，重启即清零——够挡住在线爆破，但重启能被用来重置，这点是有意为之。

**用户名不存在时会照样算一次 Argon2**（拿一个固定的诱饵密码），否则"用户不存在"比"密码不对"
快得多，攻击者能用响应时间枚举出哪些用户名注册过。两种情况的响应体也完全一样。

## 接口

| 方法   | 路径                      | 说明                                       |
| ------ | ------------------------- | ------------------------------------------ |
| POST   | `/api/auth/register`      | 注册新账号（无需登录）                     |
| POST   | `/api/auth/login`         | 登录，返回 session Cookie（无需登录）       |
| POST   | `/api/auth/logout`        | 注销，仅当前令牌失效                       |
| GET    | `/api/auth/me`            | 当前用户（需登录）                         |
| GET    | `/`                       | 测试台页面                                 |
| GET    | `/api/routes`             | 接口清单（JSON）                           |
| GET    | `/health`                 | 健康检查，被 Docker HEALTHCHECK 使用       |
| GET    | `/api/hello/{name}`       | 问候语，`?loud=true` 时转大写（无需登录）   |
| POST   | `/api/echo`               | 原样回显 JSON 请求体（无需登录）           |
| GET    | `/api/items`              | 列出全部条目（需登录）                     |
| POST   | `/api/items`              | 新建条目，返回 201（需登录）               |
| GET    | `/api/items/{id}`         | 按 id 查询，不存在返回 404（需登录）       |
| DELETE | `/api/items/{id}`         | 删除条目，成功返回 204，不存在 404（需登录） |
| GET    | `/api/slow?ms=2000`       | 睡眠指定毫秒，用于观察超时行为（无需登录） |

出错时统一返回 `{"error": "中文说明"}`。SQLite 层的错误只写进日志，返回给客户端的是笼统的
"服务器内部错误"，不会把表结构或文件路径漏出去。

## 配置

全部通过环境变量设置，镜像本身不带任何硬编码：

| 变量               | 默认值                  | 说明                                        |
| ------------------ | ----------------------- | ------------------------------------------- |
| `HOST`             | `0.0.0.0`               | 监听地址，非法值会退回 `0.0.0.0`            |
| `PORT`             | `3000`                  | 监听端口                                    |
| `RUST_LOG`         | `info,tower_http=info`  | `tracing` 日志过滤级别                      |
| `DATABASE_PATH`    | `data/app.db`           | SQLite 文件路径，父目录会自动创建          |
| `SESSION_TTL_SECS` | `86400`                 | 会话有效期（秒）                            |
| `COOKIE_SECURE`    | `false`                 | 给 Cookie 加 `Secure`。走 https 时设 `true` |

> 容器里 `DATABASE_PATH` 的默认值是 `/data/app.db`（镜像里设的），本地 `cargo run` 不带这个
> 变量时是 `data/app.db`。

## 测试台页面

`GET /` 返回 `static/index.html`，通过 `include_str!` 在编译期嵌进二进制，所以页面本身不需要
挂载任何卷。页面做的事：

- 左上是账号面板，可以直接注册 / 登录 / 退出，右上角是会话状态徽标和当前账号；
- 把每个接口作为一个用例列出来，标注期望的状态码，右侧实时显示实际状态码、耗时、响应大小
  和响应体，页头汇总「通过 / 失败」；
- 「运行全部」按顺序执行，用例之间是有状态的；
- 按 id 查询和删除的用例**不写死 id**：列表用例会记住一个真实存在的 id，删除用例会删掉
  本轮刚新建的那一条，所以整套用例可以反复运行而不会越跑越少数据；
- 顶部的地址框可以改，所以页面也能拿来测远端部署；
- 每个用例旁边都有「运行」按钮，可单独执行；响应面板里的「复制为 curl」把最近一次请求导出
  成可以在终端里复现的命令。

页面只有原生 HTML/CSS/JS，没有外部依赖，离线可用。`fetch` 用的是
`credentials: "same-origin"`，所以页面由服务器自己提供时 Cookie 会被正常带上。

## 本地开发（不经 Docker）

```bash
cargo run                      # http://localhost:3000，数据库在 data/app.db
cargo test                     # 49 个测试
cargo clippy --all-targets
RUST_LOG=debug cargo run       # 打开详细日志
```

测试覆盖路由与状态码、错误处理、超时层、页面、优雅退出，以及认证这一层：Cookie 属性、
令牌随机性、Argon2id 落库、错误响应不可区分用户名/密码、大小写不敏感的用户名、伪造/过期/
重放的 Cookie、节流与锁定、SQLite 的读写与迁移。

## 实现要点

- **SQLite + 异步运行时**：rusqlite 是同步的，Argon2 更是故意慢的。所有数据库访问和哈希都
  通过 `tokio::task::spawn_blocking` 出去，绝不在 worker 线程上直接调用——否则几个并发登录
  就能把整个服务卡死。登录的"查库 + 校验 + 建会话"合并成**一次**阻塞跳转，锁的持有时间才够短。
- **连接与迁移**：`Arc<Mutex<Connection>>` 加 `spawn_blocking`，不用连接池——单机单文件 SQLite
  的瓶颈本来就在写锁上，多开连接只会让 `SQLITE_BUSY` 更频繁。启动时按 `PRAGMA user_version`
  顺序执行版本化迁移，整个迁移在一个 `BEGIN IMMEDIATE` 里。开了 WAL、`foreign_keys=ON`、
  `busy_timeout=5000`。
- **分层依赖缓存**：Dockerfile 先只拷贝 `Cargo.toml` / `Cargo.lock` 构建依赖，再拷贝
  `src/`。改业务代码只会重编本 crate，不会重编那 60 个依赖。
- **优雅退出**：`docker stop` 发的是 SIGTERM。服务收到后停止接受新连接、等在途请求做完，
  最多再等 `SHUTDOWN_GRACE`（10 秒）。compose 里的 `stop_grace_period: 15s` 要比它长，
  否则 Docker 会在请求还在收尾时就 SIGKILL 掉进程。

  注意这个 10 秒的截止时间是**收到信号之后**才开始算的。如果像常见写法那样把整个
  `serve` future 塞进 `tokio::time::timeout`，那 10 秒会从**进程启动**就开始算——服务
  会在健康的情况下每 10 秒自杀一次，容器则陷入重启循环。`src/main.rs` 里的
  `server_keeps_serving_past_the_grace_period` 就是专门盯着这个的回归测试。

- **请求超时**：所有路由套了 30 秒的 `TimeoutLayer`，超限返回 408。`/api/slow?ms=60000`
  就是用来观察这个的。
- **CORS**：`CorsLayer` 放开了来源。测试台页面和服务同源，所以用不到带凭据的 CORS；而
  `Access-Control-Allow-Headers: *` 和 `Access-Control-Allow-Credentials: true` 不能同时开
  （tower-http 会直接 panic），要支持跨域带 Cookie 就必须改成显式的 `allow_origin` 列表。
- **非 root 运行**：运行时镜像用 uid 10001 的普通用户，`/data` 在镜像里就建好并交给它。

数据存在 SQLite 文件里（默认 `data/app.db`，容器里 `/data/app.db`），compose 挂了具名卷
`http-server-data`，所以 `docker compose down` 再起来数据还在。

## 内存吃紧的机器上构建

Docker Desktop 给虚拟机的内存通常只有宿主机的一半左右（本机 8 GB → VM 约 3.9 GB）。
Rust 的 release 构建比较吃内存，`cargo` 默认按 CPU 数量并行（本机 8 核）时可能把
虚拟机撑爆，表现就是 Docker 守护进程无响应、`docker build` 一直挂着不出错。

遇到这种情况把并行度限制下来：

```bash
docker build --build-arg CARGO_BUILD_JOBS=4 -t rust-http-server:local .
```

或者在 Docker Desktop → Settings → Resources 里给 VM 多分点内存。正常情况下
（不限并行度也没 OOM）直接 `docker compose up --build` 就行。

运行时镜像不含工具链，只有约 28 MB；但构建阶段现在要装 `build-base`（gcc + make +
musl-dev）——`rusqlite` 的 `bundled` feature 要在构建期编译 SQLite 的 C 源码，光有
`musl-dev` 是不够的。这套东西只在构建阶段，不会进最终镜像。