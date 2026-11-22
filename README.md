# rust-proxy-node

Rust 代理节点：同一端口同时支持 **SOCKS5（RFC 1928）** 和 **HTTP CONNECT（RFC 7231）**，零外部依赖（只用标准库），单文件实现在 `src/main.rs`。

## 功能

| 协议 | 支持情况 |
|---|---|
| SOCKS5 握手 | 方法 0x00 无认证、0x02 用户名密码（RFC 1929） |
| SOCKS5 CONNECT (CMD 0x01) | IPv4 / 域名 / IPv6，目标域名由节点端解析 |
| SOCKS5 UDP ASSOCIATE (CMD 0x03) | 绑定本地 UDP 中继端口，按 RFC 1928 UDP 头转发，TCP 控制连接断开即停止 |
| SOCKS5 BIND (CMD 0x02) | 不支持，返回 REP 0x07 |
| HTTP CONNECT | `CONNECT host:port HTTP/1.1`，成功回 `200 Connection Established`，失败回 502；认证失败回 407 |
| HTTP 认证 | `Proxy-Authorization: Basic base64(user:pass)` |
| 认证 | 未配置用户名密码时免认证；配置后 SOCKS5 与 HTTP 都强制校验 |

## 环境要求

- Rust 工具链：本项目用 rustup 安装，实测版本
  - `cargo 1.100.0 (3acc79c0c 2026-11-05)`
  - `rustc 1.100.0 (0ef1bc386 2026-11-09)`
- 构建不需要联网下载依赖（`Cargo.toml` 里没有任何依赖）。

## 构建

```bash
# 首次安装 Rust（若已安装可跳过）
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"

cd ~/workspace/rust-proxy-node
cargo test            # 8 个单元测试
cargo build --release # 产物：target/release/rust-proxy-node
```

实测：`cargo test` 8 passed / 0 failed；`cargo build --release` 通过，无警告。

## 运行

```bash
# 默认：监听 127.0.0.1:1080，无认证
./target/release/rust-proxy-node

# 指定端口和认证
./target/release/rust-proxy-node --addr 127.0.0.1:1080 --user alice --pass secret

# 等价的环境变量写法（命令行优先）
PROXY_ADDR=127.0.0.1:1080 PROXY_USER=alice PROXY_PASS=secret ./target/release/rust-proxy-node
PROXY_PORT=1080 ./target/release/rust-proxy-node
```

参数：`--addr <host:port>`、`--port <port>`、`--user <name>`、`--pass <password>`、`--help`。
`--user` 与 `--pass` 必须成对出现。默认只监听 `127.0.0.1`（本机），不要直接把无认证版本绑到公网；需要对外服务时请先配置认证并配合防火墙。

## 测试（本机实测，见 TEST_RESULTS.md）

先启动一个本地 HTTP 回显服务（用来验证转发，不依赖外网）：

```bash
mkdir -p /tmp/echo-root && printf 'HELLO-FROM-LOCAL-ECHO\n' > /tmp/echo-root/hello.txt
cd /tmp/echo-root && python3 -m http.server 18080 --bind 127.0.0.1
```

再启动节点（另一个终端）：

```bash
./target/release/rust-proxy-node --addr 127.0.0.1:1080
```

```bash
# SOCKS5 转发本地服务（注意：本机 no_proxy 含 127.0.0.1，curl 需加 --noproxy "" 强制走代理）
curl --noproxy "" -x socks5h://127.0.0.1:1080 http://127.0.0.1:18080/hello.txt
# 预期：HELLO-FROM-LOCAL-ECHO

# HTTP CONNECT 转发本地服务（用 Python 发 CONNECT 再发 GET，或用 https 目标）
curl --noproxy "" -I -x http://127.0.0.1:1080 https://example.com
# 在有直连外网的机器上预期：HTTP/1.1 200 Connection Established + 200 OK
# 在本沙箱里：代理能建立 TCP 连接（日志显示 CONNECT ok），但随后 TLS 握手失败（curl exit 35），
# 因为沙箱出口会拦截直连 TCP，只允许走沙箱自己的 egress 代理。见 TEST_RESULTS.md。

# 带认证的节点（端口 1081，alice / secret）
./target/release/rust-proxy-node --addr 127.0.0.1:1081 --user alice --pass secret
curl --noproxy "" -x socks5h://alice:secret@127.0.0.1:1081 http://127.0.0.1:18080/hello.txt  # 成功
curl --noproxy "" -x socks5h://127.0.0.1:1081 http://127.0.0.1:18080/hello.txt               # 失败 exit 97
curl --noproxy "" -x socks5h://wrong:wrong@127.0.0.1:1081 http://127.0.0.1:18080/hello.txt   # 失败 exit 97
curl -i --noproxy "" -x http://alice:wrong@127.0.0.1:1081 https://example.com               # 407
```

## 与 CulvertProxy 客户端对接

**重要前提（实测限制）：CulvertProxy 是 Windows 11 WinUI3 客户端，需要 Windows 11 24H2（build 26100）或更高、x64 才能运行。本机是 Ubuntu 24.04 Linux，无法直接运行 CulvertProxy 来实测，因此没有“在 CulvertProxy 里点一下、流量真的走了”这一步的实测结果。下面保证的是协议兼容，CulvertProxy 按标准 SOCKS5 / HTTP CONNECT 与本节点对接。**

CulvertProxy 仓库：https://github.com/Tinmc189623/CulvertProxy
（Windows 11 进程级代理客户端，.NET 11 / WinUI3，SOCKS5 / HTTP、多跳链路、DoH、fake-IP）

在 Windows 机器上的对接步骤：

1. 把本项目拿到 Windows 机器（或有公网 IP 的服务器）上构建 / 部署：
   - Windows 上同样用 rustup 安装 Rust，`cargo build --release`，得到 `rust-proxy-node.exe`；
   - 或者在 Linux 上交叉编译 / 直接把 Linux 二进制部署到 Linux 服务器上，CulvertProxy 从 Windows 连过去。
   - 启动示例（服务器上监听对外地址时请务必配认证）：
     ```powershell
     .\rust-proxy-node.exe --addr 0.0.0.0:1080 --user alice --pass secret
     ```
     只在本机测试时用 `127.0.0.1:1080`。
2. 在 CulvertProxy 里添加上游（按其 README 的「使用流程」）：
   - 打开「代理服务器」，新增上游；
   - 协议选 **SOCKS5**（或 HTTP CONNECT，二者本节点都支持，同一端口）；
   - 地址填节点的 IP（本机测试填 `127.0.0.1`，远程填服务器 IP/域名），端口填 `1080`（或你启动时指定的端口）；
   - 若节点配了认证，填写用户名 / 密码；需要伪装时可再勾选 TLS 并填写 SNI（注意：本节点本身不做 TLS 包装，TLS 包装是 CulvertProxy 上游链路的可选项，指它与上游之间的 TLS，本节点收到的是明文 SOCKS5/HTTP，若要端到端 TLS 请在节点前再套一层 TLS 终止/隧道）；
   - 单服务器会自动生成默认策略；多服务器可以编排多跳链路。
3. 在「路由规则」里按进程 / 域名 / IP / 端口建规则（默认已把回环与内网设为直连），未命中走默认策略。
4. 启动代理：此时本地入口已可用。手动把 SOCKS5/HTTP 客户端指向 `127.0.0.1:1080` 即可；需要接管桌面应用时，去「设置 → 透明接管」开启并保存（需管理员身份，且只注入 x64 进程）。
5. 验证：在 CulvertProxy 的「连接」页应能看到目标连接，规则显示为对应进程 → 上游，并能正常访问；也可以先用 `curl -x socks5h://127.0.0.1:1080 https://example.com -I` 在 Windows 终端里验证节点本身。

协议对照（本节点实现）：

| CulvertProxy 上游能力 | 本节点 |
|---|---|
| SOCKS5 | 支持，RFC 1928，CONNECT + UDP ASSOCIATE，无认证 / 用户名密码 |
| HTTP CONNECT | 支持，RFC 7231，Basic 认证 |
| 多跳链、TLS 包装、独立 SNI、叶证书固定 | 由 CulvertProxy 客户端侧编排；本节点是链路末端的一个普通上游，不实现多跳/TLS |
| DoH / fake-IP / 本地 DNS | 由 CulvertProxy 客户端侧实现；本节点只做 TCP/UDP 转发与域名解析 |

## 已知限制

- 外部 HTTPS 转发在本沙箱里失败（curl exit 35，TLS 握手失败）：沙箱出口拦截直连 TCP，不是节点代码问题；在有直连外网的机器（VPS / Windows）上应可正常工作。本地转发已实测通过。
- UDP ASSOCIATE 的端到端转发在本沙箱里无法验证：沙箱禁止 UDP 发包（连直接 `sendto(127.0.0.1)` 都报 `Operation not permitted`），因此客户端发往中继端口的 UDP 包发不出去；但 SOCKS5 UDP ASSOCIATE 的 TCP 握手与中继端口分配已实测通过（REP 0，中继地址正常返回），转发逻辑在代码里已实现，未经端到端实测。
- 本节点只做代理转发，不实现 CulvertProxy 的进程注入、DoH、fake-IP、多跳、TLS 包装等客户端功能；那些由 CulvertProxy 客户端完成。
- 密码以明文参数/环境变量传入，仅用于本地测试；生产部署请用更安全的凭据管理方式。

## 文件清单

```
rust-proxy-node/
├── Cargo.toml            # 零依赖，edition 2021
├── README.md             # 本文件
├── TEST_RESULTS.md       # 实测结果日志（构建、单测、转发、认证、失败项）
├── src/
│   └── main.rs           # 全部实现 + 8 个单元测试（SOCKS5、HTTP CONNECT、UDP ASSOCIATE）
└── target/release/rust-proxy-node   # 构建产物（约 580 KB，构建后生成）
```
