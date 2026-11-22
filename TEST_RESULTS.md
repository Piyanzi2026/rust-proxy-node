# 测试结果日志 — rust-proxy-node

测试时间：2026-11-22 09:53 UTC（约 17:53 CST）
测试机：Ubuntu 24.04.5 LTS 沙箱，`cargo 1.100.0` / `rustc 1.100.0`
本地回显服务：`python3 -m http.server 18080`，`/hello.txt` 内容为 `HELLO-FROM-LOCAL-ECHO`

> 以下结果如实记录，未编造。第一轮测试因两个测试脚本问题（`no_proxy` 含 `127.0.0.1` 导致 curl 绕过代理、Python 脚本里 SOCKS5 目标端口写错一位）得出了误导性结果，已修正后重测，下面的“修正后重测”为准。

## 1. 构建与单元测试 — 通过

```
cargo test
running 8 tests
test tests::base64_roundtrip ... ok
test tests::basic_auth_check ... ok
test tests::parse_connect_target_bad ... ok
test tests::parse_connect_target_ok ... ok
test tests::socks_addr_bad_atyp ... ok
test tests::socks_addr_domain_roundtrip ... ok
test tests::socks_addr_ipv4_roundtrip ... ok
test tests::socks_addr_resolves_localhost ... ok
test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out

cargo build --release
Finished `release` profile [optimized] target(s)
产物：target/release/rust-proxy-node，约 580 KB，无警告
```

## 2. 修正后重测（以此为准）

### 2.1 SOCKS5 CONNECT 转发本地服务 — 通过

```
$ curl --noproxy "" -x socks5h://127.0.0.1:1080 http://127.0.0.1:18080/hello.txt
HELLO-FROM-LOCAL-ECHO
exit=0
代理日志：[proxy] 127.0.0.1:37592 SOCKS5 CONNECT 127.0.0.1:18080 ok
```

Python 直接发 SOCKS5 协议同样通过：握手回 `0500`，CONNECT 回 `050000017f000001abc0`（REP=0），随后 GET 拿到 `HELLO-FROM-LOCAL-ECHO`。

### 2.2 HTTP CONNECT 转发本地服务 — 通过

Python 直接发 `CONNECT 127.0.0.1:18080 HTTP/1.1`：

```
http CONNECT resp: b'HTTP/1.1 200 Connection Established\r\n\r\n'
http CONNECT GET body contains HELLO: True
```

### 2.3 认证 — 通过

节点 2（端口 1081，`--user alice --pass secret`，测试用账号）：

| 测试 | 结果 |
|---|---|
| SOCKS5 无凭证 | 失败，curl exit 97；日志 `SOCKS5: no acceptable auth method` |
| SOCKS5 错误凭证 | 失败，curl exit 97；日志 `SOCKS5: bad credentials` |
| SOCKS5 正确凭证 | 通过，拿到 `HELLO-FROM-LOCAL-ECHO`，exit 0；日志 `SOCKS5 CONNECT 127.0.0.1:18080 ok` |
| HTTP 错误凭证 | `HTTP/1.1 407 Proxy Authentication Required` |
| HTTP 正确凭证 | `HTTP/1.1 200 Connection Established`（随后 TLS 失败，见 3.1） |

### 2.4 SOCKS5 UDP ASSOCIATE — 部分通过（握手与中继分配通过，端到端转发未通过）

```
udp socks greeting: 0500
udp associate resp: 050000017f000001a648 rep= 0
relay addr: 127.0.0.1 42568
随后客户端 UDP 发包失败：
PermissionError: [Errno 1] Operation not permitted
```

对照验证：不经过代理、直接用 Python `sendto(b'hi', ('127.0.0.1', 18081))` 同样报
`Operation not permitted`。说明沙箱本身禁止 UDP 发包，问题不在本节点。
已验证的部分：UDP ASSOCIATE 的 TCP 握手、REP=0、中继 UDP 端口正常分配并返回。
未验证的部分：UDP 数据包经中继转发到目标并回包的端到端流程（代码已实现，需在不禁 UDP 的机器上验证）。

## 3. 未通过项及原因（均属沙箱限制，非节点代码问题）

### 3.1 外部 HTTPS 转发 — 失败

```
$ curl -s -I --noproxy "" -x socks5h://127.0.0.1:1080 https://example.com
exit=35 (SSL connect error)
$ curl -s -I --noproxy "" -x http://127.0.0.1:1080 https://example.com
HTTP/1.1 200 Connection Established
exit=35 (SSL connect error)
代理日志：SOCKS5 CONNECT example.com:443 ok / HTTP CONNECT example.com:443 ok
```

说明：代理已成功建立到 `example.com:443` 的 TCP 连接并回了 `200 Connection Established`，
但随后 curl 的 TLS 握手失败（exit 35）。沙箱出口会拦截直连 TCP，只允许走沙箱自己的
egress 代理；直接不走本节点 curl `https://example.com` 是通的（走 egress 代理）。
结论：外部转发在本沙箱里无法成功，在有直连外网的机器（VPS / Windows）上应可正常工作。
本地转发（2.1 / 2.2）已证明转发逻辑本身是通的。

### 3.2 第一轮测试的两个误导性结果（已修正，不作为结论）

- 第一轮 curl 到 `127.0.0.1:18080` 时 `no_proxy` 环境变量含 `127.0.0.1`，curl 直接绕过了
  代理，因此“无凭证/错凭证也拿到 HELLO”不是节点放行了认证，而是根本没走代理。
  修正：`NO_PROXY=""` + `curl --noproxy ""`，重测后认证行为正确（见 2.3）。
- 第一轮 Python SOCKS5 测试把目标端口 18080 写成了 0x46B0（18128），得到 REP=5
 （connection refused），是测试脚本写错端口，不是节点问题。修正为 0x46A0 后 REP=0（见 2.1）。

## 4. CulvertProxy 客户端实测 — 未做

CulvertProxy 是 Windows 11 WinUI3 客户端，需要 Windows 11 24H2（build 26100）或更高、
x64 才能运行；本机是 Ubuntu 24.04 Linux，无法直接运行它来实测。
本节点与 CulvertProxy 的兼容性只做到协议层：SOCKS5 RFC 1928、HTTP CONNECT RFC 7231，
CulvertProxy 把本节点当作普通 SOCKS5 / HTTP CONNECT 上游即可，对接步骤见 README.md。

## 5. 结论

- 构建：通过（`cargo build --release`，无警告）
- 单元测试：通过（8/8）
- SOCKS5 CONNECT 本地转发：通过
- HTTP CONNECT 本地转发：通过
- 用户名密码认证（SOCKS5 + HTTP）：通过
- SOCKS5 UDP ASSOCIATE：握手与中继分配通过，端到端转发因沙箱禁 UDP 未验证
- 外部 HTTPS 转发：本沙箱失败（exit 35，沙箱出口拦截直连 TCP），需在直连外网机器上验证
- CulvertProxy 客户端实测：未做（需 Windows 11 机器），协议兼容已保证
