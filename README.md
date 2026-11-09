# anytls-zig

`anytls-zig` 是面向 fancyss full 版本的 AnyTLS 客户端实验实现。

当前目标：

- 提供本地 SOCKS5 入站；
- 连接远端 AnyTLS 服务端；
- 支持 `anytls://password@host:port/?sni=name&insecure=1` URI；
- 用 Zig 0.15.2 生成小体积多平台二进制。

当前限制：

- 仅支持 TCP 代理，不支持 UDP/UoT；
- 每个 SOCKS5 连接独立建立 AnyTLS session，尚未实现官方要求的 session 复用；
- 默认 `--insecure` 关闭 CA 校验以兼容现有订阅节点；受 Zig TLS API 限制，带 SNI 时仍可能触发主机名校验，遇到证书主机名不匹配会自动退回不发送 SNI 重连；可用 `--verify` 启用系统 CA 校验和严格主机名校验；
- 会解析但暂不应用服务端下发的 padding scheme 更新。

常用命令：

```sh
anytls-zig --server-uri-file /tmp/anytls.uri -l 127.0.0.1:18081
curl -x socks5h://127.0.0.1:18081 http://www.google.com/generate_204
```

SOCKS negotiation has a shared 10-second deadline once a connection worker
starts processing it. Incomplete greetings and CONNECT requests are closed
even if the client periodically sends another byte. This deadline does not
apply to established relays, DNS resolution, or the upstream TCP/TLS handshake.
The existing 32-worker connection limit is unchanged.

## Regression tests

Build with Zig 0.15.2, then run the loopback-only Python 3 tests. OpenSSL is
used to generate a temporary certificate for the local TLS echo peer. The
relay test requires a Python SSL module with TLS 1.3 support; otherwise that
test is reported as skipped.

```sh
zig build -Doptimize=ReleaseSafe
python3 -m unittest discover -s tests -v
```

Set `ANYTLS_BIN` to test another native executable. No subscription, real
credentials, or external network is required. The relay test uses a local
TLS peer, while incomplete-handshake tests use an unused loopback upstream port.
