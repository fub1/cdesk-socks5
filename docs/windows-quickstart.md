# cDesk SOCKS5 Windows x64

基于 things-go/go-socks5 v0.1.3（c47d209a1459e1c86f200ba174eca9cb0bd5a14e）的最小服务。
使用原有 MIT 许可证。生产程序只使用 Go 标准库和本仓库代码，无 CGo。

## RustDesk 服务端兼容前提

0.2.0 起可在目标项设置 `"oss_hbbs_port": 21116`，启用 [OSS 协议适配](rustdesk-oss-bridge.md)。
使用 `config.oss.example.json` 或在现有配置对应的 targets 项中增加该字段，原 SOCKS5 地址、账号密码、公钥及服务器设置不变。
此模式使用 1.5.0 的旧服务端兼容路径，不建立额外的客户端到网关信令加密；远控数据仍由原有端到端流程处理。
网关需要能访问服务端 UDP 21116。未设置该字段的目标继续透明 TCP 转发。

原 0.1.2 程序只提供透明 TCP 隧道。官方客户端启用内置 SOCKS5 后会走 TCP 注册；
官方开源版 hbbs 的 TCP `RegisterPk` 分支返回 `NOT_SUPPORT`，不能使用此组合完成上线。
官方在 [SOCKS5 问题 #13010](https://github.com/rustdesk/rustdesk/issues/13010) 中确认该能力仅支持 Pro 服务端。
定制服务端需要自行确认已经实现相应 TCP 注册和握手能力；仅添加 API 不能证明兼容。

客户端流程可核对官方 [1.4.3 rendezvous_mediator.rs](https://github.com/rustdesk/rustdesk/blob/1.4.3/src/rendezvous_mediator.rs)：
`start` 在代理模式选择 `start_tcp`，随后 `secure_tcp` 等待服务端首次握手，之后才发送注册。
官方 OSS 的处理见 [rendezvous_server.rs](https://github.com/rustdesk/rustdesk-server/blob/master/src/rendezvous_server.rs) 中的 `handle_tcp`。

因此，TCP 端口可达或日志出现 `connected` 均不能作为 RustDesk 已上线的证据。
0.2.0 的适配在网关中转换注册和通知，不需要修改 OSS 服务端。
仅在 SOCKS5 服务中增加 UDP ASSOCIATE，不能改变上述客户端已选择 TCP 的行为。

## 启动

1. 将 `config.example.json` 复制为 EXE 所在目录中的 `config.json`。
2. `listen` 改为中转设备的内网 IP 和监听端口。
3. 设置 `auth.username` 和 `auth.password`；示例占位密码会导致启动失败。
4. `allow_sources` 填写允许的内网 PC 地址段；单机使用 `/32`（IPv6 `/128`）。
5. 保留或修改 `targets`，每项包含允许的主机、端口及可选的固定 `ips`。
6. 校验后启动：

```powershell
.\cdesk-socks5-windows-amd64.exe -check
.\cdesk-socks5-windows-amd64.exe
```

无参数时固定读取 EXE 同目录的 `config.json`，不依赖当前工作目录。
`-config` 可覆盖默认路径；显式传入的相对路径仍相对于工作目录。
配置缺失或无效时报告错误并退出，不会自动创建配置或回退到其他目录。
以 Ctrl+C 停止，服务会关闭监听和当前连接。
Windows 防火墙需允许指定内网来源访问监听 TCP 端口。仅在实际部署时配置此规则。

## 使用 NSSM 运行 Windows 服务

将程序和已配置的 `config.json` 放在例如 `C:\cDeskProxy`。
NSSM Application 页：Path 指向 EXE，Startup directory 可设为 `C:\cDeskProxy`，Arguments 留空。
默认配置路径始终相对于 EXE，即使 NSSM 使用其他工作目录也不受影响。

在管理员终端中运行以下命令（按实际安装目录替换）：

```powershell
nssm install cDeskSocks5 "C:\cDeskProxy\cdesk-socks5-windows-amd64.exe"
nssm set cDeskSocks5 AppDirectory "C:\cDeskProxy"
nssm reset cDeskSocks5 AppParameters
nssm set cDeskSocks5 Start SERVICE_AUTO_START
nssm set cDeskSocks5 AppStderr "C:\cDeskProxy\service.log"
nssm start cDeskSocks5
```

停止或重启使用 `nssm stop cDeskSocks5`、`nssm restart cDeskSocks5`。
保留 NSSM 默认控制台停止方式，程序响应 Ctrl+C 并清理连接。
NSSM 管理服务生命周期，程序保持前台运行；NSSM 本体需保留在安装服务时的路径。
官方说明：https://nssm.cc/usage 和 https://nssm.cc/commands 。

## 目标限制和 DNS

默认转发目标：`rustdesk.viget.net` 的 TCP 21116（hbbs）、21117（hbbr）、443（HTTPS API）。
不解析 RustDesk 消息，不终止 API TLS，原有远控密码和授权继续生效。

未指定 `ips` 时，启动期间使用中转设备的 DNS 解析目标，得到本次运行固定的允许 IP 集合。
域名请求只接受精确域名匹配（忽略大小写及末尾点）；IP 请求只接受上述 IP 与对应端口。
不支持域名通配符，不允许其他目标端口。域名变化后重启服务以刷新地址。

如需固定地址，在目标项中添加 `"ips": ["实际服务器IP"]`，此时该项不执行 DNS 查询。
域名请求也只拨这些 IP，不进行第二次解析。多 IP 目标按配置/解析顺序尝试，拨号总时间受限。
`ips` 可包含 IPv4 和 IPv6；测试用的 203.0.113.0/24 地址不可当作真实服务器。

RustDesk 1.5.0 的 HTTP API SOCKS5 客户端会在 PC 本地解析目标域名。
内网 PC 必须通过可用 DNS 或 hosts 解析 API 域名，且结果属于代理允许的 IP 集合。
只在中转设备解析成功不能解决 PC 本地 DNS 失败。分离 DNS 环境需在目标 `ips` 中列明实际获准地址。

## 客户端设置

RustDesk 的网络/代理设置：

```text
代理：socks5://中转设备内网IP:1080
用户名：与 auth.username 一致
密码：与 auth.password 一致
```

在服务端满足上述兼容前提时，保持 ID 服务器、Relay 服务器、API 地址及公钥为原来的配置。确认安装版服务进程也取得代理设置。
不启用 WebSocket 叠加代理。SOCKS5 用户名密码在客户端到中转设备之间明文传输，部署在可信内网。

## 资源和日志

默认最多 16 条同时打开的 TCP 连接（包括注册连接，不是 16 台 PC 或 16 个远控会话）。
每方向提供 16 KiB 转发缓冲池，另有 Go 运行时、协议及系统 socket 开销。
`max_connections`、`buffer_bytes` 可按现场负载调整。
`handshake_timeout` 只限制认证和请求头读取，成功读取后清除，不限制远控会话总时长。
`dns_timeout` 限制每个配置目标的启动解析，`dial_timeout` 限制一次请求的总拨号时间。
`tcp_keepalive` 用于两侧 TCP 保活，不等于业务心跳或空闲断开。

程序同时输出到控制台 stderr 和 EXE 同目录的 `cdesk-socks5.log`，日志时间为 UTC。
日志文件追加写入；目录不可写时会明确提示并继续输出到 stderr。
`log_level=warn` 仍记录认证失败、来源/目标拒绝、连接数限制、握手/转发错误和拨号失败。
样例使用 `info`，额外记录连接到达、请求目标、实际拨号 IP、连接成功及关闭。
启动时输出配置文件路径、允许来源、目标解析 IP 和端口，便于检查实际加载配置和 DNS 差异。
不会记录用户名密码或转发内容。长期使用 `info` 时需由运维管理日志文件大小。
配置启动时读取，不提供 Web 管理、数据库、动态更新或 UDP/BIND 转发。

### 排查无法连接

1. 将 `log_level` 设置为 `info`，重启代理，再保存/重启 RustDesk 的代理设置。
2. 客户端先测试 `Test-NetConnection 中转设备内网IP -Port 1080`。
3. 日志出现 `accepted` 才证明客户端连接到达；没有该记录时，先查客户端到代理的网络、防火墙及客户端代理是否生效。
4. `authentication_failed` 表示认证失败；`authentication_method_rejected` 通常表示客户端没有提供用户名密码认证。
5. `source_denied` 或 `connection_limit` 表示连接在握手前被拒绝。
6. `target_denied` 会列出实际请求的目标，核对是否仍指向旧服务器、是否多请求了未放行端口。
7. `dial_failed` 会列出中转设备尝试连接的 IP/端口和系统错误；在中转设备测试该目标 TCP 端口。
8. `connected` 只证明 TCP 隧道建立；RustDesk 公钥、服务器配置、远控授权等仍由客户端与服务端处理。
9. `info` 还记录两个方向首次收到/转发数据的时间，以及关闭时的 `transfer_summary`。
   `bytes_to_upstream` 是向服务器实际写入的业务字节，`bytes_from_upstream` 是从服务器读取的业务字节，不含 SOCKS5 认证和连接响应。
   `upstream_read_end` 表示从服务器读取结束；`client_to_upstream_copy_end` 表示客户端方向的复制循环结束，可能因 EOF 或读取错误，须结合相邻错误日志判断。
   计数不代表客户端已解析或接受数据；异常强制关闭时摘要是关闭当时的计数。
10. 如果 21116 反复在约 18 秒结束，且两方向计数都是 0，优先核对客户端版本及服务端是否支持 TCP 注册握手。
    官方客户端的 `secure_tcp` 存在等待服务端首帧的流程，读取超时为 18 秒；这是符合该日志的原因之一，不能仅凭计数认定部署端的最终故障位置。
    官方 OSS 不发送该握手且不支持 TCP 注册；若实际为 Pro/其他实现，则需进一步比对中转机直连结果和客户端握手错误。

## 编译与验证

```powershell
go test ./...
go vet ./...
.\scripts\build-windows.ps1
```

产物在 `dist/`；脚本使用 `CGO_ENABLED=0 GOOS=windows GOARCH=amd64 GOAMD64=v1`，
并生成 SHA256SUMS.txt。版本包含 Git 提交号；工作区有未提交改动时带 dirty。
真实部署需在 PC 无法直连外网服务器时验证：hbbs 上线、hbbr 远控、API 请求及断线重连。
自动测试使用本地 TCP 和 HTTPS 目标，不能代替真实双端 RustDesk 验收。
