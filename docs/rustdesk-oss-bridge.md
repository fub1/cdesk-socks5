# RustDesk OSS 协议适配（当前实施方向）

用户已明确：客户端仍使用原 SOCKS5 接口，OSS 服务端不改；由中转组件适配两侧协议。
这取代 `oss-lan-forwarding-proposal.md` 中建议关闭客户端代理的方向。
0.2.0 提供最小实验适配实现，当前针对用户确认的官方客户端 1.5.0。

## 数据流与边界

```text
官方客户端
    │ SOCKS5 CONNECT、账号密码认证
    ▼
中转设备（既有来源白名单、目标白名单和并发限制）
    ├─ hbbs 21116：RustDesk TCP 信令 ↔ OSS UDP 注册/通知 + OSS TCP 临时信令
    ├─ hbbr 21117：既有 TCP 透明转发
    └─ API 指定端口：既有 TCP 透明转发，HTTPS 证书校验保留
```

SOCKS5 只是入口协议，不约束出口必须使用相同的传输协议。
此前的兼容问题结论适用于透明代理，不能据此排除带 RustDesk 协议适配的中转组件。
适配限定在显式配置的 hbbs 目标；不能根据任意请求自行选择额外 UDP 目标。

## hbbs 适配

1. 在 SOCKS5 认证和来源/目标检查之后，处理指定 hbbs CONNECT 请求。
2. 使用 1.5.0 的旧服务端首帧兼容路径，再解析 RustDesk 帧和 RendezvousMessage。
3. 接收客户端原有 RegisterPk，保留 ID、UUID 和设备公钥，发送到 OSS UDP 21116。
   不生成替代设备身份，不在 OSS 尚未成功时伪造注册成功。
4. 将真实 RegisterPkResponse 返回客户端。注册成功后，由组件按 OSS 语义发送 RegisterPeer 心跳；
   不能反复重放 RegisterPk 充当心跳，否则会触发 TOO_FREQUENT。
5. 同一在线设备使用独立、稳定的 UDP socket，持续收取 RegisterPeerResponse、PunchHole、
   RequestRelay、FetchLocalAddr 等通知，转换为客户端注册 TCP 连接上的帧。
6. TCP 客户端需要注册链路的保活。只做一次 RegisterPk 转换会导致客户端超时、OSS 在线状态过期；
   应分别维护客户端 TCP 保活和 OSS UDP 注册心跳，且不能用本地保活掩盖上游失联。
7. PunchHoleRequest、RelayResponse、LocalAddr 等临时信令仍按 OSS TCP 路径发送。
   不能把全部 21116 请求简单变为 UDP；OSS 的 UDP 分支并不处理全部 TCP 消息。
8. 处理断线、重连、重复 ID、多个客户端、UDP 丢包及资源回收，限制帧长度和每会话缓存。

范围保持在信令适配。不解码桌面音视频、文件传输或 API 内容；原有远控授权和端到端密钥流程保留。

## 首次握手：必须验证的兼容点

源码核对基线为官方客户端 1.5.0，用户已确认现场也是 1.5.0。

- 客户端 start_tcp 会先调用 secure_tcp，等待服务端首帧，再发注册消息。
- 官方 1.5.0 的 secure_tcp 对有效 KeyExchange 验签并建立信令加密；对非 KeyExchange 首帧有旧服务端兼容路径。
- get_next_nonkeyexchange_msg 会跳过 KeyExchange，但不是所有临时信令读法都与注册读法相同。
  不能向所有 21116 连接一律塞一个空帧，就声称兼容。
- 当前实现先等客户端首字节 500ms：已收到首字节则继续读取完整信令帧；否则发送一个空兼容帧解除注册等待。
  先发包的临时 TCP 信令不插入额外首帧。这个判别依赖时序，临时连接迟发首字节可能被误判，需现场验收。
- 不支持强制要求加密的额外信令路径（例如部分 ICE 功能），不宣称支持全部 1.5.0 协议功能。
- 不能伪造签名、关闭公钥校验，或把未完成的密钥交换记录成“加密成功”。
  若采用旧服务端兼容方式，应明确标注适用版本和客户端到网关的信令加密边界。
- 若最终选择由组件完成签名握手，必须单独定义信任和密钥部署方案；不默认将 OSS 服务器私钥分发到路由器。

## 配置

在现有配置的目标项中增加 `oss_hbbs_port`，该端口必须也在同一项的 `ports` 中。例如：

```json
{
  "host": "rd.2iu.net",
  "ports": [21116, 21117, 443],
  "oss_hbbs_port": 21116
}
```

完整示例见 `config.oss.example.json`，其中占位密码必须替换。
适配复用既有 targets 的启动解析 IP 集合；连接同一获准 IP 的同端口请求也会适配。
原 SOCKS5 listen、auth、allow_sources、targets、超时和日志配置保留。
默认关闭时继续走原透明代理路径。无需让客户端启用 SOCKS5 UDP ASSOCIATE。

中转设备必须能访问 OSS 的 UDP 21116。域名、公钥和 SOCKS5 配置在客户端保留原值。
不读取 OSS 私钥，不生成新设备身份；客户端到网关信令采用旧服务端兼容明文方式，日志明确标记。
临时信令仍按 OSS 原有 TCP 协议发送，hbbr 和 API 继续透明转发，不终止远控端到端加密或 API TLS。

## 已完成的验证

- 本地模拟双客户端：原始注册消息和真实响应回传、独立 UDP 端口、通知隔离、持续 RegisterPeer 心跳。
- 原认证/目标拒绝仍生效，临时 TCP 请求及半关闭得到保留；超长帧和非法 protobuf 被拒绝。
- 使用从官方发布页下载的 **OSS hbbs 1.1.16 Windows 程序**，在独立本地目录中运行：
  注册成功、收到实际心跳回复、实际 OSS 推送 RequestRelay，客户端临时 TCP RelayResponse 返回外部控制连接，均通过。
- 测试使用协议客户端，并未替代现场官方 RustDesk GUI 的桌面远控验收。

正常日志应包含 `oss_legacy_greeting`、`oss_register_start`、`oss_register_response ... result=0`、
`oss_heartbeat_sent`、`oss_udp_message`；失败为 `oss_bridge_failed`。
适配连接使用这些协议日志，不沿用透明 TCP 的 transfer_summary 统计，以免把转换前后字节误认为同一方向的原始流量。

## 验收标准

- 原 SOCKS5 认证、来源拒绝、目标拒绝均仍生效，适配不能绕过这些检查。
- 使用真实 OSS 验证注册和超过在线过期时间的持续在线，能收到外部控制方发来的通知。
- 通过现有 SOCKS5 入口完成 hbbr 远控连接，并覆盖断线后恢复。
- 多客户端通知不能串线；临时控制连接与注册连接互不干扰。
- 日志区分 SOCKS5 成功、握手、注册 ACK、UDP 心跳、通知回传和失败，禁止记录密码、私钥或业务内容。
- API 的现有转发路径保留；21114 的现场错误当前不作为本轮排查对象。

## 核对来源

- [官方客户端 1.5.0 rendezvous_mediator.rs](https://github.com/rustdesk/rustdesk/blob/1.5.0/src/rendezvous_mediator.rs)
- [官方客户端 1.5.0 common.rs](https://github.com/rustdesk/rustdesk/blob/1.5.0/src/common.rs)
- [官方 OSS rendezvous_server.rs](https://github.com/rustdesk/rustdesk-server/blob/master/src/rendezvous_server.rs)
- [官方透明 SOCKS5 与 OSS 不兼容的问题记录](https://github.com/rustdesk/rustdesk/issues/13010)
