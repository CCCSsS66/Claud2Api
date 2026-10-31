<p align="center">
  <img src="ui/icon.svg" alt="Claud2Api" width="112" height="112" />
</p>

<h1 align="center">Claud2Api</h1>

<p align="center"><strong>v0.1.0-alpha.7</strong></p>

Claud2Api 是一个用 Rust 编写的 Claude 网页端 → Anthropic Messages API 网关，附带私有管理控制台、账号池与自更新守护。它把网页会话的图片、PDF、文本附件、客户端工具、网页原生搜索与读取、Artifacts、远端代码沙箱和项目知识桥接为标准 Messages API。

## 来源

本项目基于 [Saito-Sakuya/Claud2Api](https://github.com/Saito-Sakuya/Claud2Api)（MIT）重构与扩展，原作者为 **Saito-Sakuya**。原始架构与大部分基础代码来自上游；本仓库补全了协议、账号运维、公网安全、界面与风控收敛。本项目与 Anthropic 及原作者均无隶属或背书关系。

## 功能

- Messages API：JSON / SSE、`count_tokens`、图片 / PDF / 文本附件、客户端工具通道
- 网页原生工具组：`web_search`、`artifacts`、`repl`、`widgets`、`project_knowledge`
- 可选扩展思考（`thinking`），返回标准思考块与上游签名
- 兼容接口：`/v1/chat/completions`、`/v1/responses`、`/v1/models`、`/v1/conversations/{id}`
- 账号池：严格串行、节奏抖动、独立浏览器配置与代理、5h 用量、存活检测、冷却重置、凭据轮换、删除
- 管理控制台：账号、模型映射、令牌、会话、运行配置、消息日志、操作审计、用量概览
- 公网安全：控制台强制 TLS、管理员会话、失败锁定、来源白名单、登录审计
- 移动端：抽屉导航、卡片化表格、触控与安全区适配

## 快速开始

```sh
sudo install -d -m 700 /srv/claud2api-private
sudo install -d -m 700 -o 65532 -g 65532 /srv/claud2api-state
sudo python3 scripts/generate_key.py /srv/claud2api-private/gateway-key.txt
sudo python3 scripts/generate_key.py /srv/claud2api-private/admin-key.txt
sudo touch /srv/claud2api-private/accounts.txt
sudo chmod 600 /srv/claud2api-private/*.txt
sudo chown 65532:65532 /srv/claud2api-private/*.txt

# 控制台证书：可信证书，或自签名
sudo python3 scripts/generate_tls.py /srv/claud2api-private --host c2a.example.com --host 203.0.113.10
sudo chown 65532:65532 /srv/claud2api-private/tls-*.pem
```

创建 `/srv/claud2api-private/settings.env`：

```dotenv
CLAUD2API_STATE_DIR=/srv/claud2api-state
GATEWAY_API_KEY_FILE=/srv/claud2api-private/gateway-key.txt
ADMIN_API_KEY_FILE=/srv/claud2api-private/admin-key.txt
CLAUDE_ACCOUNTS_FILE=/srv/claud2api-private/accounts.txt
CONTROL_TLS_CERT_FILE=/srv/claud2api-private/tls-cert.pem
CONTROL_TLS_KEY_FILE=/srv/claud2api-private/tls-key.pem
CLAUD2API_IMAGE=claud2api:local
GATEWAY_PORT=18081
CONTROL_BIND=0.0.0.0:18082
ALLOW_REMOTE_CONTROL=true
SIMULATED_CACHE_ENABLED=true
CLAUDE_TIMEZONE=Asia/Taipei
CLAUDE_LOCALE=zh-CN
```

```sh
sudo chmod 600 /srv/claud2api-private/settings.env
sudo docker compose --env-file /srv/claud2api-private/settings.env up -d --build
curl http://127.0.0.1:18081/health
```

- 控制台：`https://<地址>:18082/`，使用 `admin-key.txt` 登录
- 公开 API：`http://<地址>:18081`，使用 `gateway-key.txt` 或控制台创建的令牌
- 账号可从控制台导入，或写入 `accounts.txt`（每行一个 Session Key 或完整 Cookie）

## API 示例

```python
from pathlib import Path
from anthropic import Anthropic

client = Anthropic(
    base_url="http://127.0.0.1:18081",
    api_key=Path("/srv/claud2api-private/gateway-key.txt").read_text().strip(),
)
model = client.models.list().data[0].id
message = client.messages.create(
    model=model,
    max_tokens=1024,
    messages=[{"role": "user", "content": "Hello"}],
)
print(message.content)
```

- 默认使用账号实际支持的原生模型名；需要区分本服务时可用 `c2a-claude-*`
- 启用自定义模型配置后，请使用 `/v1/models` 返回的 ID
- 思考：请求体加 `"thinking": {"type": "enabled"}`，是否产生思考块取决于账号与模型

## 安全与风控

- 公网控制台必须启用 TLS（`CONTROL_TLS_*`），或由可信反向代理终止 TLS 并设置 `TRUST_PROXY=true`
- 管理会话默认 8 小时，退出即撤销；连续失败 10 次锁定 15 分钟
- 建议设置 `ADMIN_ALLOW_CIDRS`，并在云防火墙只放行必要端口
- 每个账号使用独立且稳定的出口 IP，不要 24/7 贴速率上限运行
- 本项目无法消除平台侧风控，也不保证账号安全、可用性或额度

## 许可证

[MIT](LICENSE)。上游版权归 Saito-Sakuya 及贡献者所有，本仓库保留原始许可声明。第三方组件许可见 `LICENSES/` 目录。

---

> 这是 fork 仓库。**不要点击 GitHub 的 Sync fork / Discard commits**，它会把代码重置回上游旧版本。
