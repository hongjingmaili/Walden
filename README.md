# Walden

**macOS 本地只读微信消息增量镜像与查询工具**

`macOS` · `Python >= 3.9` · `Apache-2.0` · `Local-First` · `v0.9.13`

## Walden 是做什么的？

Walden 帮助你在 macOS 上把**自己有权使用的本机微信消息**增量同步到一份**私有本地副本**中，并支持按联系人、群聊或日期快速检索消息内容（包括图片文字与语音转写）。

它适合以下场景：
- **给 AI 助手提供可控的本地微信消息检索能力**：搭配随包技能，让助手帮你查某段时间的群聊讨论、某位联系人的最近消息，而无需翻找聊天窗口或把数据上传到第三方服务。
- **安全隔离、只读查询**：日常查询只读本地副本，不直接写入或干扰微信源数据库；一切配置、凭据与副本都留在你自己的电脑上。

---

## 核心功能

- **按联系人、群聊与日期检索消息**：支持查询最近 N 条消息或指定时间窗的历史消息，按联系人、群聊或稳定会话标识精准定位，避免重名混淆。
- **覆盖状态与缺口透明提示**：每次查询都会同时返回副本的观测时间、覆盖状态与未覆盖缺口，清楚区分“当前可见”与“历史已全部补齐”，不把不完整的记录当成全量结果。
- **新消息优先，后台持续补齐历史**：后台同步优先跟进最新消息，再利用剩余资源稳步补齐历史记录；既支持只同步指定会话，也支持明确授权后的全账号范围同步。
- **图片与语音本地处理**：
  - 支持新图提前预览，缩短新消息图片的等待时间；
  - 支持较大图片/附件的独立 FFmpeg 解码；
  - 支持基于 Apple Vision 的本地图片 OCR 识字，以及本地语音消息转写；
  - 当附件不可用时，仍保留消息正文并如实标明缺口。
- **随包技能引导上手**：内置 `wechat-local-query` 技能。首次使用时，只需向助手确认微信账号目录、本人身份、同步范围和后台许可，即可一次衔接取钥验证、副本初始化与持续后台同步，无需手工逐条拼接命令。
- **严格的隐私与只读边界**：
  - 本地优先，数据与凭据均保存在本机私有目录，不外传；
  - 账号范围的日常查询只读本地副本，不触碰微信源库；
  - 回复兼容功能仅依赖既存事件证据，发送前必须经本人明确确认目标与完整正文。

---

## 工作原理（简明）

Walden 把**后台同步**与**日常查询**拆成两层，互不干扰：

```text
本机微信数据目录（仅已授权账号，只读读取）
        │
        │  wechat-local-sync（后台监听文件变化 + 定期检查）
        ▼
私有本地副本（消息 + 覆盖/缺口状态 + 本地图片/语音处理结果）
        │
        │  wechat-local-window --read-mode local（只读副本，不碰微信源库）
        ▼
查询结果（消息正文 + OCR / 语音转写 + 覆盖与缺口说明）
```

1. **后台同步**：监听 macOS 文件变化并定期检查，以只读方式通过 SQLite 确认增量变化，把消息同步到本地私有副本，并在本地处理图片与语音。
2. **本地查询**：日常检索直接读取本地副本，快速返回消息与覆盖/缺口信息。指定会话配置在明确授权时也支持按需刷新。

> 更多关于调度公平、单分片隔离、受控恢复与存储边界的技术说明，见 [发布说明](RELEASE_NOTES.md) 和 [安装与配置指南](docs/INSTALLATION.md)。

---

## 快速开始

### 1. 安装

需要 **macOS** 和 **Python 3.9+**，以及你有权限使用的本机微信账号数据目录。建议在独立虚拟环境中安装（如需图片与 OCR 支持，请保留 `[images]`）：

```sh
WALDEN_VENV="${XDG_DATA_HOME:-$HOME/.local/share}/walden/venv"
python3 -m venv "$WALDEN_VENV"
"$WALDEN_VENV/bin/python" -m pip install ".[images]"
```

> 若从发布 wheel 安装，将 `".[images]"` 替换为 `<wheel路径>[images]`。

随后将安装包内的 `wechat_local/resources/skills/wechat-local-query/SKILL.md` 复制到助手的用户技能目录（例如 Codex 可放至 `~/.agents/skills/wechat-local-query/SKILL.md`）。

### 2. 首次配置与开启同步

安装随包技能后，直接告诉助手“帮我配置 Walden 并开启持续后台同步”，并确认以下四项信息即可：
1. 本人有权使用的微信账号数据目录（`Documents/xwechat_files/<账号目录>`）
2. 本人稳定用户名与查询时区
3. 同步范围（指定会话列表，或明确选择全账号）
4. 同意将该范围复制到私有本地副本并开启持续后台同步

登录、扫码及 macOS 系统许可仍需由本人完成。若需直接调用命令行统一入口（示例占位值须替换为已确认的实际值）：

```sh
"$WALDEN_VENV/bin/wechat-local-setup" \
  --account-root "/实际路径/Documents/xwechat_files/<账号目录>" \
  --confirm-self-username "<本人稳定用户名>" \
  --account-scope \
  --timezone Asia/Shanghai \
  --start-sync --confirmed
```

> 仅同步指定会话时，可用一个或多个 `--mirror-username "<稳定会话标识>"` 替代 `--account-scope`。不加 `--start-sync` 时仅保存私有配置，不会自动复制或启用后台。

### 3. 基础查询与状态核查

默认配置文件路径为 `${XDG_CONFIG_HOME:-$HOME/.config}/wechat-local/current-source.json`。

```sh
# 查看指定群聊最近 20 条本地消息（只读副本）
"$WALDEN_VENV/bin/wechat-local-window" \
  --source-config "${XDG_CONFIG_HOME:-$HOME/.config}/wechat-local/current-source.json" \
  --group-query "<群聊名称>" \
  --latest 20 \
  --read-mode local

# 查看后台同步服务状态（只读，不修复或重启服务）
"$WALDEN_VENV/bin/wechat-local-sync" follow-status \
  --source-config "${XDG_CONFIG_HOME:-$HOME/.config}/wechat-local/current-source.json"
```

随包提供五个命令行入口（详见 [发布内容清单](PACKAGE_CONTENTS.md)）：
- `wechat-local-setup`：来源配置、首次取钥验证与一站式初始化／后台启用
- `wechat-local-sync`：后台同步服务管理、状态核查与受控维护操作
- `wechat-local-window`：本地副本消息查询
- `wechat-local-reply`：基于既存事件证据的回复兼容操作
- `wechat-local-evidence`：查看脱敏故障证据

---

## 隐私、安全与已验证范围

- **本地优先**：配置、凭据、本地副本、语音模型与运行记录均保留在本机私有目录，不随包分发，不外传。
- **权限边界**：首次取钥、后台同步、查询与回复各自独立受控；身份或来源冲突时停止，不自动换源或扩大范围。
- **已实机验证**：
  - `0.9.13` 已在 Intel Mac（x86_64，macOS 15.8.3，Python 3.9.6）与微信 4.2.0（构建 270348）环境下完成日常实机验收，覆盖持续后台同步、新消息增量、历史补齐、本地只读查询、图片/语音处理，以及微信端删除记录后的游标安全恢复与并发同步期间本地查询稳定性。
  - 首次实机取钥验证记录来自 `0.8`（同机环境，Xcode LLDB `lldb-1703.0.236.103`）；`0.9.13` 未重复执行首次实机取钥。
- **未验证边界与限制**：
  - 瞬态仅 `early_preview` 查询帧与 `media_segment_deferred` 分支目前仅通过定向合成测试验证，尚未在实机运行中自然命中或抓拍。
  - 首次取钥受 macOS 系统安全策略与权限许可限制；Apple Silicon 及其他 macOS、微信、Python、LLDB 版本组合尚未实机验证。
  - 不承诺固定同步秒数，单轮成功不代表整账号历史或全部媒体已追齐。

---

## 文档导航

| 文档 | 说明 |
| --- | --- |
| [安装与配置指南](docs/INSTALLATION.md) | 详细安装步骤、已验证范围、后台管理、迁移与受控维护边界 |
| [发布说明](RELEASE_NOTES.md) | `v0.9.13` 核心变化、已验证范围、未验证边界与历史演进 |
| [首次取钥排障](docs/FIRST_KEY_TROUBLESHOOTING.md) | 调试副本签名、系统许可、启动锁与捕获阶段诊断说明 |
| [语音运行环境](docs/VOICE_RUNTIME.md) | 本地语音转写依赖安装与运行要求 |
| [消息分类规则](docs/WA_MESSAGE_CLASSIFICATION_RULES.md) | 默认消息分类与摘要展示规则 |
| [查询结果分页工具](docs/QUERY_RESULT_TOOL.md) | 独立查询结果检查与分页辅助工具说明 |
| [发布内容清单](PACKAGE_CONTENTS.md) | Wheel 包含内容与五个命令行入口说明 |
| [随包查询 Skill](skills/wechat-local-query/SKILL.md) | 助手侧查询与首次引导技能说明 |

---

## 许可证

Walden 使用 [Apache License 2.0](LICENSE) 开源许可。随附第三方组件适用 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) 中列明的各自许可证。
