# 安装与配置

## 安装

需要 macOS 和 Python 3.9 或以上版本。准备一个你有权限使用的微信账号本机数据目录。查询只覆盖当前来源已同步、且副本已复制的内容。

### 已验证范围

- 0.8 已通过一次真实首次取钥，环境为 Intel Mac（x86_64）、macOS 15.8.3（24H241）及微信 4.2.0（构建 270348）。同一安装环境后续复核为 Python 3.9.6，默认 Xcode LLDB 版本为 lldb-1703.0.236.103。
- 0.8.1 对独立安装、命令入口、合成调试副本签名和启动诊断做了定向验证。真实取钥成功记录来自 0.8。
- Python 3.9 或以上是包声明的要求。Apple Silicon、其他系统或微信版本，以及其他 Python 与 LLDB 组合尚未验证。

在新的虚拟环境安装 wheel 或源码。需要配置图片支持时，保留 `[images]` 选项。

```sh
WALDEN_VENV="${XDG_DATA_HOME:-$HOME/.local/share}/walden/venv"
python3 -m venv "$WALDEN_VENV"
"$WALDEN_VENV/bin/python" -m pip install ".[images]"
```

上面的源码安装命令在包含 `pyproject.toml` 的目录中运行。wheel 安装可将 `".[images]"` 替换为该 wheel 路径并在路径末尾加 `[images]`。

将该安装包内 `wechat_local/resources/skills/wechat-local-query/SKILL.md` 复制到工具的用户技能目录。使用 Codex 时可放在 `~/.agents/skills/wechat-local-query/SKILL.md`。已有日常安装和同名 Skill 时请先保留现有副本，再按受支持的升级路径操作。

## 配置和同步

首次配置前，准备以下信息：

- 你有权查询的微信账号目录，使用微信原有的 `Documents/xwechat_files/<账号目录>` 布局，并指向其中一个账号目录。
- 至少一个你确认要同步的会话稳定标识。用 `--mirror-username` 传入；多个会话可重复指定。昵称和备注不能代替稳定标识。尚未确认标识时，先停在配置前。
- 安装在 `/Applications/WeChat.app` 的微信客户端，以及通过 `xcrun --find lldb` 能找到的调试器。时区按自己的实际情况选择，例如 `Asia/Shanghai`。

### 首次获取凭据

沿用安装时的 `WALDEN_VENV`，把示例里的账号目录、会话标识和时区换成自己的值。首次配置需要显式加上 `--acquire-passphrase`，程序会在本机获取和验证凭据：

```sh
"$WALDEN_VENV/bin/wechat-local-setup" \
  --account-root "/实际路径/Documents/xwechat_files/账号目录" \
  --mirror-username "已确认的会话稳定标识" \
  --timezone Asia/Shanghai \
  --acquire-passphrase
```

看到 `configured` 或 `configured_with_voice_incomplete` 后再继续。后者表示配置已完成，语音能力仍有缺口。默认配置路径为 `${XDG_CONFIG_HOME:-$HOME/.config}/wechat-local/current-source.json`。如果显式传了 `--config`，后续使用同一个文件。

已有日常配置时，请先使用独立的 `--config` 和 `--data-home` 路径进行验收，保留日常配置及库。失败重试时保持同一组路径，让程序核验并复用对应的受保护副本。请本人完成登录，不在聊天中提供凭据。详细步骤见[首次取钥排障与复盘](FIRST_KEY_TROUBLESHOOTING.md)。

若出现 `credentials_required`，检查命令是否省略了 `--acquire-passphrase`。若客户端、调试器或验证步骤报错，先根据错误处理当前账号的配置。取钥前提、错误说明和已有同账号凭据的高级导入方式见[随包技能的首次配置说明](../skills/wechat-local-query/SKILL.md#first-setup-explicit-scope-and-existing-copies)。

若状态为 `capture_stage_failed`，且 `failure_reason` 为 `target_exited_during_launch`，说明调试目标在开始捕获前退出。可用诊断中的阶段和退出状态定位此次失败。退出状态本身无法说明是否由 macOS 安全策略拒绝，应核对同一次启动的系统安全事件和调试权限。

### 初始化本地副本

配置成功后，已授权复制时再执行：

```sh
WALDEN_CONFIG="${XDG_CONFIG_HOME:-$HOME/.config}/wechat-local/current-source.json"
"$WALDEN_VENV/bin/wechat-local-sync" init --source-config "$WALDEN_CONFIG"
"$WALDEN_VENV/bin/wechat-local-sync" once --source-config "$WALDEN_CONFIG"
"$WALDEN_VENV/bin/wechat-local-sync" status --source-config "$WALDEN_CONFIG"
```

设置过 `--config` 时，将 `WALDEN_CONFIG` 换成你选的路径。先检查覆盖和缺口再查消息，有些历史需要多轮才能补齐。

自动后台复制需要单独启用。用同一环境的 `wechat-local-sync follow-enable`、`follow-status`、`follow-disable` 管理已配置来源的服务，并给各命令传入同一个 `--source-config`。服务登记成功和来源同步健康是两个状态。切换或回退前先确认原服务及其子任务已经停止。

## 查询

在同一环境调用 `wechat-local-window`，显式传入 `--source-config`，选择一个会话选项（`--contact-query`、`--group-query` 或 `--conversation-username`）。用 `--latest` 查看本地最新 20 条，可按需指定条数。也可用 `--request` 查询明确的时间范围。

默认 `--read-mode local` 只读副本。仅在配置为指定会话范围且明确授权同步该来源时，使用 `--read-mode refresh`。账号范围配置使用 `local` 查询，源同步由已授权的后台服务执行。查看结果时，结合 `coverage`、`synced_at`、`freshness` 和 `gaps` 判断覆盖。遇到重名、来源冲突或不可用的媒体，请按结果补足确认或报告限制。

相关说明：[消息分类规则](WA_MESSAGE_CLASSIFICATION_RULES.md)和[本地语音运行环境](VOICE_RUNTIME.md)。
