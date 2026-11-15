# 安装与配置

## 安装

需要 macOS 和 Python 3.9 或以上版本。准备一个你有权限使用的微信账号本机数据目录。查询只覆盖当前来源已同步、且副本已复制的内容。

在新的虚拟环境安装 wheel 或源码。需要配置图片支持时，保留 `[images]` 选项。

```sh
WALDEN_VENV="${XDG_DATA_HOME:-$HOME/.local/share}/walden/venv"
python3 -m venv "$WALDEN_VENV"
"$WALDEN_VENV/bin/python" -m pip install ".[images]"
```

上面的源码安装命令在包含 `pyproject.toml` 的目录中运行。wheel 安装可将 `".[images]"` 替换为该 wheel 路径并在路径末尾加 `[images]`。

将该安装包内 `wechat_local/resources/skills/wechat-local-query/SKILL.md` 复制到工具的用户技能目录。使用 Codex 时可放在 `~/.agents/skills/wechat-local-query/SKILL.md`。已有日常安装和同名 Skill 时请先保留现有副本，再按受支持的升级路径操作。

## 配置和同步

使用同一环境中的 `wechat-local-setup --help` 查看配置选项。首次配置时通过 `--account-root` 指定确认过的账号目录，通过 `--mirror-username` 指定确认授权的会话稳定标识，可以重复指定。可用 `--timezone` 保存查询时区。配置只创建私有配置，不启动同步。

已授权复制时，依次调用同一环境的 `wechat-local-sync init --source-config` 和 `wechat-local-sync once --source-config`，两条命令均传入实际配置文件。用 `wechat-local-sync status --source-config` 查看覆盖和进度。有些历史需要多轮才能补齐。

自动后台复制需要单独启用。用同一环境的 `wechat-local-sync follow-enable`、`follow-status`、`follow-disable` 管理已配置来源的服务，并给各命令传入同一个 `--source-config`。服务登记成功和来源同步健康是两个状态。切换或回退前先确认原服务及其子任务已经停止。

## 查询

在同一环境调用 `wechat-local-window`，显式传入 `--source-config`，选择一个会话选项（`--contact-query`、`--group-query` 或 `--conversation-username`）。用 `--latest` 查看本地最新 20 条，可按需指定条数。也可用 `--request` 查询明确的时间范围。

默认 `--read-mode local` 只读副本。仅在配置为指定会话范围且明确授权同步该来源时，使用 `--read-mode refresh`。账号范围配置使用 `local` 查询，源同步由已授权的后台服务执行。查看结果时，结合 `coverage`、`synced_at`、`freshness` 和 `gaps` 判断覆盖。遇到重名、来源冲突或不可用的媒体，请按结果补足确认或报告限制。

相关说明：[消息分类规则](WA_MESSAGE_CLASSIFICATION_RULES.md)和[本地语音运行环境](VOICE_RUNTIME.md)。
