# Walden

Walden 在 macOS 上将你明确授权的微信会话同步到本地副本。可以按联系人、群聊或日期查阅已复制的消息，也可以检查同步覆盖和附件状态。

- 普通查询仅读取副本。最新查询返回副本观测到的最新消息和覆盖状态。
- 显式刷新适用于指定会话范围的配置。账号范围配置用本地查询，源同步由单独授权的后台服务执行。
- 已保存的图片和音频可按配置处理。附件不可用时仍保留消息正文。
- 回复兼容功能依赖既存事件证据。新副本的消息引用不能直接用于发送。

从[安装与配置指南](docs/INSTALLATION.md)开始，或查看[发布说明](RELEASE_NOTES.md)。默认消息分类见[分类规则](docs/WA_MESSAGE_CLASSIFICATION_RULES.md)；本地语音依赖见[语音运行环境](docs/VOICE_RUNTIME.md)。

Walden 使用 [Apache License 2.0](LICENSE)。随附第三方组件适用[各自的许可证](THIRD_PARTY_NOTICES.md)。
