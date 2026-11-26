# 安装与配置

## 安装

需要 macOS 和 Python 3.9 或以上版本。准备一个你有权限使用的微信账号本机数据目录。查询只覆盖当前来源已同步、且副本已复制的内容。

### 已验证范围

- 0.8 已通过一次真实首次取钥，环境为 Intel Mac（x86_64）、macOS 15.8.3（24H241）及微信 4.2.0（构建 270348）。同一安装环境后续复核为 Python 3.9.6，默认 Xcode LLDB 版本为 lldb-1703.0.236.103。
- 0.8.1 对独立安装、命令入口、合成调试副本签名和启动诊断做了定向验证。
- 0.9.12 在同机环境（Intel Mac x86_64 / macOS 15.8.3 / Python 3.9.6 / 微信 4.2.0 构建 270348）完成了持续后台同步、新消息增量、历史补齐、本地只读查询与媒体调度/解码/工作段让步的日常实机验收；未重复执行首次实机取钥（首次取钥实机记录仍来自 0.8），且未实测在线抓拍瞬态仅 `early_preview` 查询帧及自然命中 `media_segment_deferred` 分支。
- 0.9.13 在同机环境完成了日常实机验收，验证了微信端合法删除聊天记录后的单表游标安全恢复、本地已同步旧行保留与媒体队列续跑，以及后台并发同步期间放宽登记库清单读预算（15 秒）后的本地只读查询稳定性；未重复执行首次实机取钥，且未在实机环境中人为构造真 `local_id` 复用轮换或全删无锚点场景（相关 fail-closed 路径通过自动化测试验证）。
- Python 3.9 或以上是包声明的要求。Apple Silicon、其他系统或微信版本，以及其他 Python 与 LLDB 组合尚未验证。

在新的虚拟环境安装 wheel 或源码。需要配置图片支持时，保留 `[images]` 选项。

```sh
WALDEN_VENV="${XDG_DATA_HOME:-$HOME/.local/share}/walden/venv"
python3 -m venv "$WALDEN_VENV"
"$WALDEN_VENV/bin/python" -m pip install ".[images]"
```

上面的源码安装命令在包含 `pyproject.toml` 的目录中运行。wheel 安装可将 `".[images]"` 替换为该 wheel 路径并在路径末尾加 `[images]`。

将该安装包内 `wechat_local/resources/skills/wechat-local-query/SKILL.md` 复制到工具的用户技能目录。使用 Codex 时可放在 `~/.agents/skills/wechat-local-query/SKILL.md`。已有日常安装和同名 Skill 时请先保留现有副本，再按受支持的升级路径操作。

## 首次使用与同步

安装随包技能后，告诉助手“帮我配置 Walden 并开启持续后台同步”。确认以下信息即可，助手会调用同一安装环境的入口，无需逐条执行命令：

- 一个本人有权使用的微信账号目录，指向微信 `Documents/xwechat_files/<账号目录>` 中的单个账号。
- 本人稳定用户名，以及查询使用的时区。昵称和备注不能代替稳定身份。
- 同步哪些会话：已确认的稳定会话标识列表，或明确选择全账号。
- 同意将该范围复制到私有本地副本，并持续后台同步。

已有明确确认不会重复询问。首次流程自动获取并验证凭据、保存配置、初始化副本和启用后台；登录、扫码及系统许可仍需本人完成。不要在聊天中提供凭据。系统许可针对明确识别的调试副本，详见[首次取钥排障](FIRST_KEY_TROUBLESHOOTING.md)。

结果分别报告当前阶段、后台登记、实际同步状态、覆盖和缺口。`onboarding_complete` / `background_registered` 表示服务已登记，不能据此宣称同步健康或历史已追齐。账号范围初始化先建立空的受保护本地契约，返回 `copy_pending`，由既有后台授权链开始复制；指定会话先执行一轮有界初始化。首轮不会等待全部历史。新消息优先，剩余资源补历史，持续新消息可能延后历史进度。

新登记成员的首批从实际最新消息开始，每批仍最多500条；历史覆盖从0如实推进，不把已复制的最新片段算成历史前缀。全新分片先保存暂存文件的精确归属见证，实际复制可顺延一个后台轮次。已有绑定分片中的新成员可当轮开始。中断后仅续用匹配的代次、文件、来源和本地原子进度；未知空表、丢失的既有进度或副本文件不能冒充首次初始化。`account_copy_init_uncommitted_stage` 表示有尚未提交归属证明的暂存文件，停止自动重试并保留文件，需要先核实；重复启动不能清理或自动领养它。

本版本不自动恢复旧版中没有正面复制证明的缺项。已登记的单目标在表、进度、复制凭证全无且完整绑定分片仍在时，可由助手在用户明确确认同一账号、同一来源和单表补建后调用正式 `account-copy-reconcile`。助手从 `account-scope-status` 取得实际登记引用，先取本地计划，再以计划中的来源指纹及 `--confirmed` 提交；无需用户手工拼接指纹。确认命令不读取Source、不启服务，只创建不可覆盖的单目标请求。原follow授权在已知新尾和原预算允许时独立核验Source并补建，补建动作只写目标；其后正常增量同步另算。任何表（包括空表）、进度、fingerprint或已有初始化证据残留，成员缺失、整片缺失或绑定冲突均不走此修复。

补建永久保存 `prior_coverage_unknown`。本次新H覆盖可以完成，旧历史是否曾补全仍未知，查询、覆盖和后台状态分别报告；未知本身不是可重试的历史欠账。0.9.0能够读JSON不等于可以安全运行回退：它不会执行新的待初始化和此前覆盖未知语义。存在这些新记录时，只能在停稳后按精确完整备份恢复，不能仅重装旧wheel并让它写新副本。

默认配置为 `${XDG_CONFIG_HOME:-$HOME/.config}/wechat-local/current-source.json`。已有配置或失败重试时保持同一 `--config`、`--data-home`、安装环境、账号及范围。重复执行保留来源绑定、副本游标和服务，不会重置或重复登记。不同账号、身份、范围、目标目录或时区会被拒绝；既有指定会话配置不能借首次流程扩大为全账号。

凭据或配置失败、取消及初始化失败不会继续启用后台。后台启用失败可能已保存启用意图，仍未登记运行，助手应按实际结果报告并沿同一确认重试。账号初始化会保留本流程创建配置的证明，以及副本目录之外的精确发布见证。只有身份、配置与所有初始文件哈希均匹配见证的未发布暂存可继续同一次发布；更早的不完整暂存保留但不自动信任、修补或删除。已提交副本目标丢失会报告 `onboarding_initialized_copy_missing`，需恢复同一副本，不能新建空副本替代。外来账号配置没有首次创建证明时，也不能因缺少目录或后台意图而自动初始化。未知占用、见证变化或损坏的已提交副本会停止，不会清空后重建。已有配置重试会先读取并验证同源凭据；缺失、格式错误或验证失败会停在 `credential_validation`，不会登记后台后才尝试。捕获成功后、配置发布前取消时，仅清理本次仍匹配原父目录和文件身份的自有凭据；替换或外来文件保留。并发首次配置会返回 `onboarding_busy`。

### 管理与高级入口

助手使用的统一入口如下（示例占位值需先确认）：

```sh
"$WALDEN_VENV/bin/wechat-local-setup" \
  --account-root "/实际路径/Documents/xwechat_files/账号目录" \
  --confirm-self-username "已确认的本人稳定用户名" \
  --mirror-username "已确认的会话稳定标识" \
  --timezone Asia/Shanghai --start-sync --confirmed
```

全账号选择使用 `--account-scope` 替代所有 `--mirror-username`，两者不可并用。新配置未导入同账号凭据时自动取钥；可保留原 `--acquire-passphrase` 明示选项。`--confirmed` 仅在用户确已确认账号、范围与持续后台同步后由助手传入。

不加 `--start-sync` 时仍是原来的纯配置入口：只写私有配置并返回 `next_step=init`，不会自动复制或启后台。高级用法的指定会话初始化可另行调用同环境的 `wechat-local-sync init`、`once`、`status`，前提是已获得对应复制授权。

已配置服务由同环境的 `wechat-local-sync follow-status`、`follow-disable`、`follow-enable` 管理，均传入相同 `--source-config`。状态观察不会修复或重启服务；切换或回退前需确认原服务和子任务已停止。已有日常安装的隔离验收必须使用独立配置与数据目录，不能覆盖日常状态。

## 查询

在同一环境调用 `wechat-local-window`，显式传入 `--source-config`，选择一个会话选项（`--contact-query`、`--group-query` 或 `--conversation-username`）。用 `--latest` 查看本地最新 20 条，可按需指定条数。也可用 `--request` 查询明确的时间范围。

默认 `--read-mode local` 只读副本。仅在配置为指定会话范围且明确授权同步该来源时，使用 `--read-mode refresh`。账号范围配置使用 `local` 查询，源同步由已授权的后台服务执行。查看结果时，结合 `coverage`、`synced_at`、`freshness` 和 `gaps` 判断覆盖。遇到重名、来源冲突或不可用的媒体，请按结果补足确认或报告限制。

相关说明：[消息分类规则](WA_MESSAGE_CLASSIFICATION_RULES.md)和[本地语音运行环境](VOICE_RUNTIME.md)。

## 登记库清单复用（0.9.3）

账号副本升级使用同一安装环境的 `wechat-local-sync registry-reuse`。这是本地存储维护，不是普通消息查询的隐式权限；只在用户已授权升级/维护、后台已停止时由助手取计划，再用计划返回的来源指纹及 `--confirmed` 执行，不要求用户拼接指纹。首次账号自动 setup 在已确认的初始化流程内接通该步骤；已采用新格式的重复 setup 保留同一代次。迁移不取钥、不打开微信 Source、不启服务、不更改消息分片或本地复制进度。

旧观察的全部字段、原时间、旧编号及摘要保留。相同来源边界内、顺序和重复项均相同的表清单共享一个不可变对象；当前登记库仅保存当前成员实际引用的短观察。历史短观察分入独立归档，普通启动不会将它们全部复制进内存。补建前仍核对完整历史依据，不能把当前引用里没有某表解释成从未登记。

普通登记库完整快照仍有128MiB物理保护；每个归档也保留128MiB保护，达到保护时明确拒绝而非删除历史或提高上限。当前共享对象单值最多1MiB、同一读调用累计16MiB原始输入及2秒协作截止，包含还原和完整摘要检查；这不是RSS硬上限。迁移是独立流式操作，要求SQLite支持 `octet_length`（3.43或更新），每个值最多1MiB、每遍输入累计128MiB、最多65536行、每遍最多60秒；UTF-16按保守返回字节上界计费，可能更早拒绝，不宣称与UTF-8容量完全相同。缺能力/超限会停止，旧权威不会被清空。

迁移先在同盘私有暂存中完成并封存文件身份与哈希，再用系统原子交换保留旧登记库。中断仅续用本次精确见证；不完整输出保留，最多一个新自有尝试，不无限建目录或领养未知文件。旧库副本仍含原重复文本，因此这是工作集缩小，不能把含回退材料的总磁盘用量说成已减少。

新格式由旧0.9.1写入者明确拒绝。不得仅装回旧wheel、替回一个old.db或覆盖正在前进的副本。回退必须先完整保全前进状态，再依据匹配旧协议的完整备份另行恢复，保留新旧两套资料；本命令不自动回退、删除旧库或清理暂存。

### 0.9.5 background evidence and fairness

A successful ordinary round proves its reported committed rows/PG, not whole-account catchup. `complete=false`, `completeness=unknown`, and `status_check=not_run` remain explicit until an independent `account-scope-status` check; that check retains its original2s and byte protections. If no positive debt is known, `known_backlog=false` and `backlog_state=unknown` can coexist. The existing completion-relative normal interval remains finite; no zero-wait busy loop is introduced.

The global counter persists across Sources and rounds: at most three committed tail batches precede one serviceable verified history batch of at most500 rows. A head is only a scheduling candidate. Current Source/member/schema/PG/H protection is repeated before use. Resource/authority failures do not force a history write. An interrupted round retains debt and durably reserves at most one recovery tail opportunity; another restart cannot mint it again. Previously committed historical PG is acknowledged before resuming. Old093 understands the storage syntax but does not implement the new fairness/diagnostic semantics; this is not an automatic downgrade or production rollback instruction.

## Explicit single-shard restoration (0.9.6)

This is a separately authorized, local maintenance operation, not an ordinary query or automatic error recovery. First stop the same account follow service through its normal SDK and preserve the complete forward copy and matching old runtime/materials. The plan independently requires the original strict disabled control/birth/registration proof and an exclusive original writer lock. It opens no Source database or credential value; configured path/alias directory metadata is checked before creating locks or output. Keep the plan, replacement input and stage separate from configured Source roots and protected credential/database references.

Use the same installed `wechat-local-sync account-shard-restore-plan --source-config <profile> --registered-target-ref <resolved-ref> --replacement-file <private-equivalent-file> --restore-plan <new-private-plan>` to verify and pin the selected shard. Resolve the ref through the existing installed target tools, not user-supplied identity guesses. With explicit approval, apply using `account-shard-restore --source-config <same-profile> --restore-plan <plan> --restore-plan-sha256 <returned-hash> --confirmed`. The same apply command resumes a sealed interrupted attempt. `account-shard-restore-status` accepts the same pinned plan and reports only its local maintenance state.

A private replacement must exactly preserve all table schema/index definitions, typed values, rowids, sequence, PG, observed and binding. The plan verifies all registered members using existing Source proofs. The operation preserves `.account-scope.current`, all external receipts, members, Source anchors, fairness/discovery debt and logical cursors. It invalidates only the physical account-work cache. The old shard and mapping remain in the owned private attempt directory. The marker uses the existing `.account-scope.pending` fail-closed fence with its own restoration schema, never a forged account-migration receipt. Old0.9.5 ordinary entry points refuse this fence; old migration recovery cannot process the restoration record.

Only exact sealed old/new inodes and hashes may advance after an interruption. The pending inode is durably pinned in the seal; the original stage and registry inodes are checked at publication, recovery and before clearing the fence. Wrong/replaced files, foreign pending, prepared first-copy ownership, journals/WAL/SHM, changed profile/source scope/control, unsupported schema or exhausted budget remain failures. Preserve both sides and pending; do not delete markers, adopt same-byte replacement inodes, manually update identity constants, bypass guards or run an old writer. An interrupted unsealed copy is retained and refused for explicit review; automatic continuation is limited to a sealed stage. Completed retries return publication history without pinning the initial new hash forever or replacing later legitimate progress.

The bounded local maintenance operation uses a shared120s deadline,2MiB SQLite caches, at most2048 tables, per-value1MiB and per-file/per-summary128MiB bounds. SQLite `octet_length` support is required. These limits do not change ordinary Source1MiB/20s,500-row batches, registry128MiB snapshots or retry/fairness rules. The kernel atomic swap/no-replace primitive must be supported and both sides must be on the verified same filesystem; failure preserves pending and unknown sides. No in-place old-writer rollback is provided. Real production replacement and subsequent Source synchronization require their own authorization and acceptance.

### Preparation diagnostics (0.9.7)

`wechat-local-sync follow-status --source-config PROFILE` may include `listener_task_id` and bounded `worker_preparation` diagnostic fields linking the existing CLI task to this listener generation. These fields never authorize recovery. In-progress/crash remains unknown; not-attempted-by-this-call only describes a controlled failure of that call; API-returned is not verified worker/Source commit. Missing old fields do not establish non-submission. Original pending/receipt/strict-stop checks remain mandatory.

## Revoked legacy slot after a kernel change (0.9.8)

The explicit maintenance commands `follow-legacy-retirement-plan` and
`follow-legacy-retire-after-boot` only handle a revoked account-bound legacy
pending slot whose original operation/receipts are missing. They do not cancel
a job, restart the computer, change privacy permissions, admit Source work or
prove historical submission/SQL outcomes. Same-boot retirement is refused.

A separately installed maintenance package may read the unchanged original
profile and create the plan under the original follow/writer locks; the daily
runtime/configuration must not be switched merely to obtain a plan. The plan
captures a public kernel boot-session UUID prospectively. Only after a genuine
new kernel generation, unchanged ownership/account/scope/revocation evidence,
absent exact services/material and exclusive writer lock may retirement publish
a distinct disabled instance. Reboot alone is insufficient. Missing or changed
evidence fails closed; do not reconstruct receipts, clear pending, or signal
unknown processes. Retain a complete forward backup before any later deployment.

The plan command requires `--authorize-legacy-retirement`,
`--expected-source-sha256` and `--expected-policy-generation`; it returns a
retirement ID and plan SHA-256. Apply requires the same explicit authorization
and `--legacy-retirement-id` / `--legacy-retirement-plan-sha256`. It preserves
unknown control evidence and never rewinds legitimate later progress on retry.
These commands require separate operation authorization; their presence in an
installed package is not permission to run them or reboot.

A completed receipt is historical evidence only. Current stop/status also
rechecks original lock identities, current account/scope/revocation and both
exact services in the bound caller context. A new lock inode, service reload
or unknown observation refuses current strict; historical replay never rewinds
later progress or promises the current service is stopped.

## Current-state retirement witness (0.9.9, explicit maintenance only)

A separately authorized exceptional recovery may use
`follow-current-state-recovery-plan` / `follow-current-state-recover` to create a
NEW retirement-only authority from the current protected namespace. This does
not repair, migrate or re-sign an old legacy plan/owner or prove old volume,
submission or SQL continuity. Do not invoke it as a query failure fallback.
Same-Mac/non-migration is a trusted operator precondition; current volume UUID
is not hardware attestation. It requires fresh native currentBoot != oldPlanBoot,
unchanged account/scope and original control bytes, explicit four hash anchors,
a canonical/private current home-volume identity closure, disabled intent,
absent exact services/material and existing-lock exclusion. SourceAuthority is
always false. Missing/unknown/changed evidence refuses; never clear pending,
change permissions, reanchor Source, signal, or reinstall old state to proceed.

The plan command requires `--authorize-current-state-recovery`, the original
`--expected-source-sha256`, `--legacy-retirement-id`,
`--legacy-retirement-plan-sha256`, `--current-recovery-owner-sha256`,
`--current-recovery-preboot-receipt` and its
`--current-recovery-preboot-receipt-sha256`. It returns a witness ID and a
**witness fingerprint**: SHA-256 of the encoded current stable ticket pin
(identity AND content), not merely the raw ticket bytes. Recover requires the
same explicit authorization plus `--current-recovery-witness-id` and
`--current-recovery-witness-fingerprint`; it must run in the witness's current
kernel generation. No extra reboot is requested. Plans and unknown evidence
stay intact. A partial unsealed witness is a failure, never silently adopted.

Completed receipts are historical only. Fresh maintenance `follow-status`
rechecks the current witness/object/lock ownership, account/revocation and both
exact services before strict can be confirmed. Preserve and verify a whole
forward copy before any later installation or enabling. The maintenance
interpreter/package must independently be verified as CURRENT trusted inputs;
old image receipts lacking stable volume identity are not repaired here.
Isolation acceptance does not authorize real adoption or show TCC/Source
readability, normal synchronization, or old messages recovered.


### 0.9.10 current qualification for one legacy missing copy

Use only the explicit installed `account-copy-reconcile` confirmation described in the paired Skill. `--authorize-current-reconcile --expected-reconcile-request-sha256` preserves the exact legacy request and establishes a separate current qualification through active follow; it does not retrofit old volume evidence. Optional repeated `--withhold-unowned-target-ref` requires separate explicit approval for at most two exact same-shard refs. Each remains uninitialized and coverage unknown only after fresh current-object, scope, DDL, three-absence and no-CI validation; no blanket skip of missing copies or Source errors exists. Qualification source metadata alignment is shard-wide; actual initialization/copy authority remains confined to the original target.

Install source, wheel and Skill together in the intended isolated candidate environment for acceptance. Existing daily installs and real Source configuration are not changed by preparing this candidate. Old writers fail closed on the new request schema; do not roll back a live request by copying older control files over newer progress. An owned empty target initialization is not a copied message batch. Keep actual Source completion/SQL+PG results, local-only query coverage and historical unknown separate.
