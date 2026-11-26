# Walden 0.9.12

本版本为自 `v0.8.1`（及 `v0.7.9` / `v0.8`）以来经实机日常验收通过的正式公开发布版本，整合了首次使用与持续后台同步、账号规模公平与存储稳定性、单表与分片受控恢复，以及媒体调度与解码的多项核心改进。

## 自 v0.8.1 以来的核心变化

### 媒体调度、解码与工作段改进
- **媒体调度与部分来源健康表续跑**：在既有自有媒体子进程内优先处理可信的常规新尾媒体增量，不改写旧任务标签；保留历史、语音与 OCR 的持久服务机会。部分来源出现可确认的局部暂态异常时，已通过验证的健康表与健康分片继续推进，局部缺口与失败仍如实报告。
- **较大附件独立 FFmpeg 解码支持**：支持对较大附件/图片通过独立 FFmpeg 进程执行有界解码，提升大附件处理稳定性；附件不可用时继续保留消息正文并标明缺口。
- **新图提前预览唤醒**：在后台完整媒体处理完成前支持受保护的新图提前预览唤醒，缩短新消息图片的可见等待。
- **媒体工作段到期平滑让步**：媒体子进程内的连续小批处理共享原截止时间，并在工作段到期前平滑让步退出，避免触发 300 秒误退避；遇到资源争用、系统压力、未知指标或无进展时按界停止。

### 后台同步、公平调度与存储稳定性
- **统一首次配置与持续后台同步**：`wechat-local-setup --start-sync --confirmed` 在用户明确确认后串联凭据验证／获取、受保护本地副本初始化与持续后台登记，保留既有来源绑定与进度；后台登记、同步健康与历史覆齐分别报告。
- **新消息优先与全局写入公平**：数据库与日志变化提示优先处理新消息，最多连续提交 3 批新尾消息后，下一可用机会提供给 1 批已验证历史消息（每批最多 500 条）；普通轮次结果与独立 `account-scope-status` 全账号检查明确分离。
- **单表游标回退恢复与受控补建**：保留严格的来源、身份、表结构、只读事务与游标校验，异常时可安全回退恢复；针对已登记且表/进度/复制凭证全无的单目标，支持显式确认的 `account-copy-reconcile` 与当前资格核验，永久保留 `prior_coverage_unknown` 语义。
- **账号登记库清单复用与本地迁移**：同源相同表清单共享不可变对象、历史短观察分入归档，缩小日常启动工作集，保持 128 MiB 保护；旧写入者明确拒绝新格式。
- **单分片暂态锁隔离、显式替换与受保护退场**：已验证分片遇到可信 SQLite BUSY/LOCKED 时局部退避，不阻断其他健康分片；提供显式单分片替换（`account-shard-restore`）、旧代终态恢复与当前态退场见证维护入口，以及公开服务读取短暂不可用时的有界重试。

## 已实机验证范围
- **日常运行实机验收（0.9.12）**：在 Intel Mac（x86_64，macOS 15.8.3，Python 3.9.6）与微信 4.2.0（构建 270348）环境下完成 0.9.12 实机日常运行验收，覆盖持续后台同步、新消息增量、历史补齐、本地只读查询、媒体调度与图片/语音处理，以及媒体工作段平滑让步。
- **首次取钥实机验证（历史基线）**：首次取钥实机验证记录来自 `0.8`（同机 Intel Mac / macOS 15.8.3 / 微信 4.2.0 构建 270348 / Xcode LLDB `lldb-1703.0.236.103`）；`0.9.12` 未重复执行首次实机取钥。

## 明确未验证边界与已知限制
- **瞬态仅 `early_preview` 查询帧**：未在实机在线抓拍到仅命中 `early_preview` 的瞬态查询帧（该路径已通过隔离合成测试验证）。
- **`media_segment_deferred` 分支**：实机日常运行期间未自然命中 `media_segment_deferred`（该分支已通过定向合成测试验证）。
- **首次取钥系统策略与平台覆盖**：首次取钥仍受 macOS 系统安全策略与权限许可限制，登录与系统授权须由本人完成；Apple Silicon 及其他 macOS、微信、Python、LLDB 版本组合尚未完成实机验证。
- **覆盖与时效边界**：不承诺固定同步秒数，不将单轮同步成功或后台已登记等同于整账号历史或全部媒体已追齐；查询结果中的 `coverage`、`synced_at`、`freshness`、`gaps` 与 `prior_coverage_unknown` 仍按实际状态分别报告。

---

以下为 `0.8.1` 至 `0.9.11` 的阶段演进记录：

# 0.9.11

Bounded retries for explicitly unavailable public service reads avoid abandoning an owned listener after a single recoverable read failure. Unknown/changed ownership, denied access, malformed identity and persistent read failure remain closed. No KeepAlive, background timing, Source permissions, message/media storage or scope change.

# 0.9.10 isolated reconcile candidate

Explicit current qualification preserves a legacy missing-copy request and historical unknown while validating stable same-FD volume/file identities through active follow. The authorized Source shard metadata can align atomically; only the originally confirmed target receives empty initialization and normal guarded copying. At most two separately confirmed exact refs can remain withheld only after each fresh Source/local/three-absence/no-CI check; other missing copies still fail. Qualification interruptions retain the bound object, and a permanent qualification failure remains blocked across normal listener/policy changes. No real Source, daily deployment, permission fix, or historical continuity is claimed by this isolated candidate.

# 0.9.6 — isolated single-shard restoration candidate

Adds explicit local plan/apply/status for replacing one stopped account shard with a logically equivalent SQLite file. The existing pending fence blocks ordinary old and new writers. Exact old/new file ownership, unchanged account/source proofs, original SDK quiescence and a sealed private stage govern recovery; the old file is preserved. Completed retries never reinstall the initial snapshot over later progress. This is an isolated maintenance candidate, not an automatic repair or a deployed recovery result.

# 0.9.5 — isolated background budget/diagnostic repair candidate

A previously selected positive history fairness opportunity can defer optional tail-discovery/inventory pages until after its guarded batch. It preserves pending discovery/freshness and performs the original remaining-budget maintenance after the atomic rows/PG commit, then hands the next opportunity back to fresh selection. The existing Source cookie/identity/member/schema/PG checks, 3-tail fairness rule, 500-row batch, 1MiB metadata cap and mandatory finish reserve remain.

A bounded optional discovery origin in the existing tail-probe state carries only positively unconsumed, same-registry/source hints across listener generations and partial pages. It never supplies authorization, a current counter/MAX or completeness. Complete discovery and real pending service release it; legacy states lacking a comparable positive chain keep the ordinary finite fallback. Its charged atomic prefix preserves the old consumed epoch on metadata deferral. Partial discovery reuses the existing quiet turn while a newer current-epoch hint retains priority.

SQLite failure metadata can distinguish bounded copy/read/local-write/commit/revalidation phases and retain a supported numeric extended code. Missing runtime code remains unknown; no SQL, argument, message text, path or exception string is recorded. A returned physical commit followed by failed revalidation is not described as rollback. This does not establish the root cause of earlier real failures.

Isolated candidate only; daily deployment, original46 real progress and real natural latency are not validated by this release note.

# 0.9.3 — internal registry-reuse candidate

Shared source-bound ordered table lists; complete historical observation retention outside routine registry snapshots; explicit local conversion and confirmed-account setup integration. Existing account/source, per-commit, 128MiB and 500-row priority protections remain. Old writers refuse the new binding. Not deployed or published.

# Walden 0.9.1（隔离修复候选，未部署／未发布）

- 在原1MiB元数据预算内为真实提交后强制再准入和终端回退留足费用；不增加Source时间、打开数、行数或每批500条上限，不跳过来源和存储保护。
- 本版新登记的成员保存受保护的首次复制代次。首批实际复制最新片段，历史前缀仍从0如实推进；已知新消息继续优先，历史和新成员初始化使用原有余量。
- 新分片的暂存归属先持久化、后独占发布；创建前完整预付哈希与见证费用，普通预算不足会延期。未知暂存保留并停止自动重试。已有历史清点证据的缺项不能借当前成员缺失冒充全新登记。
- 已登记目标的表、进度与复制凭证全无时，新增显式单目标确认入口，由原后台授权核验同源后单表补建，不改其他消息。此前覆盖未知永久保留，新水位完成不会抹掉它，也不会把它当成可反复追赶的历史欠账。

仅隔离测试结果不代表当前真实副本历史已恢复，真实运行与下一次日常切换须另行绑定最终制品完成。0.9.0运行回退不理解待初始化和旧覆盖未知语义，须停稳并使用精确完整备份。

# Walden 0.9.0（首次使用与后台 r4 合并候选）

- 确认同一账号、本人身份、同步范围及持续后台同步许可后，统一入口衔接既有凭据验证／获取、受保护本地副本初始化和后台登记。本人仍完成必要登录与系统许可；既有副本/凭据保护和中断续跑保持。
- 合并已审后台 r4：先处理确认的新消息，在同源进度可信且有余量时持续推进已知历史，完整分页继续查漏。保留每批500条、原Source时间及资源上限、热分片公平、每次提交后的强制来源/登记准入，以及可选缓存证据失效时的保守回退。
- 以一个最终安装包交付，不单独部署0.8.12后台输入。该0.9.0对象按目录/hash与早先内部同号候选区分；配置、账号代次、范围和本地进度不得因重复配置或同包重装而重置。

本候选的隔离对照和合成秒数不是实机结果或固定延迟承诺。服务登记、实际健康和历史覆盖分别报告；已有cleanup_pending/媒体失败等未知或未完成状态仍如实保留，不被本项自动改为成功。真实日常切换、受控恢复、重装及资源观察须绑定此同一合并包完成后另行报告；当前不公开发布。

# 0.8.12

在完整有界进度导入与同代来源核对完成后，复用经过提交验证的已知历史队列，余量无需每次等待全部分页结束或最后一个来源。新消息及其变化提示仍优先；已发现的新尾先复制，完整查漏使用后续余量，避免新尾只更新目标却没有复制。每批最多500条且不增加现有资源上限。历史每批前重验当前提示；重启、未知事件、其他进度写入或提交中断回保守路径，完整分页继续查漏，不重置已有水位。

# 0.8.11

共享索引的协调事件继续唤醒保守发现，但不再反复占据新增消息分片的优先队列。数据库和日志的事件仍优先处理，新增或替换的日志会及时进入队列；监听刷新保留未变化的订阅，避免丢失刷新期间的事件。已知新尾债务的优先级、来源校验和每轮读取上限保持原有约束，不预留历史份额。

# 0.8.10

修正终态恢复参数检查的入口归属，恢复正式本地消息查询的配置阶段路径。恢复专用参数只在同步管理入口处理，其他角色仍拒绝不适用的参数。来源与身份校验保持原有约束。

# 0.8.9

增加显式的旧代终态恢复入口：仅在原已授权且已正式撤销的同一账号来源、旧进程及进程组全已退出、登记和配置完整一致时，允许对已确认的特定系统会话标志差异进行收尾。恢复必须绑定撤销前的精确预检记录；同一未完收尾可从已验证的本事务归档继续。旧来源授权保持失效，原证明与历史水位保留；新运行须正式启用新代。来源变化、外来登记或持续无法确认的状态仍拒绝恢复。该入口不自动接受未来上下文变化，不恢复或替换凭据。

# Walden 0.8.8

- 工作段状态快照遇到运行文件原子替换或普通媒体记录变化时，会在原有界限内完整重验；来源、归属与失败保护保持。新增有界脱敏停止诊断，真实失败码和最终停止证明仍如实报告。

- 历史机会只在已验证本地仍有历史欠账的普通分片之间轮转，避免已齐分片空耗稀少的历史补齐机会。
- 欠账候选随原有有界元数据分页收集。接续旧版中段游标或旧写入者留下的候选时，完整重新覆盖后才用于历史选择；消息水位和既有分页进度不重置。
- 新消息仍优先使用全部原有额度，未知或新表仍走原来的发现路径。历史不设保底，不增来源打开数、行数、字节或探测时限，也不承诺固定历史完成时间。

# Walden 0.8.7

- 后台检查运行中工作段状态时，若恰遇同一工作段写入普通轮次元数据，会有限重取完整状态快照。仅同一归属、身份、配置和截止时间且没有新增失败的变化可重取；持续未知或实质冲突仍拒绝。
- 仅在已完成已知尾债务导入且没有已知债务、仍有普通槽位时，独立轮转原有历史Source机会，避免导入分页周期与普通分片轮转锁相。新消息占满额度时，历史继续等待。
- 不延长工作段或消息轮的截止时间，不改变同步预算和新消息优先规则。真实失败和非零退出结果继续保留；此修正不把未知媒体错误或历史覆盖称为已解决。

# Walden 0.8.6

- 修复时间预算耗尽时，尚未实际检查的变化分片被优先游标跳过的问题。变化提示和已发现新消息先使用原有分片额度，普通发现使用剩余额度。
- 仅对已经通过原来源、身份、证明、只读事务及游标检查的消息读取，按可信 SQLite 数值 BUSY/LOCKED 错误确认局部分片暂态。失败分片保留缺口、消息债务及独立有限退避；提示、进程重启和同源代次更换不提前其截止时间。
- 正常分片可以继续原有周期，本轮部分失败仍保留非零 raw 退出码和可见缺口，不变成 healthy 或完整。有限段若最后仍为部分失败，继续如实报告段末失败，不将其改成成功的清理交接。
- 添加固定阶段、异常类别和数值 SQLite/系统错误码诊断。诊断不记录异常正文、参数、SQL、路径、消息或密钥。未知原因、缺少可信错误码、权限、密钥、结构、身份、证明及全局登记故障不享局部隔离，仍按原保护处理。

本版针对前一版实机时效不足进行定向修正；不能把合成回归或驱动错误码能力测试作为本版实机时效通过。四分片、行数、字节、轮次与 SQL 探测上限保持，不保证固定秒数，也不为历史设置抢占新消息的配额。

# Walden 0.8.5

- 账号范围后台同步优先检查发生变化的消息分片和已发现的新消息债务；同一表的新消息也先于历史补齐。持续有新消息时，历史可以延后。
- 数据库、WAL 和 SHM 事件只提供有界的分片提示。读取前仍核对原来源、身份、表结构、只读事务及当前授权；未知或过量提示回到普通检查。
- 发现新消息采用有界元数据探测和可恢复游标。清点尚未完成时不将其当作“没有新消息”，历史和辅助快照等待后续清点；复制未完成时保留已知债务。
- 多个热分片、热表之间轮转，复制期间到达的新事件留待下一轮处理。资源上限和停止、撤销保护保持。

本版调度经过合成定向回归。分片提示和探测尚未覆盖的表、后续分页、未运行的后台或来源不可用都可能增加延迟；不承诺固定同步秒数。历史全量和媒体覆盖不等于已经完成。本说明不将此前版本的实机消息验证或首次取钥结果作为 0.8.5 的新实测。

# Walden 0.8.1

- 首次取钥的受保护诊断确认调试目标在捕获前意外退出时，setup 在原有 `capture_stage_failed` 状态下增加 `failure_reason=target_exited_during_launch`。此信息用于定位失败阶段；具体原因仍需核对同次启动的证据。
- 将账号范围本地登记的容量上限从 64 MiB 调整为 128 MiB。只读快照仍受原有时间限制，账号来源与完整性检查保持。
- 补充[首次取钥排障与复盘](docs/FIRST_KEY_TROUBLESHOOTING.md)，说明如何判断副本签名、系统许可、启动锁、登录、验证保存和清理结果。安装要求和验证环境见[已验证范围](docs/INSTALLATION.md#已验证范围)。

本版隔离安装通过正式命令入口、合成签名和诊断的定向验证。2026-11-17 完成的一次真实首次取钥使用的是 0.8，回执确认配置、凭据验证、保存与清理完成。约 44 秒仅为该次 setup 调用，不包含此前排查和用户操作。0.8.1 未重复实机取钥。旧版说明见对应版本标签。
