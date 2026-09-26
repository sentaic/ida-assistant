# 内部实现

本文面向要改这个插件的人，描述磁盘状态布局、状态机、跨进程锁、超时与数据库完整性
策略。只想使用的话看 [README](../README.md) 就够。

## 核心工作流

```text
open(path) ──快速返回──> launching / queued / analyzing
                              │
                              ├─ analysis_status() 纯读状态
                              ├─ wait_for_analysis() 异步等待；取消调用不取消作业
                              └─ abort(job_id, confirm=true) 精确取消
                                      │
完整 autoanalysis ──原子发布 IDB──> ready ──> metadata/functions/decompile/...
```

新原始二进制的默认行为始终是完整分析。旧参数 `wait_for_analysis` 为 schema 兼容而保留，
不再决定 `open` 是否阻塞，也不应再传它。IDB 发布前，普通查询立即返回
`ANALYSIS_PENDING`，不会隐式启动 idalib 或把半成品数据库暴露给调用方。

典型调用：

```text
ida/open(path="bin/app.exe")
ida/analysis_status()
ida/wait_for_analysis()       # 仅当本次调用确实需要等待
ida/metadata()
ida/strings(filter="license")
ida/decompile(address="0x140001000")
```

`analysis_status` 不调用 IDA，因而在分析繁忙时也能快速响应。`wait_for_analysis` 只异步
轮询持久状态；客户端取消或超时不会杀后台作业。`close` 只保存/关闭交互式查询 worker，
不会终止后台分析。需要取消时先从状态中取当前 `job_id`，再调用：

```text
ida/abort(session="app", job_id="...", confirm=true)
```

传 `job_id` 可避免延迟到达的旧取消请求误杀重试后的新作业。

## 磁盘状态与原子发布

所有托管状态位于项目目录：

```text
<project>/.ida/
  registry.lock
  renames.json
  analysis-slots/slot-N.lock
  databases/<session>/
    database.json
    <session>.i64
    <session>.<job_id>.staging.i64
    worker.lock
  sessions/<session>/
    analysis-job.json
    analysis-job.lock
    job-launch.lock
    analysis-abort.<job_id>
    events.jsonl
    bootstrap.log
    worker.stderr.log
    ida-user/
```

`database.json` 与 `analysis-job.json` 中由插件管理的 IDB、staging 路径相对 `.ida`
保存，因此整个 `.ida` 目录可以随项目迁移。原始样本路径和外部 `.i64`/`.idb` 属于项目
资产，仍保存为绝对路径。读取端继续兼容旧版绝对托管路径，并在旧位置失效时从当前
session 目录恢复对应数据库。

状态机为 `launching → queued → analyzing → publishing → ready`，失败终态为 `failed` 或
`aborted`。状态 JSON 通过临时文件加 `os.replace` 发布；每代作业使用唯一 staging 名，
并在分析前、发布前各校验一次源指纹。只有完整 staging 成功替换 final 后才报告 ready。

升级前已经存在的托管 IDB 若没有 `analysis-job.json`，按 `legacy_ready` 复用，避免自动
重建导致人工注释、类型或补丁丢失；其完整性标记为 `legacy_unknown`。外部 `.i64/.idb`
仍直接打开，保存编辑会修改外部数据库，完整性标记为 `external_unknown`。

源内容改变时返回 `SOURCE_CHANGED`。只有明确传 `reset_if_changed=true` 才提交新 generation；
旧 final 在新 IDB 原子发布前保留，但状态门禁不会让查询误用旧 generation。

## 进程生命周期与并发

后台 runner 自己长期持有 `analysis-job.lock`，执行 IDA 时再持有 session 的 `worker.lock`；
查询 worker 也使用同一 `worker.lock`，因此分析与查询不会同时写一个 IDB。项目级 numbered
slot locks 让 `--max-workers` 对 Codex、pi 和多个 scheduler 启动的后台作业同样生效；额外
作业停在 queued，不会绕过进程内 semaphore 无界启动 IDA。

Windows scheduler 用 `CREATE_BREAKAWAY_FROM_JOB` 脱离带 kill-on-close 的宿主 Job（仅在
宿主明确允许时），并将 stdin/stdout/stderr 全部指向空设备。runner 随后创建自己的命名
Job Object，设置 `KILL_ON_JOB_CLOSE` 并把自身及 IDA 子孙纳入其中。这样 scheduler 退出不
影响分析，而 runner 崩溃或被取消时系统会清理完整 IDA 进程树。如果宿主禁止 breakaway，
`open` 明确返回 `PERSISTENCE_UNAVAILABLE`，不会退化成伪持久模式。

`abort` 以 job-id 专属 marker 发出请求，并只在 lifecycle lock owner 与 job_id 匹配时终止
命名 Job Object；PID 只作诊断，绝不单独作为杀进程依据。

不同 session 的分析/查询可并行；同一 session 的查询串行。worker 冷启动短暂串行化，
规避 idalib 同时初始化多个实例可能挂起的问题。stdio 断开时交互 worker 会退出，
持久分析 runner 不退出。

## 超时

- `--startup-timeout`：持久 runner 或 idalib worker 的启动握手上限。
- `--call-timeout`：单个查询、编辑或 Python 调用及 session 排队上限。
- `--analysis-timeout`：独立的完整分析上限；默认 `0` 表示无限。
- `--flush-timeout`：显式 close 的响应等待上限，默认 `0` 表示无限；超时后保存继续，
  worker 与 IDB 锁交给后台收尾，绝不因此强杀保存进程。
- `--drain-timeout`：已取消或超时的普通调用的收尾期限，默认 900 秒；到期才终止仍阻塞的
  普通调用。进入 close/save 后不再使用该期限。
- `--shutdown-timeout`：close 完成后的进程退出与 abort 清理确认上限，默认 10 秒。

分析不再使用 `call-timeout`。因此 MCP 的 300 秒请求截止不会截断数分钟或数小时的完整
自动分析；只需让 `open` 的短握手和普通查询落在客户端截止内。

Codex/pi 示例用 270 秒 `call-timeout`，pi MCP 请求截止为 300 秒。客户端提前取消或
超时不等于回滚，也不会重放原调用。该 worker 退出前 session 返回 `WORKER_DRAINING`
或锁忙；同库跨 scheduler 的互斥锁保持占用。其他 session 可继续工作。保存期间显式
abort/force-stop 同样拒绝执行。宿主强行终止整个进程树或系统断电不受此等待策略控制。
若操作系统终止普通阻塞调用失败，收尾继续持有 IDB 锁并重试关闭，直到 worker 退出。

## 数据库保存与完整性

`close(save=None)` 和空闲回收默认只保存脏库；`save=false` 丢弃当前内存编辑，
`save=true` 显式强制保存。编辑及调试 action 在执行前置脏；任何已获授权的 Python
执行都保守置脏，执行中抛异常也不清除。仅开启能力不会置脏。只读查询关闭调用
`close_database(False)`，因此 60 秒 worker 空闲回收不再反复重写大 IDB。

保存先写同目录唯一 `.save-<id>.i64`，成功关闭并刷新后原子替换正式库；失败保留旧库及
恢复候选。IDA 9.4 的 `DBFL_COMP` 是垃圾整理标志。磁盘需容纳旧库、候选库和 IDA 展开
文件；该操作可能很慢，不能用退出进程的 10 秒预算限制它。

新发布和正常编辑保存后记录 IDB 的 size、mtime_ns 与抽样指纹。再次开库前在 session
锁内比较；不匹配报 `DATABASE_CHANGED`。托管库残留 `.id0/.id1/.id2/.nam/.til` 在锁内
移入同目录 `orphan-<id>/` 留作恢复，再从正式 IDB 开库；外部 IDB 的派生文件不自动移动。
托管库的失败保存候选（含同名展开文件）和 `orphan-*` 各保留最新一组，最多保留 24 小时；
更旧的组在下一次清理时删除。成功保存后清除已有恢复残留。清理在持锁的开库前、worker
退出后执行，并每 3 小时检查一次本项目已登记托管库；关闭的 session 也会清理，忙碌的库跳过。
周期检查复用现有 `asyncio.sleep()` 回收任务，用单调时钟判断 3 小时截止，未到期不扫描目录，
不额外启动线程或进程。worker 的 60 秒空闲回收不变。24 小时是过期阈值，实际删除等到
下一次检查，忙碌或停机可进一步推迟。scheduler 停止时
不会另起清理进程，到下次启动后继续。仅识别插件生成的确切文件名，不跟随目录链接，
不递归删除含未知文件的目录。删除失败留待后续重试，不使正常关闭失败。外部 IDB 及
手动 `.ida/recovery/` 备份不纳入此策略。
开库后校验实际数据库路径、地址空间和段数量，并对 PE 文件支持的可执行区抽样检查段、
已加载字节和文件偏移映射。Hex-Rays 初始化不再依赖重新运行自动分析；没有对应反编译器
的处理器仍可使用普通查询。

校验失败拒绝查询，不自动重建或覆盖人工编辑。检查备份/候选后可显式
`open(path, reset_if_changed=true)` 重建托管库。旧库没有历史发布指纹，抽样探针也不是
全库正确性的证明，不能据此把已疑似损坏的库认证为可信基线。`bytes` 和
`query(read_memory_bytes)` 对未加载区间返回 `UNLOADED_RANGE`，合法的 `FF` 字节照常返回；
不会静默用磁盘数据替换 IDB 视图。

## Session、路径与能力

- `open(path, session=None)`：创建或复用路径对应的 session，提交/复用后台作业并激活。
- `use(session=...)` / `use(path=...)`：只激活已有分析，可在 pending 时使用。
- `current()` / `sessions()` / `analysis_status()` / `logs()`：纯管理与观测。
- `rename_session()`：只允许 job 非活跃时改名。
- `close()`：关闭交互 worker，保留 IDB 和后台 job。

当前 session 按 MCP 协议连接隔离。高频工具省略 session/path；独立逻辑 agent 应使用独立
MCP 连接。服务直接读取源文件，不复制、硬链接或符号链接；读取失败返回
`SOURCE_READ_FAILED`。

连接默认 `edit=false, python=false, debug=false`。用 `set_capabilities` 只为当前连接启用
所需能力；`edit` 每次仍要求 `confirm=true`。`python` 是不受限 IDAPython，可编辑、调试、
访问文件或启动进程。

常用工具包括 `metadata`、`functions`、`function`、`imports`、`strings`、`decompile`、
`disassemble`、`xrefs`、`basic_blocks`、`xrefs_from`、`inspect`、`search`、`bytes`。长尾能力
先用 `actions(plane=..., filter=...)` 查询准确 action/schema，再调用 `query` 或 `edit`；未知
上游 action 默认拒绝。`python` 是完整能力逃生口，并不表示每个 IDA GUI 命令都已单独映射。


## 上游绑定

上游 `ida-pro-mcp` 没有稳定的公开接口。本插件与它的接触点有五个，性质上有一个共同点：
**它们不是上游承诺的公开 API，而是上游自己 `idalib_server.main()` 内部也在用的东西。**上游
重构自己的 CLI 时很可能顺手改掉它们。

| 接触点 | 用途 |
| --- | --- |
| 模块路径 `ida_pro_mcp.mcp-plugin` | `importlib` 动态导入 |
| 模块级单例 `idalib_server.mcp` | 在它上面 `add_tool` |
| `rpc_registry.methods` / `.unsafe` | 枚举 action、注册工具、标记 unsafe |
| 八个路由 action 的参数名 | `server.py` 里的硬编码调用 |
| `actions.py` 里的 action 名清单 | 白名单与路由声明 |

接触点虽多，但全部收敛在 `idalib_worker.py` 与 `actions.py` 两个文件里，所以上游大改的代价是
局部可修，而不是重写。

**没有运行时兼容性检查。** 注册表结构变了，`_register_upstream()` 会在 import 期以
`AttributeError` 失败；某个 action 没了，那个工具只是不会被注册，调用时报 unknown tool。两种
情况的报错都已足够定位，所以不再额外校验，也不校验各 action 的参数名（FastMCP 的参数校验会
给出更具体的信息）。用户侧的症状对照见 [README 的兼容性一节](../README.md#兼容性)。

唯一无法自动发现的是**返回语义变化**：名字与参数都没变，但结果的意思变了。这类只能靠升级后
与旧结果对比。

## CLI## CLI

```text
python scripts/ida_lazy_mcp.py
  --transport stdio|streamable-http
  --agent NAME
  --project-root WINDOWS_PATH
  --worker-command WINDOWS_PYTHON_EXE
  --ida-dir "C:\Program Files\IDA Professional 9.4"
  --pythonpath IDA_PRO_MCP_SITE_PACKAGES
  --max-sessions 8 --max-workers 3
  --worker-idle-seconds 60 --session-idle-seconds 900
  --startup-timeout 270 --call-timeout 270
  --analysis-timeout 0 --flush-timeout 0 --drain-timeout 900 --shutdown-timeout 10
  --unsafe
```

CLI 是唯一配置来源，不读取插件私有环境变量。

## 配置模板

仓库只跟踪模板，本机生成的配置不进版本库：

| 模板 | 生成方式 |
| --- | --- |
| `.mcp.json.template` | `scripts/install.ps1` 替换 `${IDA_ASSISTANT_*}` 后写出 `.mcp.json` |
| `config/pi-stdio.mcp.json` | 手工替换占位符（WSL pi 用） |
| `config/codex-http.mcp.json`、`config/pi-http.mcp.json` | 只含 `127.0.0.1` URL，通常无需修改 |

## 测试

```powershell
uv sync
uv run python -m unittest discover -s tests -v
uv run --with ruff ruff check ida_assistant tests
```

fake 测试覆盖完整后台分析、ready 门禁、原子发布、scheduler 重启、job-id abort/retry、旧
IDB 兼容与交互 worker 恢复，不需要 IDA 即可运行。真实测试使用 Windows `where.exe`，验证
stdio scheduler 的非阻塞 open、完整分析后查询以及 IDA 9.4 的实际 idalib 能力；缺少 IDA
或上游依赖时会自动 skip，也可用 `IDA_ASSISTANT_IDA_DIR` 与 `IDA_ASSISTANT_IDA_MCP_PATH`
指向本机安装。

## 验证组合

| 组件 | 验证版本 |
| --- | --- |
| IDA Professional | 9.4 |
| `ida-pro-mcp` | 1.4.0 |
| `mcp` | 1.27 – 1.29 |

