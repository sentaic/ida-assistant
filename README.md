# IDA Assistant

[English](README_en.md) | 简体中文

把 IDA Pro 变成一个**能长期干活、又能被多个 AI agent 同时安全使用**的分析服务。

它不需要你打开 IDA 图形界面，也不需要你守着它。你让 agent 去分析一个二进制，然后可以关掉
对话、切换项目、甚至重启客户端——IDB 照样会被建好。回头看结果就行。

## 为什么会有这个项目

直接给 agent 接 IDA 时，每个人都会撞上同一堵墙：**分析一个稍大的二进制要几分钟到几小时，而
MCP 请求和对话有超时**。

常见的失败长这样：agent 调一次 `open`，客户端在 30 秒后超时；重试一次，于是 IDA 又被启动了
一遍；等你终于等到分析结束，对话上下文已经断了。更糟的是第一次失败重试时，两个 IDA 进程正
在抢同一个 IDB。

IDA Assistant 把「分析」和「提问」拆开：

- **分析是一个独立的后台作业**，跑在脱离客户端的进程里，管它等你多久。客户端断开、scheduler
  退出、请求超时，都不会杀掉它。
- **只有完整分析结束后，IDB 才会被发布**。在那之前任何查询都会明确告诉你"还没好"，而不是
  拿一个半成品数据库骗你。
- **多个 agent 可以同时用**。谁先发起就谁负责建库，其他人复用；同一时刻只有一个进程能写同一
  个 IDB。

## 前置条件

| 项目 | 要求 |
| --- | --- |
| 操作系统 | Windows（idalib 与字节范围锁都依赖 Windows） |
| IDA | IDA Professional **9.1**，需要含 `idalib` |
| Python | 3.11 或更高 |
| 上游依赖 | [`ida-pro-mcp`](https://github.com/mrexodia/ida-pro-mcp)，提供 `ida_pro_mcp` 与 idalib 入口 |

项目根目录必须在 Windows 文件系统上。从 WSL 里用时要走 `/mnt/c/...` 这类路径；`/home/...`
会被转成 `\\wsl.localhost\...`，那里的锁语义不满足要求，scheduler 会直接拒绝启动并告诉你原因。

> 本插件不包含、也不分发任何 Hex-Rays 或 IDA 代码。

## 快速开始

```powershell
# 1. 把上游依赖装进独立环境
uv tool install ida-pro-mcp

# 2. 生成指向本机的 .mcp.json
pwsh -File scripts/install.ps1
```

`install.ps1` 会自动探测解释器、`site-packages` 和 IDA 目录，把模板里的占位符替换成真实路径。
如果探测不对，用环境变量覆盖：

| 变量 | 含义 |
| --- | --- |
| `IDA_ASSISTANT_PYTHON` | 装有 `ida-pro-mcp` 的 `python.exe`（据此推导 `pythonw.exe` 与 `site-packages`） |
| `IDA_ASSISTANT_IDA_DIR` | IDA 安装目录，默认 `C:\Program Files\IDA Professional 9.1` |

生成的 `.mcp.json` 是本地文件，不进版本库：**仓库里只有模板，所以个人路径不会进 git 历史。**

## 接到客户端

### stdio（单客户端，推荐）

生成好的 `.mcp.json` 直接给 Codex 用。其他客户端把等价的 command/args 填进去即可：

```json
{
  "mcpServers": {
    "ida": {
      "command": "<pythonw.exe 路径>",
      "args": [
        "<仓库路径>\\scripts\\ida_lazy_mcp.py",
        "--transport", "stdio",
        "--agent", "my-agent",
        "--worker-command", "<python.exe 路径>",
        "--ida-dir", "C:\\Program Files\\IDA Professional 9.1",
        "--pythonpath", "<ida-pro-mcp 的 site-packages>"
      ]
    }
  }
}
```

### HTTP（多客户端共享一个 scheduler）

```powershell
pwsh -File scripts/start_http.ps1 -ProjectRoot D:\samples\app
```

对应配置见 `config/codex-http.mcp.json` 与 `config/pi-http.mcp.json`。

### WSL / pi

`config/pi-stdio.mcp.json` 用 `wslpath -w "$PWD"` 把当前目录转成 Windows 路径，其余参数照常。
它使用 `keep-alive`，避免客户端空闲回收打断大 IDB 的保存。

## 怎么用

第一次调用只需要给一个路径：

```text
ida/open(path="bin/app.exe")
```

它**立刻返回**，因为真正的分析在后台跑。接着：

```text
ida/analysis_status()      # 纯读状态，不碰 IDA，繁忙时也秒回
ida/wait_for_analysis()    # 只在这次调用确实需要等待时才用
```

状态走完 `launching → queued → analyzing → publishing → ready` 之后，开始提问：

```text
ida/metadata()
ida/functions(filter="license")
ida/imports()
ida/strings(filter="api")
ida/function(value="0x140001000")
ida/decompile(address="0x140001000")
ida/disassemble(address="0x140001000")
ida/xrefs(address="0x140001000", kind="callers")
ida/basic_blocks(address="0x140001000")
ida/inspect(kind="segments")
ida/search(query="4D 5A", kind="bytes")
ida/bytes(address="0x140001000", size=64)
```

之后不必再传 `path` 或 `session`：当前活跃分析是按 MCP 连接隔离的。

### 管理会话

```text
ida/sessions()                    # 列出所有项目分析、worker、错误与配额
ida/current()                     # 当前连接在用哪个
ida/use(session="app")            # 切到一个已有分析（不会新建）
ida/rename_session(session="app", new_name="app-v2")
ida/close()                       # 关掉查询 worker，IDB 与后台作业保留
ida/logs(session="app", lines=200)# 事件、bootstrap、worker stderr 的尾部
```

### 取消分析

`close` 不会停后台作业——这是有意的。真要取消：

```text
ida/abort(session="app", job_id="<从 analysis_status 取>", confirm=true)
```

带上 `job_id` 是为了避免一个迟到的取消请求误杀掉重试后的新作业。

### 编辑与 Python

连接默认是**只读**的。需要写入时显式开启对应能力：

```text
ida/set_capabilities(edit=true)      # 允许注释、改名、改类型、打补丁
ida/set_capabilities(debug=true)     # 允许调试器操作
ida/set_capabilities(python=true)    # 允许不受限的 IDAPython
```

- `edit` / `debug` 每次调用仍要带 `confirm=true`。
- `python` 是完整的 IDAPython：能读写文件、发起网络请求、启动进程。**只对可信样本和可信调用方开。**
- 能力是**按连接**生效的，不会影响别人。

## 和「直接接 IDA MCP」的区别

| 场景 | 直接用 ida-pro-mcp | 用 IDA Assistant |
| --- | --- | --- |
| 大二进制分析 | 客户端超时后失败，重试会重头再来 | 后台作业，客户端断开也照跑 |
| 查询半成品 IDB | 可能拿到不完整结果 | 明确返回 `ANALYSIS_PENDING` |
| 两个 agent 同时开工 | 两个 IDA 抢一个 IDB | 复用同一分析，写操作串行 |
| 机器重启 / scheduler 退出 | 分析丢失 | 作业独立存活，状态在磁盘上 |
| 分析结果存放 | 取决于你怎么开 | 固定在 `<项目>/.ida/`，可随项目迁移 |

## 工具一览

| 工具 | 作用 |
| --- | --- |
| `open` / `use` / `current` / `sessions` | 提交、选择、查看分析 |
| `analysis_status` / `wait_for_analysis` / `abort` / `close` | 观测与控制后台作业 |
| `rename_session` / `logs` / `health` | 管理与会话诊断 |
| `metadata` / `functions` / `function` / `imports` / `strings` | 概览与检索 |
| `decompile` / `disassemble` / `basic_blocks` | 代码级查看 |
| `xrefs` / `xrefs_from` / `inspect` / `search` / `bytes` | 交叉引用与数据 |
| `set_capabilities` | 按连接开启 edit / debug / python |
| `edit` / `query` / `actions` | 长尾能力：先用 `actions` 查名字与参数，再调用 |
| `python` | 完整 IDAPython 逃生口 |

## 安全须知

- **HTTP transport 没有任何认证**，只绑定 `127.0.0.1`。不要改绑定地址，不要暴露到网络。
- **默认只读**。`python` 能力等于把机器交给调用方，按最小权限开启。
- 不要用它分析不可信样本，也不要用于未授权软件。

## 兼容性

上游 `ida-pro-mcp` 没有稳定的公开接口。本插件要读它的注册表（`rpc_registry.methods` /
`.unsafe`），并把里面的函数重新注册成 MCP 工具。

**升级上游后如果出现下面这些症状，先怀疑兼容性：**

| 上游改了什么 | 在哪里爆发 | 症状 |
| --- | --- | --- |
| 模块或注册表结构被改 | worker 启动时 | worker 起不来，报错里带 `ida_pro_mcp` / `rpc_registry` |
| 某个 action 被删或改名 | 调用那个 action 时 | 报 unknown tool，名字就是缺的那个 |
| 某 action 的参数名被改 | 调用那个 action 时 | 参数校验报错，会同时列出错名与期望名 |
| **返回结构或语义变了** | 不报错 | **静默给出错误结果** |

最后一行无法自动发现：名字和参数都没变，但返回的东西意思变了。所以升级上游后，如果一个
查询的结果看着不对、且差异是相对旧版比较出来的，这是首要嫌疑。

## 排错

| 症状 | 原因与处理 |
| --- | --- |
| `SOURCE_CHANGED` | 源文件内容变了。确认要重建后传 `reset_if_changed=true` |
| `WSL_LINUX_FILESYSTEM_UNSUPPORTED` | 项目根落在 WSL Linux 文件系统。换成 `/mnt/c/...` 这类 Windows 路径 |
| `PERSISTENCE_UNAVAILABLE` | 宿主 Job Object 禁止后台作业脱离。多发生在被某些终端托管的场景 |
| `ANALYSIS_PENDING` | 分析还没结束。看 `analysis_status()`，不要循环重试查询 |
| worker 起不来，报错含 `rpc_registry` | 上游 `ida-pro-mcp` 接口变了，见「兼容性」 |
| 报 unknown tool `xxx` | 上游删了或改名了那个 action，见「兼容性」 |
| `DATABASE_CHANGED` | IDB 被插件之外的东西改过。检查备份后决定是否 `reset_if_changed=true` |
| 查询卡住 | 同一 session 的查询串行；先 `ida/sessions()` 看是否有 worker 正在保存 |

更多故障码与超时语义见 [内部实现](docs/internals.md)。

## 开发

```powershell
uv sync
uv run python -m unittest discover -s tests -v
uv run --with ruff ruff check ida_assistant tests
```

不需要 IDA 就能跑的是 fake 测试（覆盖后台作业、发布门禁、原子保存、scheduler 重启、abort 与
worker 恢复）。真实 IDA 测试会在缺少安装时自动 skip：

```powershell
$env:IDA_ASSISTANT_IDA_DIR = "C:\Program Files\IDA Professional 9.1"
$env:IDA_ASSISTANT_IDA_MCP_PATH = "$env:APPDATA\uv\tools\ida-pro-mcp\Lib\site-packages"
uv run python -m unittest discover -s tests -v
```

改代码前建议先读 [docs/internals.md](docs/internals.md)，那里解释了磁盘状态与锁的约束。

## 许可证

MIT，见 [LICENSE](LICENSE)。本项目不包含任何 Hex-Rays 或 IDA 代码；"IDA" 与 "Hex-Rays" 是
各自所有者的商标。
