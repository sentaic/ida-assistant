# IDA Assistant

[English](README_en.md) | [简体中文](README.md)

Turn IDA Pro into an analysis service that **keeps working for hours and can be shared
safely by several AI agents at once**.

It does not need the IDA GUI open, and it does not need you to babysit it. Point an agent
at a binary, then close the conversation, switch projects, or restart the client — the IDB
still gets built. Come back for the results later.

## Why this exists

Everyone wiring an agent to IDA hits the same wall: **analyzing anything but a toy binary
takes minutes to hours, while MCP requests and conversations have timeouts.**

The usual failure looks like this. The agent calls `open`, the client times out after 30
seconds, the agent retries — and IDA starts over. By the time analysis finally finishes,
the conversation context is gone. Worse, during that retry two IDA processes are fighting
over the same IDB.

IDA Assistant separates *analysis* from *asking questions*:

- **Analysis is a detached background job** that runs outside the client's process tree.
  A client disconnect, a scheduler exit, or a request timeout will not kill it.
- **The IDB is published only after analysis completes.** Until then every query says so
  explicitly instead of handing you a half-finished database.
- **Several agents can share one analysis.** Whoever starts it owns it, everyone else
  reuses it, and only one process can write the IDB at a time.

## Requirements

| Item | Requirement |
| --- | --- |
| OS | Windows (both idalib and the byte-range locking depend on it) |
| IDA | IDA Professional **9.4**, with `idalib` included |
| Python | 3.11 or newer |
| Upstream | [`ida-pro-mcp`](https://github.com/mrexodia/ida-pro-mcp), which provides `ida_pro_mcp` and the idalib entry point |

The project root must live on a Windows filesystem. From WSL, use a path like
`/mnt/c/...`; `/home/...` becomes `\\wsl.localhost\...`, whose locking semantics do not
satisfy the plugin. The scheduler still starts normally and only rejects with
`WSL_LINUX_FILESYSTEM_UNSUPPORTED` when analysis actually begins (`open` or another
operation that needs `.ida` state).

> This plugin contains and distributes no Hex-Rays or IDA code.

## Quick start

```powershell
# 1. Install the upstream dependency in its own environment
uv tool install ida-pro-mcp

# 2. Generate a .mcp.json pointing at this machine
pwsh -File scripts/install.ps1
```

`install.ps1` detects the interpreter, `site-packages` and the IDA directory, then replaces
the placeholders in the template with real paths. If detection gets it wrong, override it
with environment variables:

| Variable | Meaning |
| --- | --- |
| `IDA_ASSISTANT_PYTHON` | The `python.exe` that has `ida-pro-mcp` installed (also used to derive `pythonw.exe` and `site-packages`) |
| `IDA_ASSISTANT_IDA_DIR` | IDA installation directory, default `C:\Program Files\IDA Professional 9.4` |

The generated `.mcp.json` is a local file and is not tracked: **only the template is in the
repository, so personal paths never enter git history.**

## Connecting a client

### stdio (single client, recommended)

The generated `.mcp.json` works with Codex as-is. For other clients, fill in the equivalent
command/args:

```json
{
  "mcpServers": {
    "ida": {
      "command": "<path to pythonw.exe>",
      "args": [
        "<repo path>\\scripts\\ida_lazy_mcp.py",
        "--transport", "stdio",
        "--agent", "my-agent",
        "--worker-command", "<path to python.exe>",
        "--ida-dir", "C:\\Program Files\\IDA Professional 9.4",
        "--pythonpath", "<ida-pro-mcp site-packages>"
      ]
    }
  }
}
```

### HTTP (several clients sharing one scheduler)

```powershell
pwsh -File scripts/start_http.ps1 -ProjectRoot D:\samples\app
```

See `config/codex-http.mcp.json` and `config/pi-http.mcp.json`.

### WSL / pi

`config/pi-stdio.mcp.json` uses `wslpath -w "$PWD"` to convert the current directory into a
Windows path; the rest of the arguments are unchanged. It uses `keep-alive` so client-side
idle reaping cannot interrupt the save of a large IDB.

## Usage

The first call only needs a path:

```text
ida/open(path="bin/app.exe")
```

It **returns immediately**, because the real work runs in the background. Then:

```text
ida/analysis_status()      # read-only state, never touches IDA, instant even when busy
ida/wait_for_analysis()    # only when this particular call genuinely needs to wait
```

Once the state has gone through `launching → queued → analyzing → publishing → ready`, start
asking questions:

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

You no longer need to pass `path` or `session`: the active analysis is isolated per MCP
connection.

### Managing sessions

```text
ida/sessions()                    # all project analyses, workers, errors and quotas
ida/current()                     # which one this connection is using
ida/use(session="app")            # switch to an existing analysis (never creates one)
ida/rename_session(session="app", new_name="app-v2")
ida/close()                       # stop the query worker; the IDB and the job stay
ida/logs(session="app", lines=200)# tail of events, bootstrap and worker stderr
```

### Cancelling analysis

`close` deliberately does not stop the background job. To actually cancel:

```text
ida/abort(session="app", job_id="<from analysis_status>", confirm=true)
```

Passing `job_id` prevents a late-arriving cancel request from killing a newer job that was
started after a retry.

### Editing and Python

Connections are **read-only** by default. Enable what you need explicitly:

```text
ida/set_capabilities(edit=true)      # comments, renames, types, patches
ida/set_capabilities(debug=true)     # debugger actions
ida/set_capabilities(python=true)    # unrestricted IDAPython
```

- `edit` and `debug` still require `confirm=true` on every call.
- `python` is full IDAPython: it can read and write files, make network requests and spawn
  processes. **Enable it only for trusted samples and trusted callers.**
- Capabilities apply **per connection** and do not affect anyone else.

## How it differs from talking to IDA MCP directly

| Scenario | Plain ida-pro-mcp | IDA Assistant |
| --- | --- | --- |
| Large binary | Client times out; a retry starts over | Background job; runs even if the client disconnects |
| Querying a half-built IDB | May return incomplete results | Returns `ANALYSIS_PENDING` explicitly |
| Two agents at once | Two IDA processes fight over one IDB | Share one analysis; writes are serialized |
| Machine reboot / scheduler exit | Analysis is lost | Job survives independently; state lives on disk |
| Where results live | Depends on how you opened it | Always `<project>/.ida/`, portable with the project |

## Tools

| Tool | Purpose |
| --- | --- |
| `open` / `use` / `current` / `sessions` | Submit, select and inspect analyses |
| `analysis_status` / `wait_for_analysis` / `abort` / `close` | Observe and control the background job |
| `rename_session` / `logs` / `health` | Session management and diagnostics |
| `metadata` / `functions` / `function` / `imports` / `strings` | Overview and search |
| `decompile` / `disassemble` / `basic_blocks` | Code-level inspection |
| `xrefs` / `xrefs_from` / `inspect` / `search` / `bytes` | Cross-references and data |
| `set_capabilities` | Enable edit / debug / python per connection |
| `edit` / `query` / `actions` | Long tail: look up names and arguments with `actions` first |
| `python` | Full IDAPython escape hatch |

## Security

- **The HTTP transport has no authentication at all** and binds only to `127.0.0.1`. Do not
  change the bind address and do not expose it to a network.
- **Read-only by default.** The `python` capability hands the machine to the caller; grant
  it with least privilege.
- Do not use this on untrusted samples or on software you are not authorized to analyze.

## Compatibility

Upstream `ida-pro-mcp` has no stable public API. This plugin reads its registry
(`rpc_registry.methods` / `.unsafe`) and re-registers those functions as MCP tools.

**If you see any of the following after upgrading upstream, suspect compatibility first:**

| What upstream changed | Where it breaks | Symptom |
| --- | --- | --- |
| Module or registry structure | Worker startup | Worker will not start; the error mentions `ida_pro_mcp` / `rpc_registry` |
| An action removed or renamed | Calling that action | "unknown tool", naming the missing action |
| An action's parameter names | Calling that action | Parameter validation error listing both the wrong and the expected name |
| **Return structure or semantics** | No error | **Silently wrong results** |

The last row cannot be detected automatically: names and parameters are unchanged, but the
meaning of what comes back is not. So after an upstream upgrade, if a query result looks
wrong and the difference shows up against an older version, that is the first thing to
suspect.

## Troubleshooting

| Symptom | Cause and what to do |
| --- | --- |
| `SOURCE_CHANGED` | The source file changed. Pass `reset_if_changed=true` once you have confirmed you want a rebuild |
| `WSL_LINUX_FILESYSTEM_UNSUPPORTED` | Project root is on the WSL Linux filesystem. Use a Windows path such as `/mnt/c/...` |
| `PERSISTENCE_UNAVAILABLE` | The host Job Object forbids the background job from breaking away. Usually happens when launched under certain terminals |
| `ANALYSIS_PENDING` | Analysis is not finished. Check `analysis_status()`; do not retry queries in a loop |
| Worker will not start, error mentions `rpc_registry` | The upstream `ida-pro-mcp` interface changed; see Compatibility |
| "unknown tool `xxx`" | Upstream removed or renamed that action; see Compatibility |
| `DATABASE_CHANGED` | Something outside this plugin modified the IDB. Check backups, then decide whether to pass `reset_if_changed=true` |
| A query hangs | Queries in one session are serialized; check `ida/sessions()` for a worker that is currently saving |

More error codes and timeout semantics: [docs/internals.md](docs/internals.md) (Chinese).

## Development

```powershell
uv sync
uv run python -m unittest discover -s tests -v
uv run --with ruff ruff check ida_assistant tests
```

The fake tests need no IDA and cover the background job, the publish gate, atomic saves,
scheduler restarts, abort, and worker recovery. The real IDA tests skip automatically when
the installation is missing:

```powershell
$env:IDA_ASSISTANT_IDA_DIR = "C:\Program Files\IDA Professional 9.4"
$env:IDA_ASSISTANT_IDA_MCP_PATH = "$env:APPDATA\uv\tools\ida-pro-mcp\Lib\site-packages"
uv run python -m unittest discover -s tests -v
```

Read [docs/internals.md](docs/internals.md) (Chinese) before changing the code; it explains
the on-disk state and the locking constraints.

## License

MIT, see [LICENSE](LICENSE). This project contains no Hex-Rays or IDA code. "IDA" and
"Hex-Rays" are trademarks of their respective owners.
