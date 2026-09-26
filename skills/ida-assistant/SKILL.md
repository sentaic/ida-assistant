---
name: ida-assistant
description: Reverse engineer binaries or IDBs with the project-scoped IDA Pro 9.4 MCP service, including persistent full autoanalysis, decompilation, xrefs, searches, controlled edits, debugging, and IDAPython.
---

# IDA Assistant

Use this service for IDA-backed analysis. Project state lives under the current project's `.ida`
directory. Tool names here use `ida/tool`; Pi with `directTools=false` exposes `ida_tool`, while
Codex routes the same operation as `mcp__ida__tool`.

## Open and wait

Call `ida/open(path)` once. For a raw binary it submits a detached job that waits for complete IDA
autoanalysis and atomically publishes the final IDB. `open` returns after a short persistence
handshake; stdio disconnects, scheduler shutdown, and MCP request timeouts do not stop that job.

The legacy `wait_for_analysis` argument on `open` is retained only for schema compatibility. Do not
use it: open is non-blocking and managed jobs always complete analysis before publication.

Before ready, normal analysis tools return `ANALYSIS_PENDING`; do not retry them in a loop. Use
`ida/analysis_status()` for a non-blocking persistent-state snapshot. Call
`ida/wait_for_analysis()` only when this request genuinely needs to wait. Cancelling or timing out
that wait does not cancel the job.

Use `ida/use(session=...)` or `ida/use(path=...)` to select an existing analysis without creating
one. The active selection is scoped to the MCP connection. Use `ida/current()` when uncertain and
`ida/sessions()` for project inventory.

Existing project IDBs created by an earlier plugin version are reused as `legacy_ready`; existing
external `.i64`/`.idb` files are opened directly. Their analysis completeness is unknown, and
saving edits to an external IDB modifies that file. If a raw source fingerprint changed, inspect
the situation and pass `reset_if_changed=true` only when replacing the project analysis is intended.

## Build evidence

After ready, start with `ida/metadata()`, then use small pages from `ida/imports()`, `ida/strings()`,
and `ida/functions()`. Resolve candidates with `ida/function()`, and examine them with
`ida/decompile()`, `ida/disassemble()`, `ida/xrefs()`, `ida/basic_blocks()`, and `ida/xrefs_from()`.

Use `ida/inspect()` for segments, entries, or exports. Use `ida/search()` for raw byte patterns or
encoded text; UTF-16LE is often necessary for Windows strings not defined as IDA string items. Use
`ida/bytes()` to corroborate important claims. Treat decompiler output as derived evidence: cite
relevant addresses and cross-check material behavior with disassembly, xrefs, imports, strings, or
bytes.

## Discover long-tail capabilities

Prefer named high-frequency tools. For other structured IDA operations:

1. Call `ida/actions(plane="read", filter=...)` for supported names, signatures, descriptions, and
   argument schemas.
2. Call `ida/query(action, arguments)` only with a returned read action; do not guess names or keys.
3. For edits or debugger operations, inspect the matching plane, enable only that connection
   capability, then call `ida/edit(..., confirm=true)`.
4. Use `ida/python()` when the catalog has no suitable operation or direct IDAPython is materially
   clearer.

The catalog covers globals, local types, stack frames, structures, typed reads, field xrefs,
comments, renames, type changes, patches, and debugger actions. It is the authoritative structured
surface for the installed adapter, not a one-to-one map of every IDA GUI command.

## Capabilities and IDAPython

Connections start with `edit=false`, `python=false`, and `debug=false` unless the scheduler uses
`--unsafe`. Change only this connection with `ida/set_capabilities()` and disable capabilities no
longer needed.

- `edit` permits cataloged edits through `ida/edit(..., confirm=true)`.
- `debug` permits cataloged debugger actions, but headless debugging still requires a valid target
  and debugger configuration.
- `python` permits unrestricted `ida/python()` calls. It can edit, debug, access files, or launch
  processes and is not a sandbox.

For `ida/python()`, provide exactly one of inline `code` or a `script` path and assign the returned
value to global `result`. Keep reusable scripts as normal project files and prefer project-relative
paths so Windows Codex and WSL pi resolve the same artifact. Do not retry a timed-out script whose
side effects are uncertain.

## Parallel work and lifecycle

Use separate MCP connections for separate logical agents. Partition different binaries across
sessions; project-wide slot locks bound concurrent detached analyses across Codex, pi, and multiple
schedulers. Calls to one ready IDB serialize, and query workers share the IDB lock with analysis
jobs. Worker cold starts are briefly serialized because concurrent idalib initialization
can hang.

`ida/close()` stops the interactive query worker but never the detached analysis job. Scheduler
shutdown behaves the same. Do not duplicate sessions or IDBs to work around serialization.

Close defaults to `save=null`: save only if an edit/debug action or Python execution marked the
worker dirty. Merely enabling capabilities does not mark it dirty. Any Python execution may mutate
the IDB, even on error, so it is conservatively saved. `save=false` explicitly discards in-memory
edits; `save=true` explicitly saves. Ordinary reads and idle reaping do not rewrite clean IDBs.
Saves use a temporary IDB and atomic replacement after successful close; failed candidates remain
available briefly for recovery. Managed databases retain only the newest failed-save family and
newest orphan family for at most 24 hours, removed at the next eligible cleanup. Successful saves
remove existing recovery leftovers. Cleanup runs under IDB ownership before open, after worker
exit, and every three hours for registered managed databases; active workers are skipped. The
periodic scan reuses the existing async reaper with a monotonic deadline and performs no directory
scans between deadlines. Worker idle eviction is unchanged. Manual backups
and external IDBs are excluded. Saving needs space for both databases and IDA's unpacked files.

`call-timeout` applies to query/edit/Python calls, not full analysis. `analysis-timeout` is separate
and defaults to unlimited. Cancellation or timeout is not rollback: the worker drains the original
call under the IDB lock, then closes. Do not retry side effects. `WORKER_DRAINING` means the old worker
still owns the database; other sessions can proceed. A non-save call may be terminated after the
900-second `drain-timeout`. Save/close never uses that kill deadline. `flush-timeout` defaults to
unlimited; a finite value limits the close response, not the save. `shutdown-timeout` applies only
after close completes. pi should keep this MCP alive rather than applying a short idle timeout.
If OS termination of a stalled ordinary call fails, cleanup retains the IDB lock and retries until
the worker exits; a termination error is never treated as proof of exit.

Managed IDBs are fingerprinted at publication/save and checked before reopen. Orphan unpacked
files are quarantined under the session lock and follow the retention policy above. Opening verifies the selected IDB and
samples executable PE mappings. `DATABASE_CHANGED` or `DATABASE_INTEGRITY_FAILED` requires inspecting
recovery evidence or explicitly rebuilding with `open(..., reset_if_changed=true)`; do not silently
replace the database. Legacy IDBs lack a historical fingerprint, and sampling does not certify a
suspect database. `bytes`/`read_memory_bytes` report `UNLOADED_RANGE` rather than synthetic FF data;
they do not silently substitute bytes from the source file.

## Diagnose and abort

`ida/analysis_status(session=...)` is always the first check. It reads the persistent job protocol
without starting idalib. Important phases are `launching`, `queued`, `analyzing`, `publishing`,
`ready`, `failed`, `aborted`, and recovered `interrupted`.

Use `ida/logs(session)` when the error is unclear. To stop an active analysis, copy its current
`job_id` from status and call:

```text
ida/abort(session=..., job_id=..., confirm=true)
```

Passing the job ID fences delayed cancellation against a newer retry. Abort validates the lifecycle
lock owner and named Windows Job Object; it never kills solely by a recorded PID. A completed
publication can win the race, in which case abort returns without deleting the final IDB.

After `failed` or `aborted`, a deliberate new `ida/open(path)` submits a new generation. Ordinary
queries never restart analysis implicitly. On `SOURCE_READ_FAILED`, report the source access
problem; do not silently copy the sample, elevate privileges, terminate unrelated processes, or
substitute another path.

Do not execute untrusted samples or expose the unauthenticated HTTP transport beyond localhost.
