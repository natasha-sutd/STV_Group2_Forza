"""
Generic subprocess runner for fuzzing targets.
Reads ALL target-specific behaviour from a YAML config — no hardcoded target logic.
"""

import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import json
from dataclasses import dataclass, field
from pathlib import Path, PureWindowsPath
from typing import Any

import yaml


def get_platform() -> str:
    system = platform.system()
    if system == "Linux":
        return "linux"
    elif system == "Darwin":
        return "mac"
    else:
        return "windows"


def windows_to_wsl(win_path: str) -> str:
    p = PureWindowsPath(win_path)
    drive = p.drive.rstrip(":").lower()
    parts = p.parts[1:]  # skip root
    posix_parts = "/".join(part.replace("\\", "/") for part in parts)
    return f"/mnt/{drive}/{posix_parts}"


def resolve_binary_path(binary_path: str, use_wsl: bool = False) -> list[str]:
    use_wsl = use_wsl or bool(os.environ.get("FUZZER_USE_WSL"))
    current_platform = get_platform()

    # Commands that are already shell-entry points should not be rewritten.
    if binary_path.lower() in {"wsl", "bash", "cmd", "powershell", "pwsh"}:
        return [binary_path]

    if current_platform == "windows" and use_wsl:
        return ["wsl", windows_to_wsl(binary_path)]

    return [binary_path]


def resolve_binary_for_platform(binary_config) -> str:
    if isinstance(binary_config, dict):
        current = get_platform()
        if current not in binary_config:
            raise ValueError(
                f"No binary configured for platform '{current}'. "
                f"Available: {list(binary_config.keys())}"
            )
        return binary_config[current]
    return binary_config


@dataclass
class RawResult:
    """output of target_runner.py, input to oracle.py"""

    stdout: str
    stderr: str
    returncode: int
    timed_out: bool
    crashed: bool
    error: str | None
    strategy: str | None = None
    input_data: bytes = field(default_factory=bytes)


# helper functions


def _inject_input(cmd_template: list[str], replacement: str) -> list[str]:
    return [part.replace("{input}", replacement) for part in cmd_template]


def _make_error_result(e: Exception, input_bytes: bytes) -> RawResult:
    return RawResult(
        stdout="",
        stderr="",
        returncode=-1,
        timed_out=False,
        crashed=True,
        error=str(e),
        input_data=input_bytes,
    )


def resolve_cmd(cmd: list[str]) -> list[str]:
    if cmd[0] in ("python", "python3"):
        return [sys.executable] + cmd[1:]
    resolved = shutil.which(cmd[0])
    if resolved:
        return [resolved] + cmd[1:]
    return cmd


def _prepare_run_command(
    cmd_template: list[str],
    input_str: str,
    input_mode: str,
    use_wsl: bool,
    extra_flags: list[str] | None = None,
) -> tuple[list[str], bytes | None, str | None]:
    input_bytes = input_str.encode(errors="replace")
    tmp_file: str | None = None
    stdin_data: bytes | None = None

    if input_mode == "file":
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
        tmp.write(input_str)
        tmp.close()
        tmp_file = tmp.name
        cmd = _inject_input(cmd_template, tmp_file)
    elif input_mode == "stdin":
        cmd = list(cmd_template)
        stdin_data = input_bytes
    else:
        cmd = _inject_input(cmd_template, input_str)

    binary_prefix = resolve_binary_path(cmd[0], use_wsl=use_wsl)
    cmd = binary_prefix + cmd[1:]

    if extra_flags:
        cmd += extra_flags

    cmd = resolve_cmd(cmd)
    return cmd, stdin_data, tmp_file


def run_target(
    cmd_template: list[str],
    input_str: str,
    input_mode: str = "arg",
    cwd: str | None = None,
    timeout: int = 5,
    use_wsl: bool = False,
    extra_flags: list[str] | None = None,
) -> RawResult:
    input_bytes = input_str.encode(errors="replace")
    tmp_file: str | None = None
    cmd: list[str] = []

    try:
        cmd, stdin_data, tmp_file = _prepare_run_command(
            cmd_template=cmd_template,
            input_str=input_str,
            input_mode=input_mode,
            use_wsl=use_wsl,
            extra_flags=extra_flags,
        )

        proc = subprocess.run(
            cmd,
            input=stdin_data,
            capture_output=True,
            timeout=timeout,
            cwd=cwd or None,
        )

        return RawResult(
            stdout=proc.stdout.decode(errors="replace"),
            stderr=proc.stderr.decode(errors="replace"),
            returncode=proc.returncode,
            timed_out=False,
            crashed=proc.returncode < 0,
            error=None,
            input_data=input_bytes,
        )

    except subprocess.TimeoutExpired:
        return RawResult(
            stdout="",
            stderr="",
            returncode=-1,
            timed_out=True,
            crashed=False,
            error="timeout",
            input_data=input_bytes,
        )

    except FileNotFoundError as e:
        missing_binary = cmd[0] if cmd else (cmd_template[0] if cmd_template else "<unknown>")
        raise RuntimeError(
            f"Binary not found: {missing_binary}\n"
            f"Check the binary path in your YAML config.\n"
            f"Original error: {e}"
        )

    except Exception as e:
        return _make_error_result(e, input_bytes)

    finally:
        if tmp_file and os.path.exists(tmp_file):
            os.remove(tmp_file)


def _parse_coverage_report_to_summary(report_text: str) -> str:
    """
    Parse the TOTAL line from a 'coverage report' table and emit the summary
    lines that _extract_coverage_percentages regex-matches against:

        line coverage     : 63.16%
        branch coverage   : 37.68%
        combined coverage : 50.00%

    Coverage report TOTAL line format (--branch mode):
        TOTAL   323   204   138   86   37%
    columns: Name Stmts Miss Branch BrPart Cover
    """
    for line in report_text.splitlines():
        parts = line.split()
        if not parts or parts[0].upper() != "TOTAL":
            continue
        try:
            if len(parts) >= 6:
                # branch mode: TOTAL stmts miss branch brpart cover%
                stmts = int(parts[1])
                miss_stmts = int(parts[2])
                branches = int(parts[3])
                br_part = int(parts[4])
                covered_stmts = stmts - miss_stmts
                covered_branches = br_part  # BrPart = partially/fully covered

                line_pct = (covered_stmts / stmts * 100) if stmts else 0.0
                branch_pct = (covered_branches / branches * 100) if branches else 0.0
                combined_pct = (
                    ((covered_stmts + covered_branches) / (stmts + branches) * 100)
                    if (stmts + branches)
                    else 0.0
                )

                return (
                    f"line coverage     : {line_pct:.2f}%\n"
                    f"branch coverage   : {branch_pct:.2f}%\n"
                    f"combined coverage : {combined_pct:.2f}%\n"
                )
            elif len(parts) >= 4:
                # no-branch mode: TOTAL stmts miss cover%
                stmts = int(parts[1])
                miss_stmts = int(parts[2])
                covered_stmts = stmts - miss_stmts
                line_pct = (covered_stmts / stmts * 100) if stmts else 0.0
                return (
                    f"line coverage     : {line_pct:.2f}%\n"
                    f"branch coverage   : {line_pct:.2f}%\n"
                    f"combined coverage : {line_pct:.2f}%\n"
                )
        except (ValueError, ZeroDivisionError):
            continue
    return ""



def run_reference_with_coverage(
    cmd_template: list[str],
    input_str: str,
    input_mode: str,
    cwd: str | None,
    timeout: int,
    use_wsl: bool,
) -> RawResult:
    """
    'coverage run' a plain Python reference script under, then immediately
    call 'coverage report' and append its output to stdout so that
    _extract_coverage_percentages in coverage_tracker.py can parse the real
    statement/branch/combined percentages.
    """
    import uuid

    python_interpreters = {"python", "python3", "py"}
    rest = (
        cmd_template[1:]
        if cmd_template[0].lower().split(os.sep)[-1].split(".")[0]
        in python_interpreters
        else cmd_template
    )

    data_file = f".coverage_{uuid.uuid4().hex[:8]}"
    cov_run_cmd = [
        sys.executable,
        "-m",
        "coverage",
        "run",
        "--branch",
        f"--data-file={data_file}",
    ] + rest

    run_result = run_target(
        cmd_template=cov_run_cmd,
        input_str=input_str,
        input_mode=input_mode,
        cwd=cwd,
        timeout=timeout,
        use_wsl=use_wsl,
    )

    try:
        report_proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "coverage",
                "report",
                f"--data-file={data_file}",
                "--precision=2",
                "-m",
            ],
            capture_output=True,
            timeout=15,
            cwd=cwd or None,
        )
        report_out = report_proc.stdout.decode(errors="replace")

        cov_lines = _parse_coverage_report_to_summary(report_out)

        try:
            cleanup_path = Path(cwd or ".") / data_file
            if cleanup_path.exists():
                cleanup_path.unlink()
        except OSError:
            pass

        run_result = RawResult(
            stdout=run_result.stdout + "\n" + cov_lines,
            stderr=run_result.stderr,
            returncode=run_result.returncode,
            timed_out=run_result.timed_out,
            crashed=run_result.crashed,
            error=run_result.error,
            strategy=run_result.strategy,
            input_data=run_result.input_data,
        )
    except Exception:
        pass 
    return run_result


_AFL_MAP_LINE_RE = re.compile(r"^([0-9a-fA-FxX]+)\s*[:=]\s*(\d+)$")


def _resolve_platform_cmd(cmd_config: Any) -> list[str] | None:
    if not cmd_config:
        return None
    if isinstance(cmd_config, dict):
        current_os = get_platform()
        cmd = cmd_config.get(current_os)
        return list(cmd) if isinstance(cmd, list) else None
    if isinstance(cmd_config, list):
        return list(cmd_config)
    return None


def _replace_instrumentation_placeholders(
    cmd_template: list[str],
    config: dict,
    map_file_host_path: str,
) -> list[str]:
    map_file_for_cmd = map_file_host_path
    if get_platform() == "windows" and cmd_template and cmd_template[0].lower() == "wsl":
        map_file_for_cmd = windows_to_wsl(map_file_host_path)

    buggy_cwd = str(config.get("buggy_cwd", "") or "")
    reference_cwd = str(config.get("reference_cwd", "") or "")

    if get_platform() == "windows":
        buggy_cwd_wsl = windows_to_wsl(buggy_cwd) if buggy_cwd else ""
        reference_cwd_wsl = windows_to_wsl(reference_cwd) if reference_cwd else ""
    else:
        buggy_cwd_wsl = buggy_cwd
        reference_cwd_wsl = reference_cwd

    replacements = {
        "{map_file}": map_file_for_cmd,
        "{buggy_cwd}": buggy_cwd,
        "{reference_cwd}": reference_cwd,
        "{buggy_cwd_wsl}": buggy_cwd_wsl,
        "{reference_cwd_wsl}": reference_cwd_wsl,
    }

    out: list[str] = []
    for part in cmd_template:
        new_part = part
        for token, value in replacements.items():
            new_part = new_part.replace(token, value)
        out.append(new_part)
    return out


def _parse_afl_showmap_text(text: str) -> dict[str, int]:
    edge_counts: dict[str, int] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        m = _AFL_MAP_LINE_RE.match(line)
        if not m:
            continue
        edge_id, count_text = m.group(1), m.group(2)
        try:
            count = int(count_text)
        except ValueError:
            continue
        edge_counts[f"afl:{edge_id.lower()}"] = count
    return edge_counts


def _format_coverage_freq_lines(edge_counts: dict[str, int]) -> str:
    if not edge_counts:
        return ""
    lines = [f"coverage_freq: {edge_id}={count}" for edge_id, count in sorted(edge_counts.items())]
    return "\n".join(lines)


def _resolve_instrumentation_kind(instr_cfg: dict) -> str:
    current_os = get_platform()
    override_key = f"kind_{current_os}"
    if instr_cfg.get(override_key):
        return str(instr_cfg.get(override_key)).strip().lower()
    return str(instr_cfg.get("kind", "afl_showmap")).strip().lower()


def _run_afl_showmap_instrumentation(
    instr_cfg: dict,
    config: dict,
    input_str: str,
    timeout: int,
    default_input_mode: str,
    default_use_wsl: bool,
) -> tuple[str, str | None]:
    cmd_template = _resolve_platform_cmd(instr_cfg.get("cmd"))
    if not cmd_template:
        return "", "blackbox_instrumentation.cmd is missing for current platform"

    input_mode = str(instr_cfg.get("input_mode", default_input_mode)).strip().lower()
    instr_cwd = instr_cfg.get("cwd") or config.get("buggy_cwd")

    try:
        instr_timeout = int(instr_cfg.get("timeout", timeout))
    except (TypeError, ValueError):
        instr_timeout = timeout

    use_wsl = bool(instr_cfg.get("use_wsl", default_use_wsl))
    if cmd_template and cmd_template[0].lower() == "wsl":
        use_wsl = False

    fd, map_file_host_path = tempfile.mkstemp(prefix="forza_map_", suffix=".txt")
    os.close(fd)

    try:
        cmd_with_map = _replace_instrumentation_placeholders(
            cmd_template, config, map_file_host_path
        )
        instr_result = run_target(
            cmd_template=cmd_with_map,
            input_str=input_str,
            input_mode=input_mode,
            cwd=instr_cwd,
            timeout=max(1, instr_timeout),
            use_wsl=use_wsl,
        )

        parsed = _parse_afl_showmap_text(instr_result.stdout)
        if not parsed:
            parsed = _parse_afl_showmap_text(instr_result.stderr)

        if not parsed and os.path.exists(map_file_host_path):
            try:
                with open(map_file_host_path, "r", encoding="utf-8", errors="replace") as f:
                    parsed = _parse_afl_showmap_text(f.read())
            except OSError:
                parsed = {}

        coverage_text = _format_coverage_freq_lines(parsed)
        if coverage_text:
            return coverage_text, None

        if instr_result.error:
            return "", f"instrumentation command failed: {instr_result.error}"
        return "", "instrumentation produced no edge map data"
    finally:
        try:
            if os.path.exists(map_file_host_path):
                os.remove(map_file_host_path)
        except OSError:
            pass


def _resolve_frida_cmd_template(instr_cfg: dict, config: dict) -> list[str] | None:
    frida_cmd = _resolve_platform_cmd(instr_cfg.get("frida_cmd"))
    if frida_cmd:
        return frida_cmd

    raw_buggy_cmd = config.get("buggy_cmd")
    if isinstance(raw_buggy_cmd, dict):
        cmd = raw_buggy_cmd.get(get_platform())
        if isinstance(cmd, list):
            return list(cmd)

    return None


def _classify_frida_error(raw_error: str) -> str:
    text = str(raw_error or "").strip()
    lowered = text.lower()
    if "access is denied" in lowered or "permission denied" in lowered:
        return "frida attach failed: access denied (run terminal as administrator)"
    if "architecture mismatch" in lowered or "wrong architecture" in lowered:
        return "frida attach failed: architecture mismatch between Python/Frida and target"
    if "process not found" in lowered:
        return "frida attach failed: target exited before instrumentation could attach"
    if "unable to access process" in lowered:
        return "frida attach failed: unable to access target process"
    if text:
        return f"frida instrumentation failed: {text}"
    return "frida instrumentation failed"


def _build_frida_stalker_script(
    target_module: str,
    exclude_modules: list[str],
) -> str:
    target_module_json = json.dumps(target_module.lower())
    exclude_modules_json = json.dumps([m.lower() for m in exclude_modules])
    return f"""
const TARGET_MODULE = {target_module_json};
const EXCLUDE_MODULES = {exclude_modules_json};
const followed = new Set();

function shouldTrackModule(moduleName) {{
  if (!moduleName) return false;
  const name = moduleName.toLowerCase();
  if (TARGET_MODULE && name !== TARGET_MODULE) return false;
  for (let i = 0; i < EXCLUDE_MODULES.length; i++) {{
    const token = EXCLUDE_MODULES[i];
    if (token && name.indexOf(token) !== -1) return false;
  }}
  return true;
}}

function eventAddress(event) {{
  if (Array.isArray(event)) {{
    if (event.length === 0) return null;
    if (typeof event[0] === 'string') {{
      return event.length > 1 ? event[1] : null;
    }}
    return event[0];
  }}
  if (event && typeof event === 'object') {{
    if (event.address !== undefined) return event.address;
    if (event.start !== undefined) return event.start;
    if (event.from !== undefined) return event.from;
  }}
  return null;
}}

function toEdgeKey(rawAddr) {{
  if (rawAddr === null || rawAddr === undefined) return null;
  const addr = ptr(rawAddr);
  const mod = Process.findModuleByAddress(addr);
  if (mod === null) return null;
  if (!shouldTrackModule(mod.name)) return null;
  const offset = addr.sub(mod.base);
  return mod.name.toLowerCase() + ':' + offset.toString();
}}

function emitBatch(parsedEvents) {{
  const batch = {{}};
  for (let i = 0; i < parsedEvents.length; i++) {{
    const key = toEdgeKey(eventAddress(parsedEvents[i]));
    if (!key) continue;
    batch[key] = (batch[key] || 0) + 1;
  }}
  const keys = Object.keys(batch);
  if (keys.length > 0) {{
    send({{ type: 'bb_batch', counts: batch }});
  }}
}}

function followThread(threadId) {{
  if (followed.has(threadId)) return;
  followed.add(threadId);
  try {{
    Stalker.follow(threadId, {{
      events: {{ block: true }},
      onReceive(events) {{
        try {{
          const parsed = Stalker.parse(events, {{ annotate: false }});
          emitBatch(parsed);
        }} catch (err) {{
          send({{ type: 'stalker_error', error: String(err) }});
        }}
      }}
    }});
  }} catch (err) {{
    send({{ type: 'follow_error', threadId: threadId, error: String(err) }});
  }}
}}

function unfollowAll() {{
  followed.forEach(function(threadId) {{
    try {{ Stalker.unfollow(threadId); }} catch (_) {{}}
  }});
  followed.clear();
  try {{ Stalker.garbageCollect(); }} catch (_) {{}}
}}

rpc.exports = {{
  start() {{
    const threads = Process.enumerateThreads();
    for (let i = 0; i < threads.length; i++) {{
      followThread(threads[i].id);
    }}
    try {{
      Process.attachThreadObserver({{
        onAdded(thread) {{
          followThread(thread.id);
        }},
        onRemoved(thread) {{
          try {{ Stalker.unfollow(thread.id); }} catch (_) {{}}
          followed.delete(thread.id);
        }}
      }});
    }} catch (_) {{}}
    return true;
  }},
  stop() {{
    unfollowAll();
    return true;
  }}
}};
"""


def _run_frida_stalker_instrumentation(
    instr_cfg: dict,
    config: dict,
    input_str: str,
    timeout: int,
    default_input_mode: str,
) -> tuple[str, str | None]:
    current_os = get_platform()
    if current_os != "windows":
        return "", "frida_stalker is currently supported on windows only"

    try:
        import frida  # type: ignore[import-not-found]
    except ImportError:
        return "", "frida is not installed (pip install frida frida-tools)"

    cmd_template = _resolve_frida_cmd_template(instr_cfg, config)
    if not cmd_template:
        return "", "frida instrumentation command is missing for current platform"

    input_mode = str(instr_cfg.get("input_mode", default_input_mode)).strip().lower()
    instr_cwd = instr_cfg.get("cwd") or config.get("buggy_cwd")

    timeout_override_key = f"timeout_{current_os}"
    timeout_raw = instr_cfg.get(timeout_override_key, instr_cfg.get("timeout", timeout))
    try:
        instr_timeout = int(timeout_raw)
    except (TypeError, ValueError):
        instr_timeout = timeout
    run_timeout = max(1, instr_timeout)

    frida_cfg = instr_cfg.get("frida_config")
    if not isinstance(frida_cfg, dict):
        frida_cfg = {}

    target_module = str(
        frida_cfg.get("target_module") or Path(cmd_template[0]).name
    ).strip().lower()
    exclude_modules = frida_cfg.get(
        "exclude_modules",
        ["ntdll.dll", "kernel32.dll", "kernelbase.dll", "ucrtbase.dll"],
    )
    if not isinstance(exclude_modules, list):
        exclude_modules = []

    input_bytes = input_str.encode(errors="replace")
    cmd: list[str] = []
    tmp_file: str | None = None
    proc: subprocess.Popen | None = None
    session = None
    script = None
    frida_errors: list[str] = []
    edge_counts: dict[str, int] = {}

    def _on_frida_message(message, data) -> None:
        msg_type = message.get("type")
        if msg_type == "send":
            payload = message.get("payload")
            if not isinstance(payload, dict):
                return
            if payload.get("type") in {"stalker_error", "follow_error"}:
                err = payload.get("error")
                if err:
                    frida_errors.append(str(err))
                return
            if payload.get("type") != "bb_batch":
                return
            counts = payload.get("counts")
            if not isinstance(counts, dict):
                return
            for key, raw_count in counts.items():
                try:
                    count = int(raw_count)
                except (TypeError, ValueError):
                    continue
                edge_id = f"frida_bb:{str(key).lower()}"
                edge_counts[edge_id] = edge_counts.get(edge_id, 0) + count
        elif msg_type == "error":
            desc = message.get("description") or message.get("stack") or "script error"
            frida_errors.append(str(desc))

    try:
        cmd, stdin_data, tmp_file = _prepare_run_command(
            cmd_template=cmd_template,
            input_str=input_str,
            input_mode=input_mode,
            use_wsl=False,
            extra_flags=None,
        )

        proc = subprocess.Popen(
            cmd,
            cwd=instr_cwd or None,
            stdin=subprocess.PIPE if stdin_data is not None else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        try:
            session = frida.attach(proc.pid)
            script = session.create_script(
                _build_frida_stalker_script(
                    target_module=target_module,
                    exclude_modules=[str(x) for x in exclude_modules],
                )
            )
            script.on("message", _on_frida_message)
            script.load()
            script.exports_sync.start()
        except Exception as exc:
            frida_errors.append(_classify_frida_error(str(exc)))

        try:
            proc.communicate(input=stdin_data if stdin_data is not None else None, timeout=run_timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.communicate()
            return "", f"instrumentation command timeout after {run_timeout}s"
    except FileNotFoundError as exc:
        missing_binary = cmd[0] if cmd else (cmd_template[0] if cmd_template else "<unknown>")
        return "", f"Binary not found: {missing_binary} ({exc})"
    except Exception as exc:
        return "", f"frida instrumentation command failed: {exc}"
    finally:
        if script is not None:
            try:
                script.exports_sync.stop()
            except Exception:
                pass
        if session is not None:
            try:
                session.detach()
            except Exception:
                pass
        if tmp_file and os.path.exists(tmp_file):
            try:
                os.remove(tmp_file)
            except OSError:
                pass

    coverage_text = _format_coverage_freq_lines(edge_counts)
    if coverage_text:
        return coverage_text, None

    if frida_errors:
        return "", frida_errors[0]
    return "", "instrumentation produced no edge map data"


def run_blackbox_instrumentation(
    config: dict,
    input_str: str,
    timeout: int,
    default_input_mode: str,
    default_use_wsl: bool,
) -> tuple[str, str | None]:
    """Run optional black-box instrumentation and return coverage_freq text.

    Supported mode:
        blackbox_instrumentation:
          enabled: true
          kind: afl_showmap | frida_stalker
          kind_windows: frida_stalker      # optional platform override
          kind_linux: afl_showmap          # optional platform override
          kind_mac: afl_showmap            # optional platform override
          cmd:                             # used by afl_showmap
            windows: ["wsl", "afl-showmap", "-Q", "-o", "{map_file}", "--", ...]
          frida_cmd:                       # optional custom command for frida_stalker
            windows: ["./bin/target.exe", "--arg", "{input}"]
          frida_config:
            target_module: "target.exe"
            exclude_modules: ["ntdll.dll"]
          cwd: "..."                # optional
          input_mode: "arg|stdin|file"  # optional
          timeout: 10                # optional, seconds
          use_wsl: false             # optional
    """
    instr_cfg = config.get("blackbox_instrumentation")
    if not isinstance(instr_cfg, dict) or not instr_cfg.get("enabled", False):
        return "", None

    kind = _resolve_instrumentation_kind(instr_cfg)
    if kind == "afl_showmap":
        return _run_afl_showmap_instrumentation(
            instr_cfg=instr_cfg,
            config=config,
            input_str=input_str,
            timeout=timeout,
            default_input_mode=default_input_mode,
            default_use_wsl=default_use_wsl,
        )
    if kind == "frida_stalker":
        return _run_frida_stalker_instrumentation(
            instr_cfg=instr_cfg,
            config=config,
            input_str=input_str,
            timeout=timeout,
            default_input_mode=default_input_mode,
        )

    if kind not in {"afl_showmap", "frida_stalker"}:
        return "", f"unsupported instrumentation kind: {kind!r}"
    return "", "unsupported instrumentation configuration"


def run_both(
    config: dict,
    input_str: str,
    strategy: str | None = None,
    use_coverage: bool = False,
    timeout: int = 60,
) -> tuple[RawResult, RawResult | None, str]:
    """Run buggy and reference targets and optionally collect instrumentation edges."""
    input_mode = config.get("input_mode", "arg")
    use_wsl = config.get("use_wsl", False)
    extra_flags = (
        [config["coverage_flag"]]
        if use_coverage
        and config.get("coverage_enabled")
        and config.get("coverage_flag")
        else None
    )

    raw_buggy_cmd = config["buggy_cmd"]
    if not raw_buggy_cmd:
        raise ValueError("buggy_cmd is required in the config")
    current_os = get_platform()
    if current_os not in raw_buggy_cmd:
        raise RuntimeError(f"No command configured for {current_os} in YAML!")
    buggy_cmd = raw_buggy_cmd[current_os]

    buggy_result = run_target(
        cmd_template=buggy_cmd,
        input_str=input_str,
        input_mode=input_mode,
        cwd=config.get("buggy_cwd"),
        timeout=timeout,
        use_wsl=use_wsl,
        extra_flags=extra_flags,
    )
    buggy_result.strategy = strategy

    instrumentation_coverage_text = ""
    if use_coverage and not config.get("coverage_enabled"):
        tracking_mode = str(config.get("tracking_mode", "behavioral")).strip().lower()
        if tracking_mode == "code_execution":
            instrumentation_coverage_text, instr_err = run_blackbox_instrumentation(
                config=config,
                input_str=input_str,
                timeout=timeout,
                default_input_mode=input_mode,
                default_use_wsl=use_wsl,
            )
            if instr_err and not config.get("_instr_warning_emitted"):
                print(f"[instrumentation] {config.get('name', 'target')}: {instr_err}")
                config["_instr_warning_emitted"] = True

    reference_result = None
    if (
        buggy_result.returncode == 0
        and not buggy_result.timed_out
        and not buggy_result.crashed
    ):
        ref_cmd = config.get("reference_cmd")
        if ref_cmd:
            needs_reference_coverage = (
                use_coverage
                and not config.get("coverage_enabled")
                and not instrumentation_coverage_text
            )
            if needs_reference_coverage:
                reference_result = run_reference_with_coverage(
                    cmd_template=ref_cmd[current_os],
                    input_str=input_str,
                    input_mode=input_mode,
                    cwd=config.get("reference_cwd"),
                    timeout=timeout,
                    use_wsl=use_wsl,
                )
            else:
                reference_result = run_target(
                    cmd_template=ref_cmd[current_os],
                    input_str=input_str,
                    input_mode=input_mode,
                    cwd=config.get("reference_cwd"),
                    timeout=timeout,
                    use_wsl=use_wsl,
                )
            reference_result.strategy = strategy

    return buggy_result, reference_result, instrumentation_coverage_text


def load_config(yaml_path: str) -> dict:
    p = Path(yaml_path).resolve()
    with open(p) as f:
        config = yaml.safe_load(f)

    # Resolve relative paths to absolute paths
    for key in ("buggy_cwd", "reference_cwd"):
        if config.get(key):
            config[key] = str((p.parent / config[key]).resolve())

    instr = config.get("blackbox_instrumentation")
    if isinstance(instr, dict) and instr.get("cwd"):
        instr["cwd"] = str((p.parent / instr["cwd"]).resolve())

    if config.get("seeds_path"):
        config["seeds_path"] = str((p.parent / config["seeds_path"]).resolve())

    return config


def load_seeds(seeds_path: str) -> list[str]:
    path = Path(seeds_path)
    if not path.exists():
        print(f"[WARN] Seeds file not found: {seeds_path}")
        return []
    seeds = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                seeds.append(line)
    return seeds
