import argparse
import subprocess
import os
import shutil
import time
import sys
import csv
from pathlib import Path

# Helper script to orchestrate py-afl-fuzz and standard afl-fuzz

# --------------------------------------------------------------------------
# Blackbox targets are routed through afl_arg_harness.sh to bridge AFL file
# inputs ("@@") to command-line string arguments (e.g. --ipstr).
# --------------------------------------------------------------------------
BLACKBOX_TARGETS = {"ipv4", "ipv6", "cidrize"}


def _is_wsl() -> bool:
    proc_version = Path("/proc/version")
    if not proc_version.exists():
        return False
    try:
        return "microsoft" in proc_version.read_text(encoding="utf-8", errors="ignore").lower()
    except OSError:
        return False


def _ensure_c_harness_compiled(base_dir: Path) -> Path:
    """Compiles the C harness if it doesn't already exist or if it's older than the source."""
    harness_c = base_dir / "tools" / "afl_c_harness.c"
    harness_bin = base_dir / "tools" / "afl_c_harness"
    
    if not harness_c.exists():
        raise FileNotFoundError(f"C harness source not found at {harness_c}")
        
    if not harness_bin.exists() or harness_bin.stat().st_mtime < harness_c.stat().st_mtime:
        print(f"[*] Compiling C harness: {harness_c}")
        try:
            subprocess.run(
                ["gcc", "-O3", str(harness_c), "-o", str(harness_bin)],
                check=True,
                capture_output=True,
                text=True
            )
            print("[+] Compilation successful.")
        except subprocess.CalledProcessError as e:
            print(f"[-] Compilation failed. Error: {e.stderr}")
            raise
    return harness_bin


def _to_float(value, default=0.0):
    try:
        return float(str(value).strip().replace("%", ""))
    except (TypeError, ValueError):
        return default


def _resolve_qemu_trace_path():
    """Locate afl-qemu-trace from PATH or common local AFL++ build locations."""
    from_path = shutil.which("afl-qemu-trace")
    if from_path:
        return from_path

    home = Path.home()
    candidates = [
        home / "AFLplusplus" / "afl-qemu-trace",
        home / "AFLplusplus" / "qemu_mode" / "afl-qemu-trace",
    ]
    for candidate in candidates:
        if candidate.exists() and os.access(str(candidate), os.X_OK):
            return str(candidate)

    return None


def _prepend_to_path(path_entry: str) -> None:
    current_path = os.environ.get("PATH", "")
    entries = current_path.split(os.pathsep) if current_path else []
    if path_entry not in entries:
        os.environ["PATH"] = path_entry + os.pathsep + current_path if current_path else path_entry


def start_afl(target_name, time_limit, dry_run=False, blackbox_mode="qemu", run_id=None):
    base_dir = Path(__file__).parent
    
    # Define our targets based on the yaml configurations
    targets = {
        "ipv4": {
            # Assuming native binary for ipv4
            "cmd": [str((base_dir / ".." / "IPv4-IPv6-parser-main" / "bin" / "linux-ipv4-parser").resolve()), "--ipstr"],
            "seed_dir": "inputs/ipv4_parser/seeds"
        },
        "ipv6": {
            # Assuming native binary for ipv6
            "cmd": [str((base_dir / ".." / "IPv4-IPv6-parser-main" / "bin" / "linux-ipv6-parser").resolve()), "--ipstr"],
            "seed_dir": "inputs/ipv6_parser/seeds"
        },
        "json": {
            # Python target uses native python-afl persistent harness
            "cmd": ["python", "tools/python_afl_persistent_harness.py", "--target", "json", "--crash-all-exceptions"],
            "seed_dir": "inputs/json_decoder/seeds"
        },
        "cidrize": {
            # Assuming native binary for cidrize
            "cmd": [str((base_dir / ".." / "cidrize-runner-main" / "bin" / "linux-cidrize-runner").resolve()), "--func", "cidrize", "--ipstr"],
            "seed_dir": "inputs/cidrize/seeds"
        }
    }

    t = targets[target_name]
    if run_id is None:
        run_id = time.strftime("%Y%m%d_%H%M%S")

    if target_name in BLACKBOX_TARGETS and blackbox_mode == "qemu":
        qemu_trace = _resolve_qemu_trace_path()
        if not qemu_trace:
            print("[-] blackbox mode is set to qemu, but afl-qemu-trace is not available in PATH.")
            print("[-] Install AFL++ QEMU support, or run with --blackbox-mode dumb for fallback.")
            return False
        # Ensure afl-qemu-trace is discoverable by afl-fuzz without forcing
        # manual target wrapping semantics.
        _prepend_to_path(str(Path(qemu_trace).parent))

    if target_name in BLACKBOX_TARGETS:
        tracking_mode = "afl-qemu" if blackbox_mode == "qemu" else "afl-dumb"
    else:
        tracking_mode = "python-afl"

    output_dir = base_dir / "results" / f"afl_baseline_{target_name}"
    
    # Ensure seed directories exist (AFL needs an actual directory, not a .txt file)
    seed_path = base_dir / t["seed_dir"]
    if not seed_path.exists() or len(list(seed_path.glob("*"))) == 0:
        print(f"[-] Seed directory does not exist or is empty: {seed_path}")
        print("[*] Creating seed folder from your seeds.txt if needed...")
        seed_path.mkdir(parents=True, exist_ok=True)
        # Assuming there is a seeds.txt next to it that you need to split
        seed_txt = seed_path.parent / "seeds.txt"
        if seed_txt.exists():
            with open(seed_txt, "r") as f:
                lines = f.readlines()
            for i, line in enumerate(lines):
                if line.strip():
                    with open(seed_path / f"seed_{i}.txt", "w") as out_f:
                        out_f.write(line.strip())
        else:
            # write a dummy seed if no seeds.txt is found
            with open(seed_path / "dummy_seed.txt", "w") as out_f:
                out_f.write("test")

    os.environ["AFL_IGNORE_SEED_PROBLEMS"] = "1"
    os.environ["AFL_QUIET"] = "1"

    # Give the QEMU forkserver extra time on first init
    # (PyInstaller bundles are extremely slow to unpack on cold start).
    os.environ.setdefault("AFL_FORKSRV_INIT_TMOUT", "30000")

    # ── Blackbox-specific tuning ─────────────────────────────────────────
    if target_name in BLACKBOX_TARGETS:
        # Skip deterministic trim stages — prohibitively slow with QEMU
        os.environ.setdefault("AFL_DISABLE_TRIM", "1")
        # Disable CPU pinning — avoids contention in WSL / shared-core VMs
        os.environ.setdefault("AFL_NO_AFFINITY", "1")
        # Enable QEMU translation block caching for repeated execution
        os.environ.setdefault("AFL_QEMU_PERSISTENT_CNT", "1000")

        # ── Tier 2: Route PyInstaller temp unpacking to RAM ──────────────
        # PyInstaller extracts bundled files to a temp dir on every run.
        # Using /dev/shm (tmpfs) eliminates disk I/O for this extraction.
        devshm = Path("/dev/shm")
        if devshm.exists() and devshm.is_dir():
            cache_dir = devshm / "afl_pyinstaller_cache"
            cache_dir.mkdir(exist_ok=True)
            os.environ["TMPDIR"] = str(cache_dir)

    # WSL's default core_pattern handler can block AFL crash interception.
    if _is_wsl():
        os.environ["AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES"] = "1"

    if target_name == "json":
        fuzzer_cmd = "afl-fuzz"
        
        # When fuzzing Python directly without the py-afl-fuzz script,
        # we MUST set PYTHONHASHSEED to 0 to keep dicts deterministic 
        # and afl-fuzz expects it.
        os.environ["PYTHONHASHSEED"] = "0"
        
        # When bypassing the py-afl-fuzz wrapper, we MUST tell standard 
        # afl-fuzz not to check if the Python binary itself is instrumented 
        # (since only the python-afl module inside it is hooked).
        os.environ["AFL_SKIP_BIN_CHECK"] = "1"
        
        afl_command = [
            fuzzer_cmd,
            "-i", str(seed_path),
            "-o", str(output_dir),
            "-V", str(time_limit),  # Run for N seconds
            "-t", "1000",
            "--",
            sys.executable,
            str(base_dir / "tools" / "python_afl_persistent_harness.py"),
            "--target", "json",
            "--crash-all-exceptions",
        ]
    else:
        fuzzer_cmd = "afl-fuzz"
        mode_flag = "-Q" if blackbox_mode == "qemu" else "-n"
        timeout_ms = "10000" if blackbox_mode == "qemu" else "10000"
        harness_path = str(_ensure_c_harness_compiled(base_dir))
        afl_command = [
            fuzzer_cmd,
            mode_flag,
            "-d",  # Skip deterministic stages — too slow at QEMU speeds
            "-i", str(seed_path),
            "-o", str(output_dir),
            "-V", str(time_limit),  # Run for N seconds
            "-t", timeout_ms,
            "--",
            harness_path,
        ] + t["cmd"] + ["@@"]

    # ── Dry-run mode ──────────────────────────────────────────────────────
    # Validates the full pipeline without starting AFL:
    #   1. Checks afl-fuzz is installed
    #   2. Checks target binary exists and is executable
    #   3. Verifies seed directory has files
    #   4. Runs target binary once with a real seed
    #   5. Prints the constructed AFL command
    if dry_run:
        return _dry_run(target_name, t, seed_path, afl_command, base_dir, tracking_mode)

    print(f"[*] Starting {fuzzer_cmd} for {target_name} (mode={tracking_mode}, run_id={run_id})")
    print(f"[*] Command: {' '.join(afl_command)}")
    print(f"[*] Results will be logged to: {output_dir}")
    print("[*] Logs and bug counts will be collected after the run...")
    
    try:
        # Run the fuzzer process
        run_result = subprocess.run(afl_command, cwd=str(base_dir))
    except KeyboardInterrupt:
        print("\n[*] Fuzzing interrupted by user.")
        return

    if run_result.returncode != 0:
        print(f"[-] afl-fuzz exited with non-zero code: {run_result.returncode}")
        print("[-] Skipping result logging for this run due early abort/failure.")
        return
        
    # Logging the results phase
    log_results(target_name, output_dir, tracking_mode, time_limit, run_id)


def _dry_run(target_name, target_cfg, seed_path, afl_command, base_dir, tracking_mode):
    """Smoke-test the pipeline without starting AFL.
    
    Checks:
      1. afl-fuzz binary is reachable
      2. Target binary exists (and is executable for blackbox targets)
      3. Seed directory is populated
      4. A single execution with a real seed produces output
      5. The harness wrapper (for blackbox) is present and executable
      6. Prints the final AFL command for manual inspection
    """
    ok_count = 0
    fail_count = 0

    def _pass(msg):
        nonlocal ok_count
        ok_count += 1
        print(f"  [PASS] {msg}")

    def _fail(msg):
        nonlocal fail_count
        fail_count += 1
        print(f"  [FAIL] {msg}")

    def _warn(msg):
        print(f"  [WARN] {msg}")

    def _info(msg):
        print(f"  [INFO] {msg}")

    print(f"\n{'='*60}")
    print(f"  DRY-RUN: {target_name}")
    print(f"{'='*60}\n")

    # ── 1. Check afl-fuzz is installed ────────────────────────────────────
    afl_path = shutil.which("afl-fuzz")
    if afl_path:
        _pass(f"afl-fuzz found: {afl_path}")
    else:
        _fail("afl-fuzz not found in PATH — install with: sudo apt install afl++")

    # ── 2. Check target binary / harness ──────────────────────────────────
    if target_name in BLACKBOX_TARGETS:
        # Blackbox: check both the harness script and the target binary
        harness_path = base_dir / "tools" / "afl_arg_harness.sh"
        if harness_path.exists():
            _pass(f"Harness found: {harness_path}")
            if os.access(str(harness_path), os.X_OK):
                _pass("Harness is executable")
            else:
                _fail(f"Harness is NOT executable — run: chmod +x {harness_path}")
        else:
            _fail(f"Harness not found: {harness_path}")

        # Check the actual target binary
        binary = target_cfg["cmd"][0]
        binary_path = base_dir / binary
        if binary_path.exists():
            _pass(f"Target binary found: {binary_path}")
            if os.access(str(binary_path), os.X_OK):
                _pass("Target binary is executable")
            else:
                _fail(f"Target binary is NOT executable — run: chmod +x {binary_path}")
        else:
            _fail(f"Target binary NOT found: {binary_path}")

        if tracking_mode == "afl-qemu":
            _info("Mode: qemu/blackbox (-Q flag) — dynamic binary translation coverage")
            if afl_path:
                try:
                    help_out = subprocess.run(["afl-fuzz", "-h"], capture_output=True, text=True, timeout=5)
                    if "-Q" in (help_out.stdout + help_out.stderr):
                        _pass("afl-fuzz supports QEMU mode (-Q)")
                        qemu_trace = _resolve_qemu_trace_path()
                        if qemu_trace:
                            _pass(f"afl-qemu-trace found: {qemu_trace}")
                        else:
                            _fail("afl-qemu-trace not found in PATH or local AFLplusplus build locations")
                    else:
                        _fail("afl-fuzz does not report QEMU mode (-Q) support")
                except Exception as exc:
                    _warn(f"Could not validate -Q support: {exc}")
        else:
            _info("Mode: dumb/blackbox (-n flag) — no coverage instrumentation")
    else:
        # JSON target: check Python harness
        harness_path = base_dir / "tools" / "python_afl_persistent_harness.py"
        if harness_path.exists():
            _pass(f"Python harness found: {harness_path}")
        else:
            _fail(f"Python harness NOT found: {harness_path}")
        _info("Mode: instrumented (python-afl)")

    # ── 3. Check seeds ────────────────────────────────────────────────────
    seed_files = list(seed_path.glob("*"))
    if seed_files:
        _pass(f"Seed directory populated: {len(seed_files)} files in {seed_path}")
    else:
        _fail(f"Seed directory is EMPTY: {seed_path}")

    # ── 4. Single execution smoke test ────────────────────────────────────
    if seed_files and target_name in BLACKBOX_TARGETS:
        first_seed = seed_files[0]
        seed_content = first_seed.read_text().strip()
        _info(f"Testing with seed: {repr(seed_content[:60])}")

        binary = target_cfg["cmd"][0]
        binary_path = base_dir / binary
        test_cmd = [str(binary_path)] + target_cfg["cmd"][1:] + [seed_content]
        
        try:
            result = subprocess.run(
                test_cmd,
                capture_output=True, text=True,
                timeout=15,
                cwd=str(base_dir),
            )
            stdout_preview = result.stdout.strip()[:200] if result.stdout else "(empty)"
            stderr_preview = result.stderr.strip()[:200] if result.stderr else "(empty)"
            
            _pass(f"Binary executed (exit code: {result.returncode})")
            _info(f"  stdout: {stdout_preview}")
            if result.stderr.strip():
                _info(f"  stderr: {stderr_preview}")

            bug_markers = (
                "Traceback (most recent call last)",
                "invalidity bug",
                "performance bug",
                "bonus crash",
                "bug has been triggered",
                "InvalidCidrFormatError",
                "AddrFormatError",
                "ParseException",
            )
            has_bug_marker = any(marker in result.stdout or marker in result.stderr for marker in bug_markers)
                
            # Check if the output matches what the harness/AFL would expect
            if result.returncode == 0:
                if has_bug_marker:
                    _warn("Clean exit with bug marker(s) found — harness will convert this into a crash signal")
                else:
                    _pass("Clean exit — AFL will NOT count this as a crash")
            else:
                _warn(f"Non-zero exit ({result.returncode}) — AFL harness may translate to crash signal")

        except FileNotFoundError:
            _fail(f"Binary not found or not executable: {binary_path}")
        except subprocess.TimeoutExpired:
            _warn("Binary timed out (15s) — expected for cold PyInstaller start, should work after caching")
        except Exception as e:
            _fail(f"Execution error: {e}")

    # ── 5. Print constructed command ──────────────────────────────────────
    print(f"\n{'─'*60}")
    print("  Constructed AFL command:")
    print(f"{'─'*60}")
    print(f"  {' '.join(afl_command)}")
    print()

    # ── 6. Note dumb-mode metric limitations ──────────────────────────────
    if tracking_mode == "afl-dumb":
        print(f"{'─'*60}")
        print("  ⚠ Dumb-mode metric notes:")
        print(f"{'─'*60}")
        print("  • bitmap_cvg (Map Density)  — NOT meaningful without instrumentation")
        print("  • stability                 — NOT meaningful without instrumentation")
        print("  • Reliable metrics: saved_crashes, execs_done, execs_per_sec")
        print("  • CSV will log fuzzer as 'afl-dumb' for these targets")
        print()

    # ── Summary ───────────────────────────────────────────────────────────
    print(f"{'='*60}")
    if fail_count == 0:
        print(f"  ✓ ALL CHECKS PASSED ({ok_count}/{ok_count})")
        print(f"  Ready to fuzz: python afl_baseline.py --target {target_name} --time {60}")
    else:
        print(f"  ✗ {fail_count} CHECK(S) FAILED — fix issues above before fuzzing")
    print(f"{'='*60}\n")

    return fail_count == 0


def log_results(target_name, output_dir, tracking_mode, time_budget_sec, run_id):
    """Parses afl fuzzer_stats and logs to a baseline comparison CSV.
    
    Extracts all metrics needed for fair 1-to-1 comparison with custom fuzzer:
    - Performance metrics: execs_done, execs_per_sec, saved_crashes
    - Map coverage: bitmap_cvg (map density)
    - Item geometry: max_depth (levels), pending_total (pending),
      pending_favs (pend_fav), paths_found (own_finds),
      paths_imported (imported), stability
    """
    # AFL++ 4.x writes fuzzer_stats to output root; legacy AFL 2.x uses default/
    stats_file = output_dir / "default" / "fuzzer_stats"
    if not stats_file.exists():
        stats_file = output_dir / "fuzzer_stats"
    
    if stats_file.exists():
        stats = {}
        with open(stats_file, "r") as f:
            for line in f:
                if ":" in line:
                    k, v = line.split(":", 1)
                    stats[k.strip()] = v.strip()
        return _log_from_stats(target_name, stats, output_dir, tracking_mode, time_budget_sec, run_id)

    # Fallback: When AFL++ is killed by -V timer, fuzzer_stats may not exist.
    # Parse the last line of plot_data instead (always written periodically).
    plot_file = output_dir / "plot_data"
    if not plot_file.exists():
        plot_file = output_dir / "default" / "plot_data"

    if plot_file.exists():
        print("[*] fuzzer_stats not found — falling back to plot_data")
        return _log_from_plot_data(target_name, plot_file, output_dir, tracking_mode, time_budget_sec, run_id)

    print("[-] Neither fuzzer_stats nor plot_data found. Did AFL run successfully?")
    return

def _log_from_stats(target_name, stats, output_dir, tracking_mode, time_budget_sec, run_id):
    """Extract metrics from fuzzer_stats key-value file."""
    bugs_found    = stats.get("saved_crashes", "0")
    exec_count    = stats.get("execs_done", "0")
    exec_speed    = stats.get("execs_per_sec", "0")
    bitmap_cvg    = stats.get("bitmap_cvg", "n/a")
    max_depth     = stats.get("max_depth", "0")
    pending       = stats.get("pending_total", "0")
    pend_fav      = stats.get("pending_favs", "0")
    paths_found   = stats.get("paths_found", "0")
    paths_import  = stats.get("paths_imported", "0")
    stability_pct = stats.get("stability", "n/a")
    paths_total   = stats.get("paths_total", "0")
    saved_hangs   = stats.get("saved_hangs", "0")
    cycles_done   = stats.get("cycles_done", "0")

    _print_and_save_results(
        target_name, bugs_found, exec_count, exec_speed,
        bitmap_cvg, max_depth, pending, pend_fav,
        paths_found, paths_import, stability_pct,
        paths_total, saved_hangs, cycles_done,
        tracking_mode, time_budget_sec, run_id,
    )


def _log_from_plot_data(target_name, plot_file, output_dir, tracking_mode, time_budget_sec, run_id):
    """Fallback: extract metrics from the last row of plot_data CSV.
    
    plot_data columns (AFL++ 4.x):
      relative_time, cycles_done, cur_item, corpus_count, pending_total,
      pending_favs, map_size, saved_crashes, saved_hangs, max_depth,
      execs_per_sec, total_execs, edges_found
    """
    last_line = ""
    with open(plot_file, "r") as f:
        for line in f:
            if not line.startswith("#") and line.strip():
                last_line = line.strip()

    if not last_line:
        print("[-] plot_data is empty — no metrics to extract")
        return

    cols = [c.strip() for c in last_line.split(",")]
    # Ensure we have enough columns
    if len(cols) < 13:
        print(f"[-] plot_data has unexpected format ({len(cols)} cols, expected 13)")
        return

    _print_and_save_results(
        target_name,
        bugs_found    = cols[7],
        exec_count    = cols[11],
        exec_speed    = cols[10],
        bitmap_cvg    = cols[6],
        max_depth     = cols[9],
        pending       = cols[4],
        pend_fav      = cols[5],
        paths_found   = "n/a",  # not in plot_data
        paths_import  = "n/a",  # not in plot_data
        stability_pct = "n/a",  # not in plot_data
        paths_total   = cols[3],
        saved_hangs   = cols[8],
        cycles_done   = cols[1],
        tracking_mode = tracking_mode,
        time_budget_sec = time_budget_sec,
        run_id = run_id,
    )


def _print_and_save_results(
    target_name, bugs_found, exec_count, exec_speed,
    bitmap_cvg, max_depth, pending, pend_fav,
    paths_found, paths_import, stability_pct,
    paths_total, saved_hangs, cycles_done,
    tracking_mode, time_budget_sec, run_id,
):
    """Display results and append to the comparison CSV."""
    is_dumb = tracking_mode == "afl-dumb"
    fuzzer_label = tracking_mode
    notes = ""
    if is_dumb:
        notes = "map_density/stability not measured in dumb mode"
        bitmap_cvg = "not_measured"
        stability_pct = "not_measured"

    crashes_value = _to_float(bugs_found, default=0.0)
    crash_rate_per_hour = 0.0
    if time_budget_sec > 0:
        crash_rate_per_hour = crashes_value * 3600.0 / time_budget_sec

    print(f"\n=== AFL Baseline Results for {target_name} ===")
    print(f"  Fuzzer Mode    : {fuzzer_label}")
    print(f"  Run ID         : {run_id}")
    print(f"  Time Budget    : {time_budget_sec}s")
    print(f"  Crashes Found  : {bugs_found}")
    print(f"  Crash Rate     : {crash_rate_per_hour:.2f} crashes/hour")
    print(f"  Total Execs    : {exec_count}")
    print(f"  Exec Speed     : {exec_speed} execs/sec")
    if is_dumb:
        print(f"  Map Density    : {bitmap_cvg}  (⚠ not meaningful in dumb mode)")
        print(f"  Stability      : {stability_pct}  (⚠ not meaningful in dumb mode)")
    else:
        print(f"  Map Density    : {bitmap_cvg}")
        print(f"  Stability      : {stability_pct}")
    print(f"  Levels         : {max_depth}")
    print(f"  Pending        : {pending}")
    print(f"  Pend Fav       : {pend_fav}")
    print(f"  Own Finds      : {paths_found}")
    print(f"  Imported       : {paths_import}")
    print(f"  Corpus Size    : {paths_total}")

    # Save to comparison CSV
    log_file = Path(__file__).parent / "results" / "afl_baseline_comparison_latest.csv"
    file_exists = log_file.exists()
    expected_header = [
        "Date", "Run_ID", "Target", "Tracking_Mode", "Time_Budget_sec",
        "Crashes", "Crashes_per_Hour", "Total_Execs", "Exec_Speed_sec",
        "Map_Density", "Corpus_Size", "Levels", "Pending", "Pend_Fav",
        "Own_Finds", "Imported", "Stability", "Saved_Hangs", "Cycles_Done", "Notes",
    ]

    if file_exists:
        try:
            with open(log_file, "r", newline="") as existing:
                reader = csv.reader(existing)
                current_header = next(reader, [])
            if current_header != expected_header:
                backup_file = log_file.with_name(
                    f"{log_file.stem}.bak_{time.strftime('%Y%m%d_%H%M%S')}{log_file.suffix}"
                )
                shutil.move(log_file, backup_file)
                print(f"[*] Existing CSV schema changed; backed up old file to {backup_file}")
                file_exists = False
        except Exception as exc:
            print(f"[!] Could not validate existing CSV header ({exc}); writing with expected schema")
            file_exists = False

    with open(log_file, "a", newline="") as csvfile:
        writer = csv.writer(csvfile)
        if not file_exists:
            writer.writerow(expected_header)

        date_str = time.strftime("%Y-%m-%d %H:%M:%S")
        crashes_per_hour = f"{crash_rate_per_hour:.4f}"
        writer.writerow([
            date_str, run_id, target_name, fuzzer_label, time_budget_sec,
            bugs_found, crashes_per_hour, exec_count, exec_speed,
            bitmap_cvg, paths_total,
            max_depth, pending, pend_fav,
            paths_found, paths_import, stability_pct,
            saved_hangs, cycles_done,
            notes,
        ])

    print(f"[*] Results logged to {log_file}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Baseline AFL/python-afl wrapper for targets")
    parser.add_argument("--target", required=True, choices=["ipv4", "ipv6", "json", "cidrize"])
    parser.add_argument("--time", type=int, default=3600, help="Fuzz time limit in seconds")
    parser.add_argument(
        "--blackbox-mode", choices=["qemu", "dumb"], default="qemu",
        help="Mode for native blackbox targets: qemu (-Q) or dumb (-n)"
    )
    parser.add_argument(
        "--run-id", default=None,
        help="Optional run identifier for CSV logging"
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Verify pipeline (binary, seeds, harness, afl) without fuzzing"
    )
    
    args = parser.parse_args()
    
    if args.dry_run:
        start_afl(
            args.target,
            args.time,
            dry_run=True,
            blackbox_mode=args.blackbox_mode,
            run_id=args.run_id,
        )
    else:
        start_afl(
            args.target,
            args.time,
            blackbox_mode=args.blackbox_mode,
            run_id=args.run_id,
        )

