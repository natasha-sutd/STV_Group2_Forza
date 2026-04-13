import argparse
import importlib
import os
import sys
from pathlib import Path

try:
    import afl
except ImportError:
    print("python-afl is not installed in this environment.")
    sys.exit(1)


def _read_stdin_bytes() -> bytes:
    chunks = []
    while True:
        chunk = os.read(0, 65536)
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks)


def _resolve_json_target():
    repo_root = Path(__file__).resolve().parents[2]
    target_dir = repo_root / "json-decoder"
    sys.path.insert(0, str(target_dir))

    from buggy_json import loads

    return loads


def _resolve_custom_target(module_name: str, callable_name: str):
    module = importlib.import_module(module_name)
    fn = getattr(module, callable_name, None)
    if fn is None or not callable(fn):
        raise RuntimeError(f"Callable not found: {module_name}.{callable_name}")
    return fn


def _should_abort(exc: BaseException, crash_all_exceptions: bool, ignore_exception_names):
    if crash_all_exceptions:
        return True
    return exc.__class__.__name__ not in ignore_exception_names


def _build_parser():
    parser = argparse.ArgumentParser(
        description="Generic python-afl persistent harness for Python-callable targets"
    )
    parser.add_argument(
        "--target",
        choices=["json", "custom"],
        default="json",
        help="Built-in target adapter to use",
    )
    parser.add_argument(
        "--module",
        default=None,
        help="Module path for custom target adapter (required when --target custom)",
    )
    parser.add_argument(
        "--callable",
        dest="callable_name",
        default=None,
        help="Callable name for custom target adapter (required when --target custom)",
    )
    parser.add_argument(
        "--iters",
        type=int,
        default=100000,
        help="Persistent iterations before process recycle",
    )
    parser.add_argument(
        "--crash-all-exceptions",
        action="store_true",
        help="Abort on any Python exception so AFL counts it as a crash",
    )
    parser.add_argument(
        "--ignore-exception",
        action="append",
        default=[],
        help="Exception class name to ignore when not using --crash-all-exceptions",
    )
    parser.add_argument(
        "--decode-errors",
        choices=["ignore", "replace", "strict"],
        default="ignore",
        help="UTF-8 decode policy for fuzz input bytes",
    )
    return parser


def main():
    parser = _build_parser()
    args = parser.parse_args()

    if args.target == "custom" and (not args.module or not args.callable_name):
        parser.error("--module and --callable are required when --target custom")

    os.environ.setdefault("PYTHONHASHSEED", "0")
    os.environ.setdefault("AFL_SKIP_BIN_CHECK", "1")

    if args.target == "json":
        target_fn = _resolve_json_target()
    else:
        target_fn = _resolve_custom_target(args.module, args.callable_name)

    afl.init()

    ignore_exception_names = set(args.ignore_exception)
    while afl.loop(args.iters):
        data = _read_stdin_bytes()
        payload = data.decode("utf-8", errors=args.decode_errors)
        try:
            target_fn(payload)
        except KeyboardInterrupt:
            raise
        except BaseException as exc:
            if _should_abort(exc, args.crash_all_exceptions, ignore_exception_names):
                os.abort()


if __name__ == "__main__":
    main()
