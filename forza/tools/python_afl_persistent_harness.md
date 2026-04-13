# python_afl_persistent_harness.py

Generic native `python-afl` harness for Python-callable targets.

## What it solves

- Removes QEMU overhead for whitebox Python targets
- Uses persistent mode (`afl.init()` + `while afl.loop(...)`)
- Reads fuzz input from stdin per AFL iteration
- Supports strict crash policy (`--crash-all-exceptions`) or selective ignores

## Basic usage

JSON target:

```bash
afl-fuzz -i inputs/json_decoder/seeds -o results/afl_baseline_json -V 3600 -t 1000 -- \
  python tools/python_afl_persistent_harness.py --target json --crash-all-exceptions
```

Custom Python-callable target:

```bash
afl-fuzz -i <seed_dir> -o <out_dir> -V 3600 -- \
  python tools/python_afl_persistent_harness.py \
    --target custom \
    --module <python.module.path> \
    --callable <function_name> \
    --iters 100000 \
    --crash-all-exceptions
```

Selective exception ignore mode:

```bash
python tools/python_afl_persistent_harness.py --target custom \
  --module mypkg.adapter --callable fuzz_entry \
  --ignore-exception ValueError --ignore-exception TypeError
```

## Corpus directory requirements

- `-i` must point to a directory (not a single file)
- Put one seed per file
- Keep seeds compact and format-diverse
- Avoid nested directories for seed files

Example:

```text
inputs/
  json_decoder/
    seeds/
      seed_0001.json
      seed_0002.json
      seed_0003.json
```
