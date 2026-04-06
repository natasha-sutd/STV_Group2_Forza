"""
engine/seed_generator.py

Generalised grammar-based seed generator and grammar-aware mutator.

Generates seeds for the initial corpus based on the input grammar
defined in the target's YAML config under the `input:` key.

Also exposes mutate_from_spec() for grammar-aware mutation in
MutationEngine.

Supported grammar types
-----------------------
  int            — random integer in [min, max]
  hex            — random hex string in [min, max]
  string         — random string of length [min, max]
  boolean        — "True" or "False"
  null           — literal "null"
  any            — random choice of int, string, or boolean
  literal        — fixed string value
  array          — list of elements
  object         — JSON/dict with random keys and values
  sequence       — repeat element N times with separator (count + separator + element)
                   OR concatenate fixed parts (parts list)
  concat         — alias for sequence with parts
  one_of         — choose one option uniformly at random
  weighted_one_of— choose one option by weight

CLI usage
---------
  python3 engine/seed_generator.py targets/json_decoder.yaml
  python3 engine/seed_generator.py targets/ipv4_parser.yaml --count 50
"""

from __future__ import annotations

import json
import os
import random
import string
import yaml
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# Type generator registry
# ---------------------------------------------------------------------------

TYPE_GENERATORS: dict[str, callable] = {}


def register_type(name: str):
    """Decorator to register a generator function for a grammar type."""
    def decorator(func):
        TYPE_GENERATORS[name] = func
        return func
    return decorator


# ---------------------------------------------------------------------------
# Built-in type generators
# ---------------------------------------------------------------------------

@register_type("int")
def gen_int(spec: dict) -> str:
    return str(random.randint(spec.get("min", 0), spec.get("max", 100)))


@register_type("hex")
def gen_hex(spec: dict) -> str:
    return format(random.randint(spec.get("min", 0), spec.get("max", 65535)), "x")


@register_type("string")
def gen_string(spec: dict) -> str:
    length = random.randint(spec.get("min", 1), spec.get("max", 10))
    chars = spec.get("chars", string.ascii_letters)
    return "".join(random.choice(chars) for _ in range(length))


@register_type("boolean")
def gen_boolean(spec: dict) -> str:
    return str(random.choice([True, False]))


@register_type("null")
def gen_null(spec: dict) -> str:
    return "null"


@register_type("any")
def gen_any(spec: dict) -> str:
    """Generate a random value of any basic type."""
    choice = random.choice(["int", "string", "boolean", "null"])
    return generate_from_spec({"type": choice, "min": 0, "max": 100})


@register_type("literal")
def gen_literal(spec: dict) -> str:
    return str(spec.get("value", ""))


@register_type("array")
def gen_array(spec: dict) -> str:
    length = random.randint(spec.get("min_length", 1),
                            spec.get("max_length", 3))
    element_spec = spec.get("element", {"type": "int", "min": 0, "max": 100})
    items = [generate_from_spec(element_spec) for _ in range(length)]
    return str(items)


@register_type("object")
def gen_object(spec: dict) -> str:
    """
    Generate a random object/dict.

    Supports two key/value field naming conventions:
      New style: key_schema / value_schema  (explicit)
      Old style: key / value                (shorthand — also accepted)

    encoding field controls output format:
      json     (default) — {"a": 1}   proper JSON
      dict_str           — {'a': 1}   Python dict string
    """
    # Accept both naming conventions
    key_spec = spec.get("key_schema") or spec.get(
        "key",   {"type": "string", "min": 1, "max": 8})
    value_spec = spec.get("value_schema") or spec.get(
        "value", {"type": "int",    "min": 0, "max": 100})

    n_fields = random.randint(1, spec.get("max_fields", 3))
    obj = {}
    for _ in range(n_fields):
        k = generate_from_spec(key_spec)
        v_raw = generate_from_spec(value_spec)
        # Try to parse the value back to a Python type for proper JSON encoding
        try:
            v = json.loads(v_raw)
        except (json.JSONDecodeError, TypeError):
            v = v_raw
        obj[str(k)] = v

    encoding = spec.get("encoding", "json")
    if encoding == "dict_str":
        return str(obj)
    # Default: proper JSON encoding
    return json.dumps(obj)


@register_type("sequence")
def gen_sequence(spec: dict) -> str:
    """
    Two modes:
      Repeat mode  (count + separator + element) — repeat element N times
      Parts mode   (parts list)                  — concatenate fixed parts
    """
    if "count" in spec and "element" in spec:
        count = spec["count"]
        sep = str(spec.get("separator", ""))
        elements = [str(generate_from_spec(spec["element"]))
                    for _ in range(count)]
        return sep.join(elements)
    # Parts mode
    return "".join(str(generate_from_spec(p)) for p in spec.get("parts", []))


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def generate_from_spec(spec: Any) -> str:
    """
    Recursively generate a value from a grammar spec dict.
    Returns a string in all cases.
    """
    if not isinstance(spec, dict):
        return str(spec)

    t = spec.get("type", "")

    # Registered types (int, hex, string, boolean, null, any, literal,
    #                   array, object, sequence)
    if t in TYPE_GENERATORS:
        result = TYPE_GENERATORS[t](spec)

    # Aliases
    elif t == "concat":
        result = "".join(str(generate_from_spec(p))
                         for p in spec.get("parts", []))

    elif t == "one_of":
        options = spec.get("options", [])
        result = str(generate_from_spec(
            random.choice(options))) if options else ""

    elif t == "weighted_one_of":
        options = spec.get("options", [])
        if not options:
            result = ""
        else:
            weights = [float(o.get("weight", 1.0)) for o in options]
            chosen = random.choices(options, weights=weights, k=1)[0]
            result = str(generate_from_spec(chosen))

    else:
        result = ""

    return str(result)


# ---------------------------------------------------------------------------
# Grammar-aware mutation
# ---------------------------------------------------------------------------

def mutate_from_spec(seed: str, spec: dict) -> str:
    """
    Grammar-aware mutation: produce a structurally plausible variant of
    seed by applying one of three sub-strategies chosen at random.

    Sub-strategies
    --------------
    fresh            — regenerate entire input from grammar
    boundary         — push one numeric leaf to its min or max value
    component_swap   — force selection of the last one_of option
                       (typically the invalid/edge-case branch)
    """
    if not spec:
        return seed

    strategy = random.choice(
        [_mutate_fresh, _mutate_boundary, _mutate_component_swap])
    try:
        return strategy(seed, spec)
    except Exception:
        return generate_from_spec(spec)


def violate_constraints(seed: str, spec: dict) -> str:
    """
    Intentionally generate a value that breaks the grammar's constraints.
    Walks the spec to find numeric or structured components to violate.

    Used by MutationEngine as the 'constraint_violation' strategy.
    """
    t = spec.get("type", "")

    if t == "int":
        return random.choice([
            str(spec.get("max", 100) + random.randint(1, 1000)),
            str(spec.get("min", 0) - random.randint(1, 1000)),
            "not_an_int",
            "",
        ])

    if t == "hex":
        return random.choice(["GGGG", "0xZZZZ", "-1", ""])

    if t == "sequence" and "count" in spec:
        bad_count = max(0, spec["count"] + random.choice([-2, -1, 1, 3, 8]))
        sep = str(spec.get("separator", ""))
        elem_spec = spec.get("element", {"type": "int", "min": 0, "max": 255})
        elements = [str(generate_from_spec(elem_spec))
                    for _ in range(bad_count)]
        return sep.join(elements)

    if t in ("one_of", "weighted_one_of"):
        # Pick a random option and violate it recursively
        options = spec.get("options", [])
        if options:
            return violate_constraints(seed, random.choice(options))

    if t == "object":
        # Return structurally broken JSON
        return random.choice([
            '{"unclosed": ',
            '{"a": }',
            '{bad json}',
            '',
        ])

    # Generic fallback
    from engine.mutation_engine import insert_special_char
    return insert_special_char(seed)


# ---------------------------------------------------------------------------
# Mutation helpers
# ---------------------------------------------------------------------------

def _mutate_fresh(seed: str, spec: dict) -> str:
    return generate_from_spec(spec)


def _mutate_boundary(seed: str, spec: dict) -> str:
    import copy
    mutated_spec = copy.deepcopy(spec)
    leaves = _collect_numeric_leaves(mutated_spec)
    if not leaves:
        return generate_from_spec(mutated_spec)
    leaf = random.choice(leaves)
    leaf["_boundary"] = leaf.get(
        "min", 0) if random.random() < 0.5 else leaf.get("max", 999)
    return _generate_with_boundary(mutated_spec)


def _mutate_component_swap(seed: str, spec: dict) -> str:
    import copy
    mutated_spec = copy.deepcopy(spec)
    one_of_nodes = _collect_one_of_nodes(mutated_spec)
    if not one_of_nodes:
        return generate_from_spec(mutated_spec)
    node = random.choice(one_of_nodes)
    options = node.get("options", [])
    if options:
        node["_forced_index"] = len(options) - 1
    return _generate_forced(mutated_spec)


def _collect_numeric_leaves(spec: dict) -> list[dict]:
    leaves = []
    if spec.get("type") in ("int", "hex"):
        leaves.append(spec)
    for key in ("element", "key", "key_schema", "value", "value_schema"):
        if key in spec and isinstance(spec[key], dict):
            leaves.extend(_collect_numeric_leaves(spec[key]))
    for part in spec.get("parts", []):
        if isinstance(part, dict):
            leaves.extend(_collect_numeric_leaves(part))
    for opt in spec.get("options", []):
        if isinstance(opt, dict):
            leaves.extend(_collect_numeric_leaves(opt))
    return leaves


def _collect_one_of_nodes(spec: dict) -> list[dict]:
    nodes = []
    if spec.get("type") in ("one_of", "weighted_one_of"):
        nodes.append(spec)
    for key in ("element", "key", "key_schema", "value", "value_schema"):
        if key in spec and isinstance(spec[key], dict):
            nodes.extend(_collect_one_of_nodes(spec[key]))
    for part in spec.get("parts", []):
        if isinstance(part, dict):
            nodes.extend(_collect_one_of_nodes(part))
    for opt in spec.get("options", []):
        if isinstance(opt, dict):
            nodes.extend(_collect_one_of_nodes(opt))
    return nodes


def _generate_with_boundary(spec: dict) -> str:
    if not isinstance(spec, dict):
        return str(spec)
    t = spec.get("type", "")
    if t == "int" and "_boundary" in spec:
        return str(spec["_boundary"])
    if t == "hex" and "_boundary" in spec:
        return format(int(spec["_boundary"]), "x")
    if t in TYPE_GENERATORS:
        return str(TYPE_GENERATORS[t](spec))
    if t in ("sequence", "concat"):
        if "count" in spec and "element" in spec:
            sep = str(spec.get("separator", ""))
            return sep.join(_generate_with_boundary(spec["element"]) for _ in range(spec["count"]))
        return "".join(_generate_with_boundary(p) for p in spec.get("parts", []))
    if t in ("one_of", "weighted_one_of"):
        options = spec.get("options", [])
        weights = [float(o.get("weight", 1.0))
                   for o in options] if options else []
        chosen = random.choices(options, weights=weights, k=1)[
            0] if options else {}
        return _generate_with_boundary(chosen)
    return generate_from_spec(spec)


def _generate_forced(spec: dict) -> str:
    if not isinstance(spec, dict):
        return str(spec)
    t = spec.get("type", "")
    if t in ("one_of", "weighted_one_of") and "_forced_index" in spec:
        options = spec.get("options", [])
        idx = min(spec["_forced_index"], len(options) - 1)
        return _generate_forced(options[idx])
    if t in TYPE_GENERATORS:
        return str(TYPE_GENERATORS[t](spec))
    if t in ("sequence", "concat"):
        if "count" in spec and "element" in spec:
            sep = str(spec.get("separator", ""))
            return sep.join(_generate_forced(spec["element"]) for _ in range(spec["count"]))
        return "".join(_generate_forced(p) for p in spec.get("parts", []))
    if t in ("one_of", "weighted_one_of"):
        options = spec.get("options", [])
        weights = [float(o.get("weight", 1.0))
                   for o in options] if options else []
        chosen = random.choices(options, weights=weights, k=1)[
            0] if options else {}
        return _generate_forced(chosen)
    return generate_from_spec(spec)


# ---------------------------------------------------------------------------
# File-based seed generation
# ---------------------------------------------------------------------------

def generate_seeds_from_yaml(yaml_path: str, count: int | None = None) -> list[str]:
    """Generate seeds from a YAML grammar config and write to seeds_path."""
    with open(yaml_path) as f:
        config = yaml.safe_load(f)

    seed_count = count or config.get("seed_count", 10)
    input_spec = config.get("input")
    if not input_spec:
        print(f"[warn] No 'input:' grammar block found in {yaml_path}")
        return []

    seeds = [generate_from_spec(input_spec) for _ in range(seed_count)]

    seeds_path = config.get("seeds_path", "seeds.txt")
    os.makedirs(os.path.dirname(os.path.abspath(seeds_path)), exist_ok=True)
    with open(seeds_path, "w") as f:
        for s in seeds:
            f.write(str(s) + "\n")

    print(f"[+] Generated {len(seeds)} seeds → {seeds_path}")
    return seeds


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        description="Generalised grammar-based seed generator")
    parser.add_argument("yaml_file", help="Path to YAML grammar config")
    parser.add_argument("--count", type=int,
                        help="Number of seeds to generate")
    args = parser.parse_args()
    generate_seeds_from_yaml(args.yaml_file, args.count)
