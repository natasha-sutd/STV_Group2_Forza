'''
Generalized grammar-based seed generator.
Generates seeds for inital corpus based on the input format specified in the target's YAML config.
'''


import yaml
import random
import string
import os

# Registry of built-in type generators
TYPE_GENERATORS = {}

def register_type(name):
    """Decorator to register a generator function for a type"""
    def decorator(func):
        TYPE_GENERATORS[name] = func
        return func
    return decorator

# Built-in types
@register_type("int")
def gen_int(spec):
    return str(random.randint(spec.get("min", 0), spec.get("max", 100)))

@register_type("hex")
def gen_hex(spec):
    return format(random.randint(spec.get("min", 0), spec.get("max", 65535)), "x")

@register_type("string")
def gen_string(spec):
    length = random.randint(spec.get("min", 1), spec.get("max", 10))
    chars = spec.get("chars", string.ascii_letters)
    return ''.join(random.choice(chars) for _ in range(length))

@register_type("boolean")
def gen_boolean(spec):
    return random.choice([True, False])

@register_type("literal")
def gen_literal(spec):
    return spec.get("value", "")

@register_type("array")
def gen_array(spec):
    length = random.randint(spec.get("min_length", 1), spec.get("max_length", 3))
    element_spec = spec["element"]
    return [generate_from_spec(element_spec) for _ in range(length)]

@register_type("random_object")
def gen_random_object(spec):
    obj = {}
    n_fields = random.randint(1, spec.get("max_fields", 3))
    for _ in range(n_fields):
        key = generate_from_spec(spec["key"])
        value = generate_from_spec(spec["value"])
        obj[key] = value
    return str(obj)

# Recursive seed generator
def generate_from_spec(spec):
    """Recursively generate a seed from a grammar spec"""
    t = spec.get("type")
    if t in TYPE_GENERATORS:
        return TYPE_GENERATORS[t](spec)

    # Sequence: concatenate all parts
    elif t == "sequence" or t == "concat":
        return "".join(generate_from_spec(p) for p in spec.get("parts", []))

    # One-of: choose one option randomly
    elif t == "one_of":
        choice = random.choice(spec.get("options", []))
        return generate_from_spec(choice)

    # Unknown type fallback
    return ""

# Generate seeds from YAML
def generate_seeds_from_yaml(yaml_path, count=None):
    with open(yaml_path, "r") as f:
        config = yaml.safe_load(f)

    seed_count = count or config.get("seed_count", 10)
    seeds = []

    for _ in range(seed_count):
        seed = generate_from_spec(config["input"])
        seeds.append(seed)

    seeds_path = config.get("seeds_path", "seeds.txt")
    os.makedirs(os.path.dirname(seeds_path), exist_ok=True)
    with open(seeds_path, "w") as f:
        for s in seeds:
            f.write(s + "\n")

    print(f"[+] Generated {len(seeds)} seeds at {seeds_path}")
    return seeds

# CLI
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Generalized Grammar-based Seed Generator")
    parser.add_argument("yaml_file", help="Path to YAML grammar config")
    parser.add_argument("--count", type=int, help="Number of seeds to generate")
    args = parser.parse_args()

    generate_seeds_from_yaml(args.yaml_file, args.count)
