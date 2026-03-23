"""
engine/mutation_engine.py

AFL-style weighted mutation engine.
- Each strategy starts with an equal base weight.
- When a mutation strategy finds new coverage, its weight is boosted (energy recalibration).
- Strategy is selected via weighted random each iteration.
- Format-aware strategies are applied only when input_format matches (set in YAML).

Updated based on generalization:
Generalized AFL-style mutation engine.
Mutates seeds in a format-agnostic way using grammar-aware strategies when available.

No external libraries used — all mutation logic written from scratch.
"""

import random
import string
import subprocess


# ── Constants ────────────────────────────────────────────────────────────────

# Characters commonly used to break parsers
SPECIAL_CHARS = [
    "\x00",         # null byte
    "\xff",         # max byte
    "\n", "\r",     # newlines
    "\\",           # backslash
    "\"", "'",      # quotes
    "{", "}", "[", "]",  # brackets
    "<", ">",       # angle brackets (XML/HTML confusion)
    "/../",         # path traversal
    "%00",          # URL-encoded null
    "&&", "||",     # shell injection
    "999999999999999999999999",  # integer overflow bait
]


# ── Individual mutation strategies ───────────────────────────────────────────

def bit_flip(data: str) -> str:
    """Flip a random bit in a random character of the input."""
    if not data:
        return data
    idx = random.randint(0, len(data) - 1)
    char_code = ord(data[idx])
    bit = 1 << random.randint(0, 7)
    flipped = chr(char_code ^ bit)
    return data[:idx] + flipped + data[idx + 1:]


def truncate(data: str) -> str:
    """Cut the input short at a random position."""
    if len(data) <= 1:
        return data
    cut = random.randint(0, len(data) - 1)
    return data[:cut]


def insert_special_char(data: str) -> str:
    """Insert a special/bad character at a random position."""
    if not data:
        return random.choice(SPECIAL_CHARS)
    idx = random.randint(0, len(data))
    char = random.choice(SPECIAL_CHARS)
    return data[:idx] + char + data[idx:]


def repeat_chunk(data: str) -> str:
    """Duplicate a random slice of the input (stress-tests length handling)."""
    if len(data) < 2:
        return data * 2
    start = random.randint(0, len(data) - 1)
    end = random.randint(start + 1, len(data))
    chunk = data[start:end]
    repeat = random.randint(2, 10)
    return data[:start] + chunk * repeat + data[end:]


def byte_insert(data: str) -> str:
    """Insert a random printable ASCII character at a random position."""
    idx = random.randint(0, len(data))
    char = random.choice(string.printable)
    return data[:idx] + char + data[idx:]


def swap_chars(data: str) -> str:
    """Swap two random characters in the input."""
    if len(data) < 2:
        return data
    i, j = random.sample(range(len(data)), 2)
    lst = list(data)
    lst[i], lst[j] = lst[j], lst[i]
    return "".join(lst)


# ── Radamsa mutation ─────────────────────────────────────────────────────────

def radamsa_mutate(data: str) -> str:
    """Mutate data using external Radamsa."""
    try:
        p = subprocess.Popen(["radamsa"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        out, _ = p.communicate(data.encode())
        return out.decode(errors="ignore")
    except Exception:
        return data


# ── Grammar-aware mutation hooks ───────────────────────────────────────────

def grammar_aware_mutate(data: str) -> str:
    """Fallback generic mutation for any structured grammar input"""
    # Currently just random byte/char insert, extendable later per type
    return insert_special_char(repeat_chunk(data))


# ── Strategy registry ────────────────────────────────────────────────────────
# Each entry: (name, function, base_weight, applicable_formats)
# applicable_formats: list of input_format values this strategy applies to,
#                     or ["*"] for all formats.

STRATEGIES = [
    ("bit_flip",                bit_flip,             1.0, ["*"]),
    ("truncate",                truncate,             1.0, ["*"]),
    ("insert_special_char",     insert_special_char,  1.0, ["*"]),
    ("repeat_chunk",            repeat_chunk,         1.0, ["*"]),
    ("byte_insert",             byte_insert,          1.0, ["*"]),
    ("swap_chars",              swap_chars,           1.0, ["*"]),
    ("grammar_aware_mutate",    grammar_aware_mutate, 1.5, ["*"]),
    ("radamsa",                 radamsa_mutate,       2.0, ["*"]),
]


# ── MutationEngine class ─────────────────────────────────────────────────────

class MutationEngine:
    """
    AFL-style weighted mutation engine.

    Usage:
        engine = MutationEngine(input_format="*")
        - input_format="*" : generic mode, applies all generic mutations and grammar-aware mutation.
        - Format-specific mutations (e.g., JSON-aware, IP-aware) are ignored
          if seeds are not explicitly labeled with a format in the YAML.
    """

    def __init__(self, input_format: str = "*"):
        """
        Parameters
        ----------
        input_format : str
            '*' for generic (fully format-agnostic).
            Other values (e.g., 'json', 'ipv4') can enable format-aware mutations, if seeds are labeled accordingly.
        """
        self.input_format = input_format

        # Build the active strategy list filtered by input_format
        self.strategies = [
            {"name": name, "fn": fn, "weight": weight}
            for name, fn, weight, formats in STRATEGIES
            if "*" in formats or input_format in formats
        ]

    def mutate(self, seed: str) -> str:
        """
        Pick a strategy via weighted random selection (AFL-style)
        and return a mutated version of the seed.
        """
        chosen = self._weighted_choice()
        try:
            return chosen["fn"](seed)
        except Exception:
            # If a strategy fails on an unusual input, fall back to truncation
            return truncate(seed) if seed else seed

    def boost(self, strategy_name: str, factor: float = 1.5) -> None:
        """
        Boost the weight of a strategy that found new coverage.
        Called by coverage_tracker when a mutated input increases coverage.

        Parameters
        ----------
        strategy_name : name of the strategy to boost
        factor        : multiplier applied to the current weight
        """
        for s in self.strategies:
            if s["name"] == strategy_name:
                s["weight"] *= factor
                return

    def decay(self, factor: float = 0.95) -> None:
        """
        Slightly decay all weights each iteration to prevent
        one strategy dominating forever (AFL-style energy decay).
        """
        for s in self.strategies:
            s["weight"] = max(0.1, s["weight"] * factor)

    def get_last_strategy(self) -> str:
        """Return the name of the last strategy used (for coverage_tracker to call boost)."""
        # return self._last_strategy
        return getattr(self, "_last_strategy", "unknown")

    def _weighted_choice(self) -> dict:
        """Select a strategy using weighted random sampling."""
        total = sum(s["weight"] for s in self.strategies)
        pick = random.uniform(0, total)
        cumulative = 0.0
        for s in self.strategies:
            cumulative += s["weight"]
            if pick <= cumulative:
                self._last_strategy = s["name"]
                return s
        self._last_strategy = self.strategies[-1]["name"]
        return self.strategies[-1]


# ── Quick manual test ────────────────────────────────────────────────────────
# Run directly to see mutations in action:
#   python engine/mutation_engine.py

if __name__ == "__main__":
    print("=== JSON mutations ===")
    engine = MutationEngine(input_format="json")
    seed = '{"name": "alice", "age": 30}'
    for i in range(8):
        mutated = engine.mutate(seed)
        print(f"[{engine.get_last_strategy():25s}] {repr(mutated)}")
        engine.decay()

    print("\n=== IP mutations ===")
    engine = MutationEngine(input_format="ip")
    seed = "192.168.1.1"
    for i in range(8):
        mutated = engine.mutate(seed)
        print(f"[{engine.get_last_strategy():25s}] {repr(mutated)}")
        engine.decay()

    print("\n=== Weight boosting demo ===")
    engine = MutationEngine(input_format="json")
    print("Before boost:", {s["name"]: round(s["weight"], 2) for s in engine.strategies})
    engine.boost("json_aware_mutate")
    engine.boost("json_aware_mutate")
    print("After 2x boost:", {s["name"]: round(s["weight"], 2) for s in engine.strategies})