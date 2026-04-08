from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto


class BugType(Enum):
    VALIDITY = auto()  # Occurs when input fed is syntactically correct but semantically wrong
    INVALIDITY = auto()  # occurs when input fed is syntactically incorrect
    # occurs when inputs cause a delay in the execution of the program, execution time deviates from normal.
    PERFORMANCE = auto()
    FUNCTIONAL = auto()  # when the program behaves abmormally in thee presence of certain inputs, semantically incorrect behaviour
    BOUNDARY = auto()  # bugs that occur at the boundary values of the accepted input range
    RELIABILITY = auto()  # covers bug_oracle's CRASH too (unexpected non-zero exit)
    BONUS = auto()  # bugs which are not seeded and are raised for certain inputs

    SYNTACTIC = auto()  # AddrFormatError / SyntaxError
    TIMEOUT = auto()  # process killed by timeout
    MISMATCH = auto()  # normalised output differs from reference
    NORMAL = auto()  # clean run
    ERROR = auto()  # fuzzer-level failure


# ---------------------------------------------------------------------------
# Keyword → BugType mapping
#
# classify_from_keywords() scans stdout+stderr for these strings in order.
# First match wins — so higher-specificity strings must come first.
# Used by both fuzzer.py (_classify_inline) and bug_oracle.py.
# ---------------------------------------------------------------------------
KEYWORD_TO_BUGTYPE: list[tuple[str, BugType]] = [
    ("ValidityBug",             BugType.VALIDITY),
    ("invalidity bug",          BugType.INVALIDITY),
    ("InvalidityBug",           BugType.INVALIDITY),
    ("InvalidCidrFormatError",  BugType.INVALIDITY),
    ("PerformanceBug",          BugType.PERFORMANCE),
    ("FunctionalBug",           BugType.FUNCTIONAL),
    ("BoundaryBug",             BugType.BOUNDARY),
    ("ReliabilityBug",          BugType.RELIABILITY),
    ("bug has been triggered",  BugType.RELIABILITY),
    ("AddrFormatError",         BugType.SYNTACTIC),
    ("syntactic",               BugType.SYNTACTIC),
    ("syntax error",            BugType.SYNTACTIC),
    ("JSONDecodeError",         BugType.BONUS),
    ("CidrizeError",            BugType.BONUS),
    ("Traceback (most recent",  BugType.BONUS),
]


def classify_from_keywords(stdout: str, stderr: str) -> BugType | None:
    combined = stdout + stderr
    for keyword, bug_type in KEYWORD_TO_BUGTYPE:
        if keyword in combined:
            return bug_type
    return None


@dataclass
class BugResult:
    bug_type: BugType
    bug_key: str
    input_data: str
    target: str
    strategy: str = ""
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0
    timed_out: bool = False
    crashed: bool = False
    new_coverage: bool = False
    exec_time_ms: float = 0.0

    def is_bug(self) -> bool:
        """True for any result that should be logged (everything except NORMAL and ERROR)."""
        return self.bug_type not in (BugType.NORMAL, BugType.ERROR)

    def is_seeded(self) -> bool:
        """
        True for the seeded bug types from the project PDF + SYNTACTIC
        (cidrize-specific). These are the types that earn graded marks.
        """
        return self.bug_type in (
            BugType.VALIDITY,
            BugType.INVALIDITY,
            BugType.PERFORMANCE,
            BugType.FUNCTIONAL,
            BugType.BOUNDARY,
            BugType.RELIABILITY,
            BugType.SYNTACTIC,
        )

    def label(self) -> str:
        """Short human-readable label for terminal output."""
        return self.bug_type.name
