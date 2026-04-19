from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto


class BugType(Enum):
    VALIDITY = auto() # Occurs when input fed is syntactically correct but semantically wrong
    INVALIDITY = auto() # occurs when input fed is syntactically incorrect
    PERFORMANCE = auto() # occurs when inputs cause a delay in the execution of the program, execution time deviates from normal. 
    FUNCTIONAL = auto() # when the program behaves abmormally in thee presence of certain inputs, semantically incorrect behaviour
    BOUNDARY = auto() # bugs that occur at the boundary values of the accepted input range
    RELIABILITY = auto() # covers bug_oracle's CRASH too (unexpected non-zero exit)
    BONUS = auto() # bugs which are not seeded and are raised for certain inputs

    SYNTACTIC = auto()  # AddrFormatError / SyntaxError
    TIMEOUT = auto()  # process killed by timeout
    MISMATCH = auto()  # normalised output differs from reference
    NORMAL = auto()  # clean run
    ERROR = auto()  # fuzzer-level failure


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
        return self.bug_type not in (BugType.NORMAL, BugType.ERROR)

    def is_seeded(self) -> bool:
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
        return self.bug_type.name
