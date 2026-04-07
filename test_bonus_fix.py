#!/usr/bin/env python3
"""
Test the updated oracle bonus bug detection.
Specifically tests that unhandled JSONDecodeError/CidrizeError in Traceback are BONUS.
"""

import sys
sys.path.insert(0, 'forza')

from engine.bug_oracle import BugOracle
from engine.target_runner import RawResult
from engine.types import BugType

oracle = BugOracle()

# Test 1: Unhandled JSONDecodeError (in Traceback) — should be BONUS
print("=" * 70)
print("TEST 1: Unhandled JSONDecodeError with Traceback → BONUS")
print("=" * 70)

test_output_1 = """Loading existing coverage data from .coverage_buggy_json

An unknown exception has been triggered. 'str' object is not subscriptable
============================================================
TRACEBACK
============================================================
Traceback (most recent call last):
  File "C:/path/to/json_decoder/json_decoder_stv.py", line 262, in <module>
    data = loads(args.str_json)
  File "C:/path/to/buggy_json/__init__.py", line 134, in loads
    return _default_decoder.decode(s)
  File "C:/path/to/buggy_json/decoder_stv.py", line 366, in decode
    obj, end = self.raw_decode(s, idx=_w(s, 0).end())
buggy_json.decoder_stv.JSONDecodeError: Expecting value: line 1 column 1 (char 0)
"""

raw1 = RawResult(
    stdout=test_output_1,
    stderr="",
    returncode=0,
    timed_out=False,
    crashed=False,
    error=None,
    input_data=b"test",
)

bug1 = oracle.classify(raw1, "test_input", "json_decoder", config={"bug_keywords": []})
print(f"Output contains 'Traceback': {'Traceback (most recent' in test_output_1}")
print(f"Output contains 'JSONDecodeError': {'JSONDecodeError' in test_output_1}")
print(f"Bug Type: {bug1.bug_type}")
print(f"Expected: {BugType.BONUS}")
print(f"✓ PASS" if bug1.bug_type == BugType.BONUS else f"✗ FAIL")
print()

# Test 2: Handled JSONDecodeError (caught, logged) — should be INVALIDITY
print("=" * 70)
print("TEST 2: Handled JSONDecodeError with 'invalidity bug' → INVALIDITY")
print("=" * 70)

test_output_2 = """Loading existing coverage data from .coverage_buggy_json

An invalidity bug has been triggered: Expecting value: line 1 column 1 (char 0)
============================================================
TRACEBACK
============================================================
============================================================
Saved bug count report and tracebacks for the bugs encountered!
Final bug count: defaultdict(<class 'int'>, {('invalidity', <class 'buggy_json.decoder_stv.JSONDecodeError'>, 'Expecting value: line 1 column 1 (char 0)', 'C:\\\\path\\\\decoder_stv.py', 210): 1})
"""

raw2 = RawResult(
    stdout=test_output_2,
    stderr="",
    returncode=0,
    timed_out=False,
    crashed=False,
    error=None,
    input_data=b"test",
)

bug2 = oracle.classify(raw2, "test_input", "json_decoder", config={"bug_keywords": []})
print(f"Output contains 'Final bug count': {'Final bug count' in test_output_2}")
print(f"Output contains 'invalidity': {'invalidity' in test_output_2}")
print(f"Bug Type: {bug2.bug_type}")
print(f"Expected: {BugType.INVALIDITY}")
print(f"✓ PASS" if bug2.bug_type == BugType.INVALIDITY else f"✗ FAIL")
print()

# Test 3: CidrizeError unhandled (in Traceback) — should be BONUS
print("=" * 70)
print("TEST 3: Unhandled CidrizeError with Traceback → BONUS")
print("=" * 70)

test_output_3 = """Traceback (most recent call last):
  File "cidrize.py", line 50, in parse_network
    result = IPNetwork(cidr_str)
  File "cidrize_lib.py", line 100, in __init__
    raise CidrizeError(f"Invalid CIDR: {self}")
cidrize.CidrizeError: Invalid CIDR: 999.999.999.999/32
"""

raw3 = RawResult(
    stdout=test_output_3,
    stderr="",
    returncode=0,
    timed_out=False,
    crashed=False,
    error=None,
    input_data=b"999.999.999.999/32",
)

bug3 = oracle.classify(raw3, "999.999.999.999/32", "cidrize", config={"bug_keywords": []})
print(f"Output contains 'Traceback': {'Traceback (most recent' in test_output_3}")
print(f"Output contains 'CidrizeError': {'CidrizeError' in test_output_3}")
print(f"Bug Type: {bug3.bug_type}")
print(f"Expected: {BugType.BONUS}")
print(f"✓ PASS" if bug3.bug_type == BugType.BONUS else f"✗ FAIL")
print()

# Summary
print("=" * 70)
print("SUMMARY")
print("=" * 70)
results = [
    ("Unhandled JSONDecodeError (Traceback)", bug1.bug_type == BugType.BONUS),
    ("Handled JSONDecodeError (invalidity bug)", bug2.bug_type == BugType.INVALIDITY),
    ("Unhandled CidrizeError (Traceback)", bug3.bug_type == BugType.BONUS),
]
passed = sum(1 for _, result in results if result)
for name, result in results:
    print(f"  {'✓' if result else '✗'} {name}")
print(f"\nTotal: {passed}/{len(results)} passed")
