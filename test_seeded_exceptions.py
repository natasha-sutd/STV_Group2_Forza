#!/usr/bin/env python3
"""
Test all 5 major seeded exception types:
- PerformanceBug → PERFORMANCE
- FunctionalBug → FUNCTIONAL
- BoundaryBug → BOUNDARY
- ReliabilityBug → RELIABILITY
- ValidityBug → VALIDITY
"""

import sys
sys.path.insert(0, 'forza')

from engine.bug_oracle import BugOracle
from engine.target_runner import RawResult
from engine.types import BugType

oracle = BugOracle()

# Test 1: PerformanceBug
print("=" * 70)
print("TEST 1: PerformanceBug → PERFORMANCE")
print("=" * 70)

test_output_1 = """Processing input...
A performance bug has been triggered: while True loop detected
============================================================
TRACEBACK
============================================================
Traceback (most recent call last):
  File "decoder.py", line 200, in decode_value
    raise PerformanceBug("Infinite loop detected in parsing")
buggy_json.decoder_stv.PerformanceBug: Infinite loop detected in parsing
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

bug1 = oracle.classify(raw1, "test_input", "json_decoder", config={})
print(f"Contains 'PerformanceBug': {'PerformanceBug' in test_output_1}")
print(f"Bug Type: {bug1.bug_type}")
print(f"Expected: {BugType.PERFORMANCE}")
print(f"✓ PASS" if bug1.bug_type == BugType.PERFORMANCE else f"✗ FAIL")
print()

# Test 2: FunctionalBug (already has explicit detection)
print("=" * 70)
print("TEST 2: FunctionalBug → FUNCTIONAL")
print("=" * 70)

test_output_2 = """Processing input...
A functional bug has been triggered: incorrect result
============================================================
TRACEBACK
============================================================
Traceback (most recent call last):
  File "decoder.py", line 150, in compute
    raise FunctionalBug("Result is semantically wrong: expected 5, got 3")
buggy_json.decoder_stv.FunctionalBug: Result is semantically wrong: expected 5, got 3
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

bug2 = oracle.classify(raw2, "test_input", "json_decoder", config={})
print(f"Contains 'FunctionalBug': {'FunctionalBug' in test_output_2}")
print(f"Contains 'functional bug' (lowercase): {'functional bug' in test_output_2}")
print(f"Bug Type: {bug2.bug_type}")
print(f"Expected: {BugType.FUNCTIONAL}")
print(f"✓ PASS" if bug2.bug_type == BugType.FUNCTIONAL else f"✗ FAIL")
print()

# Test 3: BoundaryBug
print("=" * 70)
print("TEST 3: BoundaryBug → BOUNDARY")
print("=" * 70)

test_output_3 = """Processing input...
A boundary bug has been triggered: off-by-one error
============================================================
TRACEBACK
============================================================
Traceback (most recent call last):
  File "decoder.py", line 75, in parse_array
    raise BoundaryBug("Array index out of bounds by 1")
buggy_json.decoder_stv.BoundaryBug: Array index out of bounds by 1
"""

raw3 = RawResult(
    stdout=test_output_3,
    stderr="",
    returncode=0,
    timed_out=False,
    crashed=False,
    error=None,
    input_data=b"test",
)

bug3 = oracle.classify(raw3, "test_input", "json_decoder", config={})
print(f"Contains 'BoundaryBug': {'BoundaryBug' in test_output_3}")
print(f"Bug Type: {bug3.bug_type}")
print(f"Expected: {BugType.BOUNDARY}")
print(f"✓ PASS" if bug3.bug_type == BugType.BOUNDARY else f"✗ FAIL")
print()

# Test 4: ReliabilityBug
print("=" * 70)
print("TEST 4: ReliabilityBug → RELIABILITY")
print("=" * 70)

test_output_4 = """Processing input...
A reliability bug has been triggered: null pointer
============================================================
TRACEBACK
============================================================
Traceback (most recent call last):
  File "decoder.py", line 120, in safe_access
    raise ReliabilityBug("Null pointer dereference")
buggy_json.decoder_stv.ReliabilityBug: Null pointer dereference
"""

raw4 = RawResult(
    stdout=test_output_4,
    stderr="",
    returncode=0,
    timed_out=False,
    crashed=False,
    error=None,
    input_data=b"test",
)

bug4 = oracle.classify(raw4, "test_input", "json_decoder", config={})
print(f"Contains 'ReliabilityBug': {'ReliabilityBug' in test_output_4}")
print(f"Bug Type: {bug4.bug_type}")
print(f"Expected: {BugType.RELIABILITY}")
print(f"✓ PASS" if bug4.bug_type == BugType.RELIABILITY else f"✗ FAIL")
print()

# Test 5: ValidityBug
print("=" * 70)
print("TEST 5: ValidityBug → VALIDITY")
print("=" * 70)

test_output_5 = """Processing input...
A validity bug has been triggered: semantic error
============================================================
TRACEBACK
============================================================
Traceback (most recent call last):
  File "decoder.py", line 300, in validate
    raise ValidityBug("Value 2025-13-01 is not a valid date")
buggy_json.decoder_stv.ValidityBug: Value 2025-13-01 is not a valid date
"""

raw5 = RawResult(
    stdout=test_output_5,
    stderr="",
    returncode=0,
    timed_out=False,
    crashed=False,
    error=None,
    input_data=b"test",
)

bug5 = oracle.classify(raw5, "test_input", "json_decoder", config={})
print(f"Contains 'ValidityBug': {'ValidityBug' in test_output_5}")
print(f"Bug Type: {bug5.bug_type}")
print(f"Expected: {BugType.VALIDITY}")
print(f"✓ PASS" if bug5.bug_type == BugType.VALIDITY else f"✗ FAIL")
print()

# Test 6: Via Traceback detection (classify_from_keywords)
print("=" * 70)
print("TEST 6: Detect via KEYWORD_TO_BUGTYPE mapping")
print("=" * 70)

from engine.types import classify_from_keywords

test_cases = [
    ("Traceback\nPerformanceBug: timeout", BugType.PERFORMANCE),
    ("Traceback\nFunctionalBug: wrong result", BugType.FUNCTIONAL),
    ("Traceback\nBoundaryBug: off-by-one", BugType.BOUNDARY),
    ("Traceback\nReliabilityBug: crash", BugType.RELIABILITY),
    ("Traceback\nValidityBug: invalid", BugType.VALIDITY),
]

all_pass = True
for output, expected_type in test_cases:
    result = classify_from_keywords(output, "")
    passed = result == expected_type
    all_pass = all_pass and passed
    print(f"  {'✓' if passed else '✗'} {expected_type.name}: {output[:30]}...")

print()

# Summary
print("=" * 70)
print("SUMMARY")
print("=" * 70)
results = [
    ("PerformanceBug → PERFORMANCE", bug1.bug_type == BugType.PERFORMANCE),
    ("FunctionalBug → FUNCTIONAL", bug2.bug_type == BugType.FUNCTIONAL),
    ("BoundaryBug → BOUNDARY", bug3.bug_type == BugType.BOUNDARY),
    ("ReliabilityBug → RELIABILITY", bug4.bug_type == BugType.RELIABILITY),
    ("ValidityBug → VALIDITY", bug5.bug_type == BugType.VALIDITY),
    ("KEYWORD_TO_BUGTYPE mappings", all_pass),
]
passed = sum(1 for _, result in results if result)
for name, result in results:
    print(f"  {'✓' if result else '✗'} {name}")
print(f"\nTotal: {passed}/{len(results)} passed")
