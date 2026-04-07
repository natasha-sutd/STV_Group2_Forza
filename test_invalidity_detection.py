#!/usr/bin/env python3
"""
Test InvalidityBug and InvalidCidrFormatError detection.
"""

import sys
sys.path.insert(0, 'forza')

from engine.bug_oracle import BugOracle
from engine.target_runner import RawResult
from engine.types import BugType

oracle = BugOracle()

# Test 1: InvalidityBug exception (json_decoder)
print("=" * 70)
print("TEST 1: InvalidityBug exception → INVALIDITY")
print("=" * 70)

test_output_1 = """An invalidity bug has been triggered: Incorrect hex length!
============================================================
TRACEBACK
============================================================
Traceback (most recent call last):
  File "decoder_stv.py", line 100, in _decode_uXXXX
    raise InvalidityBug("Incorrect hex length!")
buggy_json.decoder_stv.InvalidityBug: Incorrect hex length!
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
print(f"Contains 'InvalidityBug': {'InvalidityBug' in test_output_1}")
print(f"Bug Type: {bug1.bug_type}")
print(f"Expected: {BugType.INVALIDITY}")
print(f"✓ PASS" if bug1.bug_type == BugType.INVALIDITY else f"✗ FAIL")
print()

# Test 2: InvalidCidrFormatError exception (cidrize)
print("=" * 70)
print("TEST 2: InvalidCidrFormatError exception → INVALIDITY")
print("=" * 70)

test_output_2 = """Error processing CIDR: 999.999.999.999/32
Traceback (most recent call last):
  File "cidrize.py", line 50, in parse_network
    raise InvalidCidrFormatError(f"Invalid network: {cidr_str}")
cidrize.InvalidCidrFormatError: Invalid network: 999.999.999.999/32
"""

raw2 = RawResult(
    stdout=test_output_2,
    stderr="",
    returncode=0,
    timed_out=False,
    crashed=False,
    error=None,
    input_data=b"999.999.999.999/32",
)

bug2 = oracle.classify(raw2, "999.999.999.999/32", "cidrize", config={})
print(f"Contains 'InvalidCidrFormatError': {'InvalidCidrFormatError' in test_output_2}")
print(f"Bug Type: {bug2.bug_type}")
print(f"Expected: {BugType.INVALIDITY}")
print(f"✓ PASS" if bug2.bug_type == BugType.INVALIDITY else f"✗ FAIL")
print()

# Test 3: Keyword "invalidity" still works
print("=" * 70)
print("TEST 3: Keyword 'invalidity' → INVALIDITY")
print("=" * 70)

test_output_3 = """An invalidity bug has been triggered: Extra data on line
============================================================
TRACEBACK
============================================================
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
print(f"Contains 'invalidity': {'invalidity' in test_output_3}")
print(f"Bug Type: {bug3.bug_type}")
print(f"Expected: {BugType.INVALIDITY}")
print(f"✓ PASS" if bug3.bug_type == BugType.INVALIDITY else f"✗ FAIL")
print()

# Test 4: Check extraction of exception message
print("=" * 70)
print("TEST 4: Exception message extraction")
print("=" * 70)

test_output_4 = """Error!
Traceback (most recent call last):
  File "test.py", line 10, in decode
    raise InvalidityBug("This is a detailed error message about hex")
buggy_json.decoder_stv.InvalidityBug: This is a detailed error message about hex
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
print(f"Bug Type: {bug4.bug_type}")
print(f"Bug Key: {bug4.bug_key}")
print(f"Expected type: {BugType.INVALIDITY}")
print(f"✓ PASS" if bug4.bug_type == BugType.INVALIDITY else f"✗ FAIL")
print()

# Test 5: Distinguish from BONUS (unhandled JSONDecodeError)
print("=" * 70)
print("TEST 5: JSONDecodeError in Traceback (not InvalidityBug) → BONUS")
print("=" * 70)

test_output_5 = """Unexpected error occurred!
Traceback (most recent call last):
  File "decoder.py", line 50, in parse
    return json.loads(data)
buggy_json.decoder_stv.JSONDecodeError: Expecting value: line 1 column 1
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
print(f"Contains 'Traceback': {'Traceback (most recent' in test_output_5}")
print(f"Contains 'JSONDecodeError': {'JSONDecodeError' in test_output_5}")
print(f"Contains 'InvalidityBug': {'InvalidityBug' in test_output_5}")
print(f"Bug Type: {bug5.bug_type}")
print(f"Expected: {BugType.BONUS}")
print(f"✓ PASS" if bug5.bug_type == BugType.BONUS else f"✗ FAIL")
print()

# Summary
print("=" * 70)
print("SUMMARY")
print("=" * 70)
results = [
    ("InvalidityBug exception", bug1.bug_type == BugType.INVALIDITY),
    ("InvalidCidrFormatError exception", bug2.bug_type == BugType.INVALIDITY),
    ("Keyword 'invalidity'", bug3.bug_type == BugType.INVALIDITY),
    ("Message extraction", bug4.bug_type == BugType.INVALIDITY),
    ("Distinguish BONUS (JSONDecodeError)", bug5.bug_type == BugType.BONUS),
]
passed = sum(1 for _, result in results if result)
for name, result in results:
    print(f"  {'✓' if result else '✗'} {name}")
print(f"\nTotal: {passed}/{len(results)} passed")
