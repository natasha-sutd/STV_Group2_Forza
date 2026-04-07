#!/usr/bin/env python3
"""
Comprehensive test of ALL bug types to ensure oracle is 100% correct.
Tests all 11 bug types in the taxonomy.
"""

import sys
sys.path.insert(0, 'forza')

from engine.bug_oracle import BugOracle
from engine.target_runner import RawResult
from engine.types import BugType

oracle = BugOracle()

print("=" * 70)
print("COMPREHENSIVE ORACLE BUG TYPE TEST")
print("=" * 70)
print()

test_cases = []

# 1. TIMEOUT
print("1. TIMEOUT")
raw = RawResult(stdout="", stderr="", returncode=-1, timed_out=True, crashed=False, error=None, input_data=b"")
bug = oracle.classify(raw, "input", "target", config={})
passed = bug.bug_type == BugType.TIMEOUT
test_cases.append(("TIMEOUT", passed))
print(f"   {'✓' if passed else '✗'} Got {bug.bug_type}")
print()

# 2. Structured Final bug count (json_decoder)
print("2. STRUCTURED (Final bug count)")
stdout = """Final bug count: defaultdict(<class 'int'>, {('validity', <class 'buggy_json.decoder_stv.ValidityBug'>, 'invalid date', 'decoder.py', 100): 1})"""
raw = RawResult(stdout=stdout, stderr="", returncode=0, timed_out=False, crashed=False, error=None, input_data=b"")
bug = oracle.classify(raw, "input", "target", config={})
passed = bug.bug_type == BugType.VALIDITY
test_cases.append(("STRUCTURED (validity)", passed))
print(f"   {'✓' if passed else '✗'} Got {bug.bug_type}")
print()

# 3. BONUS (unhandled JSONDecodeError with Traceback)
print("3. BONUS (unhandled JSONDecodeError + Traceback)")
stdout = """Error!
Traceback (most recent call last):
  File "test.py", line 10
    raise JSONDecodeError("msg")
buggy_json.decoder_stv.JSONDecodeError: Expecting value"""
raw = RawResult(stdout=stdout, stderr="", returncode=0, timed_out=False, crashed=False, error=None, input_data=b"")
bug = oracle.classify(raw, "input", "target", config={})
passed = bug.bug_type == BugType.BONUS
test_cases.append(("BONUS (JSONDecodeError)", passed))
print(f"   {'✓' if passed else '✗'} Got {bug.bug_type}")
print()

# 4. INVALIDITY (InvalidityBug exception)
print("4. INVALIDITY (InvalidityBug exception)")
stdout = """Traceback (most recent call last):
  File "test.py", line 10
    raise InvalidityBug("hex error")
buggy_json.decoder_stv.InvalidityBug: Incorrect hex length!"""
raw = RawResult(stdout=stdout, stderr="", returncode=0, timed_out=False, crashed=False, error=None, input_data=b"")
bug = oracle.classify(raw, "input", "target", config={})
passed = bug.bug_type == BugType.INVALIDITY
test_cases.append(("INVALIDITY (InvalidityBug)", passed))
print(f"   {'✓' if passed else '✗'} Got {bug.bug_type}")
print()

# 5. SYNTACTIC (AddrFormatError)
print("5. SYNTACTIC (AddrFormatError exception)")
stdout = """Traceback (most recent call last):
  File "cidrize.py", line 50
    raise AddrFormatError("Invalid CIDR")
cidrize.AddrFormatError: Invalid network format"""
raw = RawResult(stdout=stdout, stderr="", returncode=0, timed_out=False, crashed=False, error=None, input_data=b"")
bug = oracle.classify(raw, "input", "target", config={})
passed = bug.bug_type == BugType.SYNTACTIC
test_cases.append(("SYNTACTIC (AddrFormatError)", passed))
print(f"   {'✓' if passed else '✗'} Got {bug.bug_type}")
print()

# 6. PERFORMANCE
print("6. PERFORMANCE (PerformanceBug exception)")
stdout = """Traceback (most recent call last):
  File "test.py", line 20
    raise PerformanceBug("infinite loop")
buggy_json.decoder_stv.PerformanceBug: Timeout in while loop"""
raw = RawResult(stdout=stdout, stderr="", returncode=0, timed_out=False, crashed=False, error=None, input_data=b"")
bug = oracle.classify(raw, "input", "target", config={})
passed = bug.bug_type == BugType.PERFORMANCE
test_cases.append(("PERFORMANCE (PerformanceBug)", passed))
print(f"   {'✓' if passed else '✗'} Got {bug.bug_type}")
print()

# 7. VALIDITY
print("7. VALIDITY (ValidityBug exception)")
stdout = """Traceback (most recent call last):
  File "test.py", line 30
    raise ValidityBug("semantic error")
buggy_json.decoder_stv.ValidityBug: Date is invalid"""
raw = RawResult(stdout=stdout, stderr="", returncode=0, timed_out=False, crashed=False, error=None, input_data=b"")
bug = oracle.classify(raw, "input", "target", config={})
passed = bug.bug_type == BugType.VALIDITY
test_cases.append(("VALIDITY (ValidityBug)", passed))
print(f"   {'✓' if passed else '✗'} Got {bug.bug_type}")
print()

# 8. BOUNDARY
print("8. BOUNDARY (BoundaryBug exception)")
stdout = """Traceback (most recent call last):
  File "test.py", line 40
    raise BoundaryBug("off-by-one")
buggy_json.decoder_stv.BoundaryBug: Index out of bounds"""
raw = RawResult(stdout=stdout, stderr="", returncode=0, timed_out=False, crashed=False, error=None, input_data=b"")
bug = oracle.classify(raw, "input", "target", config={})
passed = bug.bug_type == BugType.BOUNDARY
test_cases.append(("BOUNDARY (BoundaryBug)", passed))
print(f"   {'✓' if passed else '✗'} Got {bug.bug_type}")
print()

# 9. FUNCTIONAL
print("9. FUNCTIONAL (FunctionalBug exception)")
stdout = """A functional bug has been triggered: wrong result
Traceback (most recent call last):
  File "test.py", line 50
    raise FunctionalBug("incorrect")
buggy_json.decoder_stv.FunctionalBug: Expected 5 got 3"""
raw = RawResult(stdout=stdout, stderr="", returncode=0, timed_out=False, crashed=False, error=None, input_data=b"")
bug = oracle.classify(raw, "input", "target", config={})
passed = bug.bug_type == BugType.FUNCTIONAL
test_cases.append(("FUNCTIONAL (FunctionalBug)", passed))
print(f"   {'✓' if passed else '✗'} Got {bug.bug_type}")
print()

# 10. RELIABILITY (seeded ReliabilityBug)
print("10. RELIABILITY (ReliabilityBug exception)")
stdout = """Traceback (most recent call last):
  File "test.py", line 60
    raise ReliabilityBug("crash")
buggy_json.decoder_stv.ReliabilityBug: Null pointer"""
raw = RawResult(stdout=stdout, stderr="", returncode=0, timed_out=False, crashed=False, error=None, input_data=b"")
bug = oracle.classify(raw, "input", "target", config={})
passed = bug.bug_type == BugType.RELIABILITY
test_cases.append(("RELIABILITY (ReliabilityBug)", passed))
print(f"   {'✓' if passed else '✗'} Got {bug.bug_type}")
print()

# 11. BONUS (keyword fallback)
print("11. BONUS (bonus keyword)")
stdout = "A bonus bug was found: something unexpected"
raw = RawResult(stdout=stdout, stderr="", returncode=0, timed_out=False, crashed=False, error=None, input_data=b"")
bug = oracle.classify(raw, "input", "target", config={})
passed = bug.bug_type == BugType.BONUS
test_cases.append(("BONUS (bonus keyword)", passed))
print(f"   {'✓' if passed else '✗'} Got {bug.bug_type}")
print()

# 12. Generic keyword fallback
print("12. GENERIC KEYWORD (from config)")
stdout = "A custom semantic error occurred"
raw = RawResult(stdout=stdout, stderr="", returncode=0, timed_out=False, crashed=False, error=None, input_data=b"")
bug = oracle.classify(raw, "input", "target", config={"bug_keywords": ["semantic error"]})
passed = bug.bug_type == BugType.RELIABILITY  # fallback when no keyword matches
test_cases.append(("GENERIC KEYWORD (fallback)", passed))
print(f"   {'✓' if passed else '✗'} Got {bug.bug_type}")
print()

# 13. RELIABILITY (infra crash, non-zero exit)
print("13. RELIABILITY (non-zero exit code)")
stdout = "Something went wrong"
raw = RawResult(stdout=stdout, stderr="", returncode=1, timed_out=False, crashed=False, error=None, input_data=b"")
bug = oracle.classify(raw, "input", "target", config={})
passed = bug.bug_type == BugType.RELIABILITY
test_cases.append(("RELIABILITY (crash)", passed))
print(f"   {'✓' if passed else '✗'} Got {bug.bug_type}")
print()

# 14. MISMATCH (differential)
print("14. MISMATCH (output differs from reference)")
stdout = "Output: [1234]"
ref_stdout = "Output: [5678]"
raw = RawResult(stdout=stdout, stderr="", returncode=0, timed_out=False, crashed=False, error=None, input_data=b"")
bug = oracle.classify(raw, "input", "target", 
                     config={"output_pattern": "Output: [{value}]"},
                     ref_stdout=ref_stdout)
passed = bug.bug_type == BugType.MISMATCH
test_cases.append(("MISMATCH (differential)", passed))
print(f"   {'✓' if passed else '✗'} Got {bug.bug_type}")
print()

# 15. NORMAL (clean run)
print("15. NORMAL (clean run, no bugs)")
stdout = "Output: test result"
raw = RawResult(stdout=stdout, stderr="", returncode=0, timed_out=False, crashed=False, error=None, input_data=b"")
bug = oracle.classify(raw, "input", "target", config={})
passed = bug.bug_type == BugType.NORMAL
test_cases.append(("NORMAL (clean)", passed))
print(f"   {'✓' if passed else '✗'} Got {bug.bug_type}")
print()

# Summary
print("=" * 70)
print("SUMMARY - ALL BUG TYPES")
print("=" * 70)
passed_count = sum(1 for _, result in test_cases if result)
for name, result in test_cases:
    print(f"  {'✓' if result else '✗'} {name}")
print()
print(f"Total: {passed_count}/{len(test_cases)} passed")
if passed_count == len(test_cases):
    print("\n🎯 ALL BUG TYPES DETECTED CORRECTLY!")
else:
    print(f"\n⚠️  {len(test_cases) - passed_count} bug type(s) failed")
