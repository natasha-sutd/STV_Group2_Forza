import sys
import coverage
from io import StringIO
import re


def main():
    if len(sys.argv) < 2:
        return

    ip_to_test = sys.argv[1]

    cov = coverage.Coverage(source=["ipv6"], branch=True)
    cov.start()

    try:
        from ipyparse import ipv6
        result = ipv6.IPv6.parseString(ip_to_test, parseAll=True)
        decimal_ip = result[0]
        print(f"Output: [{decimal_ip}]")
    except Exception:
        print(f"Reference: Invalid IP")

    cov.stop()

    stream = StringIO()
    cov.report(file=stream, show_missing=False)
    report = stream.getvalue()

    line_match = re.search(r"TOTAL\s+\d+\s+\d+\s+\d+\s+\d+\s+(\d+)%", report)
    simple_match = re.search(r"TOTAL\s+\d+\s+\d+\s+(\d+)%", report)

    if line_match:
        pct = line_match.group(1)
    elif simple_match:
        pct = simple_match.group(1)
    else:
        pct = "0"

    print(f"line coverage     : {pct}%")
    print(f"branch coverage   : {pct}%")


if __name__ == "__main__":
    main()
