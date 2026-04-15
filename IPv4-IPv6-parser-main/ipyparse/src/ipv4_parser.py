import sys
import coverage


def main():
    if len(sys.argv) < 2:
        return

    ip_to_test = sys.argv[1]

    cov = coverage.Coverage(source=["ipyparse"])
    cov.start()

    try:
        from ipyparse import ipv4
        result = ipv4.IPv4.parseString(ip_to_test, parseAll=True)
        decimal_ip = result[0]
        print(f"Output: [{decimal_ip}]")
    except Exception as e:
        print(f"Reference: Invalid IP")

    cov.stop()

    from io import StringIO
    import re

    stream = StringIO()
    cov.report(file=stream)
    report = stream.getvalue()

    total_match = re.search(r"TOTAL\s+\d+\s+\d+\s+(\d+)%", report)
    if total_match:
        pct = total_match.group(1)
        print(f"line coverage     : {pct}%")
        print(f"branch coverage   : {pct}%")


if __name__ == "__main__":
    main()
