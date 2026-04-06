import sys
from ipyparse import ipv6 

def main():
    if len(sys.argv) < 2:
        return
    
    ip_to_test = sys.argv[1]
    
    try:
        result = ipv6.IPv6_WholeString.parseString(ip_to_test, parseAll=True)
        decimal_ip = result[0]
        print(f"Output: [{decimal_ip}]")
        
    except Exception as e:
        print("Reference: Invalid IP")

if __name__ == "__main__":
    main()