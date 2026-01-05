#input info = domain name 
#output info = IP Address(only primary 1 right now), Server headers, HTTP Status
#possible errors = domains not reachable, invalid domain name, no HTTP response

import socket

def get_ip_from_domain(domain_name):
    try:
        ip_address= socket.gethostbyname(domain_name)
        return ip_address
    except socket.gaierror:
        return None
    
def main():
    domain_name= input("Enter domain name:")
    ip_address=get_ip_from_domain(domain_name)
    if(ip_address):
        print(f"The IP address for {domain_name}={ip_address}")
    else:
        print(f"Couldn't find IP for {domain_name}")

if __name__ == "__main__":
    main()

