#input info = domain name 
#output info = IP Address(only primary 1 right now), Server headers, HTTP Status
#possible errors = domains not reachable, invalid domain name, no HTTP response

import socket
import requests

def get_ip_from_domain(domain_name):
    try:
        ip_address= socket.gethostbyname(domain_name)
        return ip_address
    except socket.gaierror:
        return None

def get_httpStatusCode_and_serverHeader(domain_name):
    try:
        url="https://"+ domain_name 
        response=requests.get(url, timeout=5)
        status_code=response.status_code
        server_header=response.headers.get('server')
        http_status={"protocol":"https","status_code":status_code, "server_header":server_header}
        return http_status
    except:
        try:
            url="http://"+ domain_name 
            response=requests.get(url, timeout=5)
            status_code=response.status_code
            server_header=response.headers.get('server')
            http_status={"protocol":"http","status_code":status_code, "server_header":server_header}
            return http_status
        except Exception as err:
            return None


    
def main():
    domain_name= input("Enter domain name:")
    ip_address=get_ip_from_domain(domain_name)
    if(ip_address):
        print(f"The IP address for {domain_name}={ip_address}")
    else:
        print(f"Couldn't find IP for {domain_name}")

    http_status=get_httpStatusCode_and_serverHeader(domain_name)
    if(http_status):
        if(http_status['server_header']!=None):
            print(f"The protocol used for {domain_name}={http_status['protocol']}")
            print(f"The http status code for {domain_name}={http_status['status_code']}")
            print(f"The server header for {domain_name}={http_status['server_header']}")
        else:
            print(f"The protocol used for {domain_name}={http_status['protocol']}")
            print(f"The http status code for {domain_name}={http_status['status_code']}")
            print(f"The server header for {domain_name} is NOT DISCLOSED")
    else:
        print(f"Couldn't find http status for {domain_name}")

if __name__ == "__main__":
    main()

