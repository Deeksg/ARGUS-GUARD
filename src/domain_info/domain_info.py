#input info = domain name 
#output info = IP Address(only primary 1 right now), Server headers, HTTP Status
#possible errors = domains not reachable, invalid domain name, no HTTP response

import socket
import requests

#To get IP from domain
def get_ip_from_domain(domain_name):
    try:
        ip_address= socket.gethostbyname(domain_name)
        return ip_address
    except socket.gaierror:
        return None
    

#To get Status code like 404 and server header like google web server etc
def get_httpStatusCode_and_serverHeader(domain_name):
    #first check for https, if fails, check fot http, if that also fails then error
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


#helper function to print the result of getting http status
def print_http_status(http_status):
    #if http status gives a value, then print it (print server header if given, if None, then hidden), otherwise error
    if (http_status is not None):
        print(f"Protocol = {http_status['protocol']}")
        print(f"HTTP Status Code = {http_status['status_code']}")
        if(http_status['server_header'] is not None):
            print(f"Server Header = {http_status['server_header']}")
        else:
            print(f"Server Header = None(NOT DISCLOSED)")
    else:
        print(f"Couldn't find http status")


#helper function to interpret everything detected in http status
def interpret_http_status(http_status):
    interpret=[]
    if (http_status is not None):
        #status code
        status4xx={401:"Authentication Required",403:"Access is Forbidden",404:"Resource Not Found, Possible Catch all Host"}
        status_code=http_status["status_code"]
        if(status_code==401 or status_code==403 or status_code==404):
            interpret.append("Status "+str(status_code)+" suggests "+status4xx[status_code])
        elif(200<=status_code<300):
            interpret.append("Status "+str(status_code)+" suggests Active endpoint responding normally")
        elif(300<=status_code<400):
            interpret.append("Status "+str(status_code)+" suggests Endpoint responds with redirection behavior(e.g., HTTP to HTTPS)")
        elif(500<=status_code<600):
            interpret.append("Status "+str(status_code)+" suggests Server responded with an internal error, indicating misconfiguration")
        else:
            interpret.append("Received an uncommon or unexpected HTTP status code")

        #protocol
        if(http_status["protocol"]=="https"):
            interpret.append("Secured over HTTPS")
        else:
            interpret.append("Connected over HTTP(insecure transport)")

        #server header
        if(http_status["server_header"]is not None):
            interpret.append("Domain hosted on "+ http_status["server_header"]+" server")
        else:
            interpret.append("Server Header is intentionally hidden.")
        
    else:
        interpret.append("No HTTP status to interpret")
    
    return interpret


    
def main():
    domain_name= input("Enter domain name:")
    ip_address=get_ip_from_domain(domain_name)
    print(f"Domain_name = {domain_name}")
    if(ip_address):
        print(f"IP Address = {ip_address}")
    else:
        print(f"Couldn't find IP")

    http_status=get_httpStatusCode_and_serverHeader(domain_name)
    print_http_status(http_status)
    print("\n")
    print("INTERPRETATION:")
    interpret=interpret_http_status(http_status)
    for key in interpret:
        print("-"+ key)
    


if __name__ == "__main__":
    main()

