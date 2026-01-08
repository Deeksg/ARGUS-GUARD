#input=ip address from domain
#output= list of open or responding ports
#error=a port not responding (filtered port)

import socket

def get_ip_from_domain(domain_name):
    try:
        ip_address= socket.gethostbyname(domain_name)
        return ip_address
    except socket.gaierror:
        return None

#create a socket object and check TCP connectivity using brute force(known ports)
def port_scanner(ip_address):
    ports=[21,22,80,443,3306,8080]
    port_status={}
    for key in ports:
        #we don't want to stop the scan if one port fails, so using 'try' inside 'for' loop, one port fails, other ports can
        #still try
        try:
            #create socket object, AF_INET= IPv4 addresses (address family) and SOCK_STREAM= TCP connection
            s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.01)
            status=s.connect_ex((ip_address, key))
            if (status==0):
                port_status[key]="open"
            else:
                port_status[key]="closed"
            s.close()
        except socket.gaierror:
            port_status[key]="IP resolve error"
        except socket.error:
            port_status[key]="Server error"

    return port_status

def main():
    domain_name= input("Enter domain name:")
    ip_address=get_ip_from_domain(domain_name)
    if ip_address is not None:
        status=port_scanner(ip_address)
        for value in status:
            print(f"{value}={status[value]}")
    else:
        print("IP can't be resolved")

if __name__=="__main__":
    main()
        

    

    
