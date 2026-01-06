#input= domain name
#output= list of subdomains that resolve (any subdomain that resolves to an IP)
#errors= subdomains not resolving to an IP

import socket

def get_ip_from_domain(domain_name):
    try:
        ip_address=socket.gethostbyname(domain_name)
        return ip_address
    except socket.gaierror:
        return None

def find_subdomains(domain_name):
    
    prefix=["www","blog","admin","login","user","ftp","mail","api"]
    valid_subdomains=[]
    
    for key in prefix:
        subdomain=key+"."+domain_name
        ip_address=get_ip_from_domain(subdomain)
        if ip_address is not None:
            valid_subdomains.append(subdomain)
    return valid_subdomains


def main():
    domain_name=input("Enter Domain name:")
    valid_subdomains=find_subdomains(domain_name)
    print("Valid Subdomains:")
    #an empty list in python is considered false
    if not valid_subdomains:
        print("-No Subdomains Discovered")
    else:
        for key in valid_subdomains:
            print("-"+key)

if __name__=="__main__":
    main()