#input= domain name
#output= list of subdomains that resolve (any subdomain that resolves to an IP)
#errors= subdomains not resolving to an IP

import socket
import random
import string
from src.domain_info.domain_info import get_ip_from_domain


#Wildcard is a mechanism in which DNS resolves even for invalid domains and subdomains since internet is designed to return
#something anyways, invalid subdomain resolve means, a server responds, not that it's valid
def detect_wildcard(domain_name):
    wildcard_behaviour=False
    detected=[]
    characters=string.ascii_lowercase+string.digits+"-"
    for i in range(0,21):
        prefix_len=random.randint(8,12)
        prefix=''.join(random.choices(characters,k=prefix_len))
        subdomain=prefix+"."+domain_name
        ip_address=get_ip_from_domain(subdomain)
        if ip_address is not None:
            wildcard_behaviour=True
        else:
            wildcard_behaviour=False
        detected.append(wildcard_behaviour)
        
    if all(value==True for value in detected):
        true_behaviour="Wildcard DNS detected"
    elif all(value==False for value in detected):
        true_behaviour="No Wildcard DNS detected"
    else:
        true_behaviour="Inconsistent wildcard behavior observed/ Partial Wildcard"
    return true_behaviour


#We take a list of possible prefixed and add them to domain to make a subdomain, check if they resolves to an IP and if they
#do, list them as valid subdomains
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

    print(detect_wildcard(domain_name))

if __name__=="__main__":
    main()