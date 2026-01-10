from src.domain_info.domain_info import get_ip_from_domain
from src.domain_info.domain_info import get_httpStatusCode_and_serverHeader
from src.domain_info.domain_info import interpret_http_status
from src.domain_info.subdomain_enum import find_subdomains
from src.domain_info.subdomain_enum import detect_wildcard
from src.port_scanner.port_scanner import port_scanner

def run_recon(domain_name):
    #fields we require in our recon data returned as dictionary
    recon={"domain":None,"ip":None,"domain_http":{},"domain_wildcard":None,"subdomains":[],"ports":{}}

    #domain name
    recon["domain"]=domain_name

    #ip address
    recon["ip"]=get_ip_from_domain(domain_name)

    #get the http as dictionary and interpretation as list, tghen add list as a key in http dictionary with values
    recon["domain_http"]=get_httpStatusCode_and_serverHeader(domain_name)
    interpret=interpret_http_status(recon["domain_http"])
    if recon["domain_http"] is not None:
        recon["domain_http"]["interpret"]=interpret
    else:
        recon["domain_http"]="can't get http" 
    
    #wildcard detection
    recon["domain_wildcard"]=detect_wildcard(domain_name)

    #for subdomains we need a list of dictionaries, each dictionary giving info about one particular subdomain
    #create keys for info we need for each subdomain and get subdomain names as list
    #now for each subdomain name, create a dictionary having all info in keys named subdomain_info
    #append these dictionaries into a single list at each iteration of for loop 
    subdomain_name=find_subdomains(domain_name)
    # subdomain_info={"name":None,"resolves":None,"wildcard":None,"ports":{},"http":{}}

    for key in subdomain_name:
        #dictionary for each subdomain
        subdomain_info={"name":None,"dns_resolves":None,"wildcard":None,"ports":{},"http":{}}
        subdomain_info["name"]=key
        subdomain_info["dns_resolves"]=True
        recon["subdomains"].append(subdomain_info)

    #ports depend on ip address, return as a dictionary
    if recon["ip"] is not None:
        recon["ports"]=port_scanner(recon["ip"])
    return recon

domain_name=input("Enter domain name:")
recon=run_recon(domain_name)
for key in recon:
    print(f"{key}={recon[key]}")


