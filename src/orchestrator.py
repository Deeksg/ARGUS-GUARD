from src.domain_info.domain_info import get_ip_from_domain
from src.domain_info.domain_info import get_httpStatusCode_and_serverHeader
from src.domain_info.domain_info import interpret_http_status
from src.domain_info.subdomain_enum import find_subdomains
from src.domain_info.subdomain_enum import detect_wildcard
from src.port_scanner.port_scanner import port_scanner
from src.domain_info.http_wildcard import detect_http_wildcard
from src.domain_info.http_wildcard import get_http_fingerprint
from src.domain_info.subdomain_cleanup import compare_subdomain_wildcard
from src.domain_info.subdomain_cleanup import tag_subdomain


def run_recon(domain_name):
    #fields we require in our recon data returned as dictionary
    recon={"domain":None,"ip":None,"domain_basic_http":{},"domain_http_fingerprint":{},"domain_dns_wildcard":None,"domain_http_wildcard":{},"subdomains":[],"ports":{}}

    #domain name
    recon["domain"]=domain_name

    #ip address
    recon["ip"]=get_ip_from_domain(domain_name)

    #get the http as dictionary and interpretation as list, tghen add list as a key in http dictionary with values
    recon["domain_basic_http"]=get_httpStatusCode_and_serverHeader(domain_name)
    interpret=interpret_http_status(recon["domain_basic_http"])
    if recon["domain_basic_http"] is not None:
        recon["domain_basic_http"]["interpret"]=interpret
    else:
        recon["domain_http"]="can't get http" 
    
    #get http fingerprints
    recon["domain_http_fingerprint"]=get_http_fingerprint(domain_name)

    #dns wildcard detection
    recon["domain_dns_wildcard"]=detect_wildcard(domain_name)

    #http wildcard detection
    recon["domain_http_wildcard"]=detect_http_wildcard(domain_name)

    #for subdomains we need a list of dictionaries, each dictionary giving info about one particular subdomain
    #create dict of info we need for each subdomain and get subdomain names as list
    #now for each subdomain name, create a dictionary having all info named subdomain_info
    #append these dictionaries into a single list at each iteration of for loop 
    subdomain_name=find_subdomains(domain_name)
    # subdomain_info={"name":None,"resolves":None,"wildcard":None,"ports":{},"http":{}}
    if len(subdomain_name)!=0:
        for key in subdomain_name:
            #dictionary for each subdomain
            subdomain_info={"name":None,"dns_resolves":None,"basic_http":{},"http_fingerprint":{},"http_wildcard_comparison":{}, "tags and confidence":{},"ports":{} }
            #http_wildcard_comparison checks wildcard behaviour against the fake host the domain was checked against
            subdomain_info["name"]=key
            subdomain_info["dns_resolves"]=True
            subdomain_info["http_fingerprint"]=get_http_fingerprint(key)
            subdomain_info["http_wildcard_comparison"]=compare_subdomain_wildcard(subdomain_info["http_fingerprint"], recon["domain_http_wildcard"]["fake_host_fingerprint"])
            subdomain_info["tags and confidence"]=tag_subdomain(subdomain_info["http_wildcard_comparison"])
            recon["subdomains"].append(subdomain_info)
    else:
        recon["subdomains"].append("No subdomain available")

    #ports depend on ip address, return as a dictionary
    if recon["ip"] is not None:
        recon["ports"]=port_scanner(recon["ip"])
    return recon

domain_name=input("Enter domain name:")
recon=run_recon(domain_name)
for key in recon:
    print(f"{key}={recon[key]}")


