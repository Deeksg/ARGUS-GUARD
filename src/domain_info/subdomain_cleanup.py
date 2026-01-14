#input= fake host fingerprints and subdomain fingerprints
#output= compare them to detect wildcard subdomain, later used in subdomain cleanup


from src.domain_info.http_wildcard import get_http_fingerprint
from src.domain_info.http_wildcard import detect_http_wildcard
from src.domain_info.subdomain_enum import find_subdomains

def compare_subdomain_wildcard(subdomain_http,fake_http):
    comparison_result={"comparable":False, "matches_wildcard":None, "signals":{}, "notes":[]}
   

    if subdomain_http["success"]==True and fake_http["success"]==True:
        comparison_result["comparable"]=True
        comparison_result["signals"]={"content_length":None, "redirect":None}
        #content length similarity 
        if subdomain_http["content_length"]!=0:
            if ((abs(subdomain_http["content_length"]-fake_http["content_length"]))/(abs(subdomain_http["content_length"])))*100 <=30:
                comparison_result["signals"]["content_length"]="similar"
            else:
                comparison_result["signals"]["content_length"]="different"
        else:
            comparison_result["signals"]["content_length"]="unknown"

        
        #redirect behaviour similarity
        if subdomain_http["redirect"]==True and fake_http["redirect"]==True:
            if subdomain_http["redirect_location"]==fake_http["redirect_location"]:
                comparison_result["signals"]["redirect"]="same"
            else:
                comparison_result["signals"]["redirect"]="different"
        elif subdomain_http["redirect"]==True and fake_http["redirect"]==False:
                comparison_result["signals"]["redirect"]="subdomain_only"
        elif subdomain_http["redirect"]==False and fake_http["redirect"]==True:
                comparison_result["signals"]["redirect"]="fake_only"
        elif subdomain_http["redirect"]==False and fake_http["redirect"]==False:
                comparison_result["signals"]["redirect"]="unknown"

        #checking for wildcard
        if comparison_result["signals"]["content_length"]=="similar":
            if comparison_result["signals"]["redirect"]=="same":
                  comparison_result["matches_wildcard"]= True
            elif comparison_result["signals"]["redirect"]=="different" or comparison_result["signals"]["redirect"]=="subdomain_only" or comparison_result["signals"]["redirect"]=="fake_only": 
                 comparison_result["matches_wildcard"]=False
            else:
                 comparison_result["matches_wildcard"]= True
                 
        elif comparison_result["signals"]["content_length"]=="different":
            if comparison_result["signals"]["redirect"]=="same":
                  comparison_result["matches_wildcard"]= True
            elif comparison_result["signals"]["redirect"]=="different" or comparison_result["signals"]["redirect"]=="subdomain_only" or comparison_result["signals"]["redirect"]=="fake_only": 
                 comparison_result["matches_wildcard"]=False
            else:
                 comparison_result["matches_wildcard"]= False

        else:
            if comparison_result["signals"]["redirect"]=="same":
                  comparison_result["matches_wildcard"]= True
            elif comparison_result["signals"]["redirect"]=="different" or comparison_result["signals"]["redirect"]=="subdomain_only" or comparison_result["signals"]["redirect"]=="fake_only": 
                 comparison_result["matches_wildcard"]=False
            else:
                 comparison_result["matches_wildcard"]="unknown"

        return comparison_result

    elif subdomain_http["success"]==True and fake_http["success"]==False:
        comparison_result["notes"].append("Fake host didn't respond")
        return comparison_result


    elif subdomain_http["success"]==False and fake_http["success"]==True:
        comparison_result["notes"].append("Real host didn't respond")
        return comparison_result


    elif subdomain_http["success"]==False and fake_http["success"]==False:
        comparison_result["notes"].append("Subdomain and Fake host didn't respond")
        return comparison_result


def tag_subdomain(subdomain_http_comparison):
    interpretation={"tags":[],"confidence":None}
    if subdomain_http_comparison["comparable"]==False:
        interpretation["tags"].append("unknown")
        interpretation["confidence"]="Low"
    else:
        if subdomain_http_comparison["matches_wildcard"]==True:
            interpretation["tags"].extend(["wildcard_http","noise"])
            interpretation["confidence"]="High"
        elif subdomain_http_comparison["matches_wildcard"]==False:
            interpretation["tags"].extend(["real_http","interesting"])
            interpretation["confidence"]="High"
        else:
            interpretation["tags"].append("ambiguous")
            interpretation["confidence"]="Medium"
    return interpretation
             

def main():
    domain=input("Enter domain name: ")
    subdomain=find_subdomains(domain)
    if len(subdomain)!=0:
        subdomain_http=get_http_fingerprint(subdomain[1])
        fake_http=detect_http_wildcard(domain)["fake_host_fingerprint"]
        subdomain_http_comparison=compare_subdomain_wildcard(subdomain_http, fake_http)
        print(subdomain_http_comparison)
        print(tag_subdomain(subdomain_http_comparison))
    else:
         print("No Subdomains found")

if __name__=="__main__":
    main()