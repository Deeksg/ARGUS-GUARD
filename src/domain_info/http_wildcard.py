#input= domain name
#output= wildcard behaviour, if anything matches, protocol tested, confidence etc
#IMPORTANT:::KEPT *_match as info only, verdict is passed based on scores only, don't use *_match for verdict since it sometimes have None value

import requests
import string
import random
from src.domain_info.domain_info import get_httpStatusCode_and_serverHeader

#get the real and fake hostnames for the given domain
def generate_fake_hostnames(domain_name):   
    characters=string.ascii_lowercase+string.digits+"-"
    prefix_len=random.randint(8,13)
    subdomain="".join(random.choices(characters, k=prefix_len))
    fake_host=subdomain
    return fake_host

#get complete http fingerprints, use previous defined basic http function from domain_info module and extend it to include content
#length and redirect behaviour, handle fallback of http being None, also if protocol given, hostname will be forced to get http status
#using that protocol
def get_http_fingerprint(hostname,protocol=None):
    http={"protocol":None, "status_code":None, "server_header":None, "content_length":0, "redirect":False,"redirect_location":None,"success":False}
    if protocol is None:
        basic=get_httpStatusCode_and_serverHeader(hostname)
        if basic is not None:
            http["protocol"]=basic["protocol"]
            http["status_code"]=basic["status_code"]
            http["server_header"]=basic["server_header"]
            url=basic["protocol"]+"://"+hostname
            response=requests.get(url, timeout=5)
            http["content_length"]=len(response.content)
            http["redirect"]=response.is_redirect
            if http["redirect"] is not False:
                http["redirect_location"]=response.headers["location"]
            http["success"]=True
            return http
        else:
            http["error"]="HTTP probe failed"
            return http
    #if protocol given
    else:
        try:
            url=protocol+"://"+hostname
            response=requests.get(url, timeout=5)
            http["protocol"]=protocol
            http["status_code"]=response.status_code
            http["server_header"]=response.headers.get('server')
            http["content_length"]=len(response.content)
            http["redirect"]=response.is_redirect
            if http["redirect"] is not False:
                http["redirect_location"]=response.headers["location"]
            http["success"]=True
            return http
        except:
            http["error"]="HTTP probe failed"
            return http
        

#first of all check if status code, server header, redirect behaviour, content length etc matches, based on that infer the
#wildcard behaviour, confidence, protocol tested and the comparison summary (only comparable if we get real and fake host http) 
def detect_http_wildcard(domain_name):
    real_host=domain_name
    fake_host=generate_fake_hostnames(domain_name)
    real_http=get_http_fingerprint(real_host)
    #fake host need to be forced to follow protocol used by real (if real http fails, protocol= None, hence handled)
    fake_http=get_http_fingerprint(fake_host, real_http["protocol"])

    #this defined dictionary will be returned
    wildcard={"wildcard_detected":None, "confidence":None, "protocol":None,"fake_host_fingerprint":fake_http,"comparison_summary":{},"notes":[]}


    #if both real and fake host reply on http then comparable
    if real_http["success"]==True and fake_http["success"]==True:
        #protocol?
        wildcard["protocol"]=real_http["protocol"]

        #comparison_summary
        wildcard["comparison_summary"]={"status_match":None, "length_difference_percent":None, "server_match":None, "redirect_match":None}

        #for status, server and redirects, we will give scores, positive means positive wildcard, negative means negative wildcard, 1 and 2 are indicating which parameter has how much effect, 0 means no effect on wildcard

        #status_match?
        if real_http["status_code"]==fake_http["status_code"]:
            wildcard["comparison_summary"]["status_match"]=True
            wildcard["comparison_summary"]["status_score"]=1
        else:
            wildcard["comparison_summary"]["status_match"]=False
            wildcard["comparison_summary"]["status_score"]=-1

        #length_difference_percent
        if real_http["content_length"]!=0:
            wildcard["comparison_summary"]["length_difference_percent"]=((abs(real_http["content_length"]-fake_http["content_length"]))/(abs(real_http["content_length"])))*100

        #server_match?
        if real_http["server_header"] is not None and fake_http["server_header"] is not None:
            if real_http["server_header"]==fake_http["server_header"]:
                wildcard["comparison_summary"]["server_match"]=True
                wildcard["comparison_summary"]["server_score"]=1
            else:
                wildcard["comparison_summary"]["server_match"]=False
                wildcard["comparison_summary"]["server_score"]=-1
        elif real_http["server_header"] is not None and fake_http["server_header"] is None:
            wildcard["comparison_summary"]["server_note"]="Fake host possibly hides server header"
            wildcard["comparison_summary"]["server_score"]=-1
        elif real_http["server_header"] is None and fake_http["server_header"] is not None:
            wildcard["comparison_summary"]["server_note"]="Real host possibly hides server header"
            wildcard["comparison_summary"]["server_score"]=-1
        else:
            wildcard["comparison_summary"]["server_note"]="Server possibly hidden for both hosts"
            wildcard["comparison_summary"]["server_score"]=0

        #redirect_match?
        if real_http["redirect"] is not False and fake_http["redirect"] is not False:
            if real_http["redirect_location"]==fake_http["redirect_location"]:
                wildcard["comparison_summary"]["redirect_match"]=True
                wildcard["comparison_summary"]["redirect_score"]=2
            else:
                wildcard["comparison_summary"]["redirect_match"]=False
                wildcard["comparison_summary"]["redirect_score"]=-2
        elif real_http["redirect"] is True and fake_http["redirect"] is False:
            wildcard["comparison_summary"]["redirect_note"]="Only real host redirected"
            wildcard["comparison_summary"]["redirect_score"]=-2
        elif real_http["redirect"] is False and fake_http["redirect"] is True:
            wildcard["comparison_summary"]["redirect_note"]="Only fake host redirected"
            wildcard["comparison_summary"]["redirect_score"]=2
        else:
            wildcard["comparison_summary"]["redirect_note"]="No host redirected"
            wildcard["comparison_summary"]["redirect_score"]=0

        wildcard["support_score"]=wildcard["comparison_summary"]["status_score"]+wildcard["comparison_summary"]["server_score"]+wildcard["comparison_summary"]["redirect_score"]

        #wildcard verdict
        
        if wildcard["comparison_summary"]["length_difference_percent"] is not None:
            if wildcard["comparison_summary"]["length_difference_percent"]<30:
                if wildcard["support_score"]>=2:
                    wildcard["wildcard_detected"]=True
                    wildcard["confidence"]="High" 
                    wildcard["notes"].append("Strong content length similarity with multiple matching HTTP behaviors")
                if wildcard["support_score"]==1:
                    wildcard["wildcard_detected"]=True
                    wildcard["confidence"]="Medium" 
                    wildcard["notes"].append("Content length similarity observed, but limited supporting signals")
                if wildcard["support_score"]<=0:
                    wildcard["wildcard_detected"]=False
                    wildcard["confidence"]="Medium"
                    wildcard["notes"].append("Content length similarity present, but HTTP behavior differs significantly") 

            elif (30<=wildcard["comparison_summary"]["length_difference_percent"]<50):
                if wildcard["support_score"]>=2:
                    wildcard["wildcard_detected"]="Suspected"
                    wildcard["confidence"]="Medium" 
                    wildcard["notes"].append("Moderate content length similarity with strong supporting HTTP signals")
                else:
                    wildcard["wildcard_detected"]=False
                    wildcard["confidence"]="Medium"
                    wildcard["notes"].append("Moderate content length similarity without sufficient supporting signals") 
                
            else:
                wildcard["wildcard_detected"]=False
                wildcard["confidence"]="High"
                wildcard["notes"].append("Significant content difference between real and fake host")
   
            return wildcard
        
        #if length difference is None
        else:
            if wildcard["support_score"]>=2:
                        wildcard["wildcard_detected"]="Suspected"
                        wildcard["confidence"]="Low" 
                        wildcard["notes"].append("Content comparison unavailable, decision based on HTTP behavior only")
            else:
                wildcard["wildcard_detected"]=False
                wildcard["confidence"]="Medium"
                wildcard["notes"].append("Insufficient evidence of HTTP wildcard behavior") 
            
        return wildcard


    #when real host http is success but fake host http is not
    elif real_http["success"]==True and fake_http["success"]==False:
        wildcard["wildcard_detected"]=False
        wildcard["confidence"]="High"
        wildcard["protocol"]=real_http["protocol"]
        wildcard["notes"].append("Fake host did not respond under same protocol")
        wildcard["notes"].append("No HTTP wildcard behavior observed")
        return wildcard


    #when real host http is not success but fake host http is 
    elif real_http["success"]==False and fake_http["success"]==True:
        wildcard["wildcard_detected"]="Suspected"
        wildcard["confidence"]="Low"
        wildcard["notes"].append("Fake host responded (over"+fake_http["protocol"]+"protocol) while real host failed")
        wildcard["notes"].append("Possible catch-all HTTP behavior or misconfiguration")
        return wildcard

    #when both real and fake host http is not success
    elif real_http["success"]==False and fake_http["success"]==False:
        wildcard["notes"].append("HTTP probing failed for both real and fake host")
        wildcard["notes"].append(" Unable to determine wildcard behavior")
        return wildcard


def main():
    domain_name=input("Enter Domain name:")
    wildcard=detect_http_wildcard(domain_name)
    for key in wildcard:
        print(f"{key}={wildcard[key]}")

if __name__=="__main__":
    main()
    
        


