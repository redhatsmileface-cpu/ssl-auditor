import socket
import ssl
import datetime
import json
#Declare list of domains for audit
DOMAINS=["google.com","github.com","dbs.com","bing.com"]
DAYS_THRESHOLD=30 # Alert if expiring within 30 days.
OUTPUT_FILE="security_audit.json"

def get_expiry_date(hostname):
    context=ssl.create_default_context()
    #Connect to port 443
    with socket.create_connection((hostname, 443), timeout=10) as sock:
        with context.wrap_socket(sock, server_hostname=hostname) as ssock:
             cert=ssock.getpeercert()
             expiry_str=cert['notAfter']
             return datetime.datetime.strptime(expiry_str,'%b %d %H:%M:%S %Y %Z')
def run_audit():
    results=[]
    print(f"---Starting security Audit:{datetime.datetime.now()}---")

    for domain in DOMAINS:
        try:
            expiry=get_expiry_date(domain)
            remaining=(expiry-datetime.datetime.now()).days
            status="CRITICAL" if remaining<DAYS_THRESHOLD else "HEALTHY"

            result={
                "domain":domain,
                "expiry_date":expiry.strftime("%Y-%m-%d"),
                "days_remaining":remaining,
                "status": status
            }
            results.append(result)
            print(f"[ERROR] {domain}: {remaining} days left ")

        except Exception as e:
            print(f"[Error] {domain}:{str(e)}")


    #Save the results to a Json file for reporting
    with open (OUTPUT_FILE,"w")as f:
        json.dump(results,f,indent=4)
    print(f"---Audit complete.Results saved to {OUTPUT_FILE} ---")

if __name__  == "__main__" :
    run_audit()
