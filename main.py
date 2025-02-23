import openai
import shodan
import nmap
import requests

# Set API Keys (Replace with your actual keys)
OPENAI_API_KEY = "your-openai-api-key"
SHODAN_API_KEY = "your-shodan-api-key"
VIRUSTOTAL_API_KEY = "your-virustotal-api-key"

# Initialize APIs
openai.api_key = OPENAI_API_KEY
shodan_api = shodan.Shodan(SHODAN_API_KEY)
nm = nmap.PortScanner()

def run_nmap_scan(target):
    """Runs an Nmap scan on a given target."""
    nm.scan(hosts=target, arguments="-sV -T4")
    results = {}
    
    for host in nm.all_hosts():
        results[host] = {}
        for proto in nm[host].all_protocols():
            results[host][proto] = nm[host][proto].keys()
    
    return results

def shodan_scan(query):
    """Searches for internet-connected devices using Shodan."""
    try:
        results = shodan_api.search(query)
        return [match['ip_str'] for match in results['matches']]
    except shodan.APIError as e:
        return f"Shodan error: {e}"

def check_virustotal(url):
    """Checks a URL using VirusTotal."""
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url}", headers=headers)
    
    if response.status_code == 200:
        return response.json()
    else:
        return "Error checking VirusTotal"

def cybersecurity_chatbot():
    """Cybersecurity chatbot with penetration testing tools."""
    print("Ethical Hacking AI - Type 'exit' to quit")
    
    while True:
        user_input = input("You: ")
        if user_input.lower() == "exit":
            print("Goodbye!")
            break

        if user_input.startswith("scan nmap"):
            target = user_input.replace("scan nmap ", "").strip()
            print("Scanning with Nmap...")
            scan_results = run_nmap_scan(target)
            print("Results:", scan_results)

        elif user_input.startswith("scan shodan"):
            query = user_input.replace("scan shodan ", "").strip()
            print("Searching Shodan...")
            shodan_results = shodan_scan(query)
            print("Results:", shodan_results)

        elif user_input.startswith("check url"):
            url = user_input.replace("check url ", "").strip()
            print("Checking URL with VirusTotal...")
            vt_results = check_virustotal(url)
            print("Results:", vt_results)

        else:
            # Use AI for general cybersecurity questions
            response = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": user_input}]
            )
            print("AI:", response["choices"][0]["message"]["content"])

# Run chatbot
cybersecurity_chatbot()
