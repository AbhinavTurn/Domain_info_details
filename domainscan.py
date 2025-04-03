import argparse
import requests
import socket
import whois
import dns.resolver
import subprocess
import re
import json
from concurrent.futures import ThreadPoolExecutor
from selenium import webdriver
from PIL import Image
from PIL.ExifTags import TAGS
from api_keys import SHODAN_API_KEY, HIBP_API_KEY, VIRUSTOTAL_API_KEY, CENSYS_API_ID, CENSYS_SECRET

class OSINTTool:
    def __init__(self, target):
        self.target = target
        self.results = {"target": target, "data": {}}

    def get_ip(self):
        try:
            ip = socket.gethostbyname(self.target)
            self.results["data"]["ip_address"] = ip
            print(f"[+] IP Address: {ip}")
            return ip
        except socket.gaierror:
            print("[-] Could not resolve hostname")
            return None

    def get_whois(self):
        try:
            w = whois.whois(self.target)
            emails = w.emails if isinstance(w.emails, list) else [w.emails] if w.emails else []
            self.results["data"]["whois"] = {
                "registrar": w.registrar,
                "creation_date": str(w.creation_date),
                "expiration_date": str(w.expiration_date),
                "name_servers": w.name_servers,
                "emails": emails
            }
            print("[+] WHOIS information collected.")
        except Exception as e:
            print(f"[-] WHOIS lookup failed: {e}")

    def get_dns_records(self):
        record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME"]
        dns_results = {}

        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(self.target, record_type)
                records = [str(rdata) for rdata in answers]
                dns_results[record_type] = records
            except:
                pass

        self.results["data"]["dns_records"] = dns_results
        print("[+] DNS Records collected.")

    def scan_ports(self):
        ip = self.get_ip()
        if not ip:
            return
        ports = [21, 22, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 3306, 3389, 8080, 8443]
        open_ports = {}
        
        def check_port(port):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            sock.close()
            return port, result == 0
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            results = list(executor.map(check_port, ports))
        
        for port, is_open in results:
            if is_open:
                open_ports[port] = "Open"
        
        self.results["data"]["open_ports"] = open_ports
        print("[+] Port Scan Completed.")

    def shodan_scan(self):
        try:
            url = f"https://api.shodan.io/shodan/host/{self.target}?key={SHODAN_API_KEY}"
            response = requests.get(url).json()
            self.results["data"]["shodan"] = response
            print("[+] Shodan Scan Completed.")
        except Exception as e:
            print(f"[-] Shodan scan failed: {e}")

    def haveibeenpwned(self):
        try:
            url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{self.target}"
            headers = {"hibp-api-key": HIBP_API_KEY}
            response = requests.get(url, headers=headers).json()
            self.results["data"]["hibp"] = response
            print("[+] Have I Been Pwned Check Completed.")
        except Exception as e:
            print(f"[-] HIBP check failed: {e}")

    def virustotal_scan(self):
        try:
            url = "https://www.virustotal.com/api/v3/domains/" + self.target
            headers = {"x-apikey": VIRUSTOTAL_API_KEY}
            response = requests.get(url, headers=headers).json()
            self.results["data"]["virustotal"] = response
            print("[+] VirusTotal Scan Completed.")
        except Exception as e:
            print(f"[-] VirusTotal scan failed: {e}")

    def save_results(self, filename="osint_results.json"):
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=4)
        print(f"[+] Results saved to {filename}")

    def run_all(self):
        print(f"[*] Running OSINT Reconnaissance on {self.target}")
        self.get_ip()
        self.get_whois()
        self.get_dns_records()
        self.scan_ports()
        self.shodan_scan()
        self.haveibeenpwned()
        self.virustotal_scan()
        self.save_results()
        print("[*] OSINT Reconnaissance Completed!")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced OSINT Reconnaissance Tool")
    parser.add_argument("target", help="Target domain or IP address")
    args = parser.parse_args()
    
    tool = OSINTTool(args.target)
    tool.run_all()
