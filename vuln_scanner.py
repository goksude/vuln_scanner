import nmap
import requests
from bs4 import BeautifulSoup
import webbrowser
import os
import tempfile

# Scanning ports with Nmap
def scan_ports(ip):
    nm = nmap.PortScanner()
    try:
        nm.scan(ip, '1-1024')  # Scan ports from 1 to 1024
        open_ports = [port for port in nm[ip]['tcp'] if nm[ip]['tcp'][port]['state'] == 'open']
        return open_ports
    except KeyError:
        print(f"Could not perform Nmap scan for {ip} or IP address not found.")
        return []

# Fetching CVE information
def get_cve_info():
    url = "https://cve.circl.lu/api/last"  # Use API to fetch recent CVE records
    response = requests.get(url)
    if response.status_code == 200:
        cve_data = response.json()
        return cve_data
    else:
        print("Could not fetch CVE data.")
        return []

# Saving report to HTML file
def save_report_to_html(ip, open_ports, cve_data):
    # Save to temporary directory
    temp_dir = tempfile.gettempdir()
    html_file = os.path.join(temp_dir, f"{ip}_vulnerability_report.html")

    with open(html_file, "w") as report_file:
        report_file.write(f"<html><head><title>{ip} Vulnerability Report</title></head><body>\n")
        report_file.write(f"<h1>Vulnerability scan for {ip}</h1>\n")
        for port in open_ports:
            report_file.write(f"<h2>Port {port} is open. Potential vulnerabilities:</h2>\n<ul>")
            found_vulnerability = False
            for cve in cve_data:
                if str(port) in cve['summary']:
                    report_file.write(f"<li><b>CVE ID:</b> {cve['id']} <br> <b>Description:</b> {cve['summary']}</li>\n")
                    found_vulnerability = True
            if not found_vulnerability:
                report_file.write("<li> - No potential vulnerabilities found.</li>\n")
            report_file.write("</ul>")
        report_file.write("</body></html>")

    # Open the HTML file
    webbrowser.open(f"file://{html_file}")

# Get target IP from user
target_ip = input("Enter the IP address you want to scan: ")

# Perform port scan and vulnerability check
open_ports = scan_ports(target_ip)
cve_list = get_cve_info()

# Save the report to an HTML file and open it
save_report_to_html(target_ip, open_ports, cve_list)
