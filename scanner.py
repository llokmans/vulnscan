import sqlite3
import requests
from colorama import Fore, Style # type: ignore

class VulnScanner:
    def __init__(self,url):
        self.url = url
        self.results = []
    def check_status(self):
        try:
            response = requests.get(self.url)
            if response.status_code == 200:
                print(f"{Fore.GREEN}URL {self.url} is reachable.{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}URL {self.url} returned status code {response.status_code}.{Style.RESET_ALL}")
            self.results.append(("status", self.url, response.status_code, ""))
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}Error reaching URL {self.url}: {e}{Style.RESET_ALL}")
            
    def check_headers(self):
        try:
            response = requests.get(self.url)
            headers = response.headers
            print(f"{Fore.GREEN}Headers for {self.url}:{Style.RESET_ALL}")
            for key, value in headers.items():
                print(f"{Fore.CYAN}{key}: {value}{Style.RESET_ALL}")
            self.results.append(("headers", self.url, response.status_code, str(dict(headers))))
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}Error retrieving headers for URL {self.url}: {e}{Style.RESET_ALL}")
            
            
    def save_results(self, status_code, headers):
        
        conn = sqlite3.connect('vulnscan.db')
        cursor = conn.cursor()
        cursor.execute("INSERT INTO scans (url, status_code, headers) VALUES (?, ?, ?)", (self.url, status_code, str(headers)))
        conn.commit()
        conn.close()
        

    

scanner = VulnScanner("https://httpbin.org")
scanner.check_status()    
scanner.check_headers()

print(scanner.url)

with open("report.html", "w") as f:
    f.write("""<!DOCTYPE html>
<html lang="en">
<head>
<title>Vulnerability Scan Report</title>
<style>
body { background: #0f141c; color: #e1e4e8; font-family: 'Courier New', monospace; }
    h1 { color: #28a745; }
    table { width: 100%; border-collapse: collapse; }
    th { background: #1d4ed8; color: white; padding: 16px; }
    td { padding: 14px; border-bottom: 1px solid #333; }
    tr:hover { background: #1a1f2e; }
</style>
</head>
<body>
<h1>🔒 Vulnerability Scan Report</h1>
<div class="report-container">
<table>
<thead><tr><th>URL</th><th>Status Code</th><th>Response Headers</th></tr></thead>
<tbody>
""")
    
    for result in scanner.results:
        f.write(f"<tr><td>{result[1]}</td><td>{result[2]}</td><td><pre>{result[3]}</pre></td></tr>")
    
    f.write("""</tbody></table></div></body></html>""")   

    
    