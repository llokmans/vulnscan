import sqlite3
import requests

class VulnScanner:
    def __init__(self,url):
        self.url = url
        self.results = []
    def check_status(self):
        try:
            response = requests.get(self.url)
            if response.status_code == 200:
                print(f"URL {self.url} is reachable.")
            else:
                print(f"URL {self.url} returned status code {response.status_code}.")
            self.save_results(response.status_code, {})
        except requests.exceptions.RequestException as e:
            print(f"Error reaching URL {self.url}: {e}")
            
    def check_headers(self):
        try:
            response = requests.get(self.url)
            headers = response.headers
            print(f"Headers for {self.url}:")
            for key, value in headers.items():
                print(f"{key}: {value}")
            self.save_results(response.status_code, dict(headers))
        except requests.exceptions.RequestException as e:
            print(f"Error retrieving headers for URL {self.url}: {e}")
            
            
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

