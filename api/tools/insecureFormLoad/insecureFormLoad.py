from bs4 import BeautifulSoup
import requests

class InsecureFormLoadScanner:
    # This checks if content is sent over http from an https webpage
    def __init__(self):
        self.evidence = []

    def scan_http_response(self, url, soup: BeautifulSoup):
        # Find all form elements in the HTML soup
        forms = soup.find_all('form')
        if url.startswith('http://'):
            return self.http_to_https(forms, url)
        else: return None
            
    def http_to_https(self, forms, url):
        for form in forms:
            # print(form)
            action = form.get('action')
            if action and action.startswith('https://'):
                self.evidence.append(action)
        if self.evidence:
            # return {
            #     'cwe': "CWE-319: Cleartext Transmission of Sensitive Information",
            #     'evidence': self.evidence,
            #     'title': 'HTTP to HTTPS Insecure Transition in Form Post',
            #     'risk': '',
            #     'summary': "This check looks for insecure HTTP pages that host HTTPS forms. The issue is that an insecure HTTP page can easily be hijacked through MITM and the secure HTTPS form can be replaced or spoofed.",
            #     "solution": "Use HTTPS for landing pages that host secure forms."
            # }
            return {
                'url': url,
                'method': "GET",
                "parameter": "",
                "attack": "",
                "evidence": self.evidence[0]
            }
            

def scan(url, html):
    # Parse the HTML content using BeautifulSoup
    soup = BeautifulSoup(html, 'html.parser')  # Specify the parser here

    # Create an instance of InsecureFormLoadScanner
    scanner = InsecureFormLoadScanner()

    # Scan the HTML soup for insecure form loads
    return scanner.scan_http_response(url, soup)

# Example usage: should return none for nsi.isaix.com/ app.py includes selenium for js generated websites
# html = requests.get('http://nsi.isaix.com').text  # Fetch the HTML content from the URL
# print(scan('http://nsi.isaix.com', html))
