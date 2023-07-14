from bs4 import BeautifulSoup
import requests

class InsecureFormPostScanner:
    # This checks if content is sent over http from an https webpage
    def __init__(self):
        self.evidence = []

    def scan_http_response(self, url, soup: BeautifulSoup):
        # Find all form elements in the HTML soup
        forms = soup.find_all('form')
        if url.startswith('https://'):
            return self.https_to_http(forms, url)
            
            
    def https_to_http(self, forms, url):
        for form in forms:
            action = form.get('action')
            if action and action.startswith('http://'):
                self.evidence.append(action)
        if self.evidence:
            # return {
            #     'cwe': "CWE-319: Cleartext Transmission of Sensitive Information",
            #     'evidence': self.evidence,
            #     'title': 'HTTPS to HTTP Insecure Transition in Form Post',
            #     'risk': '',
            #     'summary': "This check identifies secure HTTPS pages that host insecure HTTP forms. The issue is that a secure page is transitioning to an insecure page when data is uploaded through a form. The user may think they’re submitting data to a secure page when in fact they are not.",
            #     "solution": "Ensure sensitive data is only sent over secured HTTPS channels."
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
    scanner = InsecureFormPostScanner()

    # Scan the HTML soup for insecure form loads
    return scanner.scan_http_response(url, soup)

# Example usage: should return none for nsi.isaix.com/ app.py includes selenium for js generated websites
# html = requests.get('http://nsi.isaix.com').text  # Fetch the HTML content from the URL
# print(scan('http://nsi.isaix.com', html))
