from bs4 import BeautifulSoup
import requests
from requests.models import PreparedRequest, Response
from typing import List, Dict

# STILL NEEDS FINETUNING
# This checks if form actions lead to an http webpage from an https webpage
class mixedContentScan:

    def __init__(self):
        self.attributes = ['src', 'background', 'classid', 'codebase', 'data', 'icon', 'usemap']
        self.evidence = []
    
    def add_attrs_containing_http_content(self, element, attr) -> List[Dict]:
        # Check if the attribute value does not start with "https"
        value = element.get(attr)
        if value and value.lower().startswith("http:"):
            # self.evidence.append({'tag': element.name, 'attr': attr, 'value': value})
            return [{'tag': element.name, 'attr': attr, 'value': value}]
        else: return

    def scan_http_response_receive(self, msg: Response, url) -> List[Dict]:
        # Check if the URL does not start with "https"
        if not msg.url.startswith('https'):
            return None
        # Check if the response content type is "text/html"
        if 'text/html' not in msg.headers.get('Content-Type', ''):
            return None

        # Parse the HTML content using BeautifulSoup
        html_content = msg.content
        soup = BeautifulSoup(html_content, 'html.parser')
        insecure_elements = []

        # Iterate over the defined attributes and find elements containing those attributes
        for attr in self.attributes:
            for tag in soup.find_all(True, {attr: True}):
                # Add the insecure elements to the list
                check = self.add_attrs_containing_http_content(tag, attr)
                if check:
                    insecure_elements.append(check)
        if insecure_elements:
            self.evidence.append(insecure_elements)

        if self.evidence:
            # return {
            #     'cwe': "CWE-311: Missing Encryption of Sensitive Data",
            #     'evidence': self.evidence,
            #     'title': 'Secure Pages Include Mixed Content',
            #     'risk': '',
            #     'summary': "The page includes mixed content, that is content accessed via HTTP instead of HTTPS.",
            #     "solution": "A page that is available over SSL/TLS must be comprised completely of content which is transmitted over SSL/TLS. The page must not contain any content that is transmitted over unencrypted HTTP. This includes content from third party sites."
            # }
            return {
                'url': url,
                'method': "GET",
                "parameter": "",
                "attack": "",
                "evidence": self.evidence[0]
            }


def scan(url):
    # Create an instance of mixedContentScan
    scanner = mixedContentScan()

    # Fetch the HTTP response from the URL
    return scanner.scan_http_response_receive(requests.get(url), url)

# Example usage: returns false for nsi.isaix.com
# print(scan('http://nsi.isaix.com'))
