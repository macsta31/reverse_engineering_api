import requests
from bs4 import BeautifulSoup

class CrossOriginResponseMisconfig():
    # This checks for proper configuration of all CORS policies
    def __init__(self):
        self.evidence = []
        self.url = ''

    def scan_http_response_receive(self, url):
        self.url = url
        # Send a GET request to the specified URL
        response = requests.get(url)
        # Process the HTTP response
        return self.process_response(response)

    def process_response(self, response):
        headers = response.headers
        # print(headers)
        for header in headers:
            # Check if the 'Access-Control-Allow-Origin' header is present
            if header == 'Access-Control-Allow-Origin':
                if '*' in headers[header]: # '*' indicates permissive cross-origin access
                    ev = str(header) + ':  '+ str(headers[header])
                    self.evidence.append(ev)
                    # return {
                    #     'cwe': "CWE-942: Permissive Cross-domain Policy with Untrusted Domains",
                    #     'evidence': self.evidence,
                    #     'title': 'CORS Misconfiguration',
                    #     'risk': 'Medium',
                    #     'summary': "If a web resource contains sensitive information, the origin should be properly specified in the Access-Control-Allow-Origin header. Only trusted websites needing this resource should be specified in this header, with the most secured protocol supported.",
                    #     "solution": "If a web resource contains sensitive information, the origin should be properly specified in the Access-Control-Allow-Origin header. Only trusted websites needing this resource should be specified in this header, with the most secured protocol supported."
                    # }  # '*' indicates permissive cross-origin access
                    return {
                        'url': self.url,
                        'method': "GET",
                        "parameter": "",
                        "attack": "",
                        "evidence": self.evidence[0]
                    }

# Example usage:

def corsConfig(url):
    # Create an instance of CrossOriginResponseMisconfig
    scanner = CrossOriginResponseMisconfig()
    # Scan the HTTP response received from the specified URL
    return scanner.scan_http_response_receive(url)
    

# Example usage: should return cwe 693 for nsi.isaix.com
# print(corsConfig('https://darkwebscanner.mackstathis.dev'))
