import re
import requests
from bs4 import BeautifulSoup

X_DEBUG_TOKEN_HEADER = "X-Debug-Token"
X_DEBUG_TOKEN_LINK_HEADER = "X-Debug-Token-Link"

class XDebugTokenScanRule:
    def __init__(self):
        self.evidence = []

    def scan_http_response_receive(self, msg, url):
        if self.response_has_header(msg, X_DEBUG_TOKEN_LINK_HEADER):
            # If the response has the 'X-Debug-Token-Link' header, return the corresponding CWE ID indicating information exposure.
            self.evidence.append("{}: {}".format("X-Debug-Token-Link", msg.headers.get('X-Debug-Token-Link')))
        
        if self.response_has_header(msg, X_DEBUG_TOKEN_HEADER):
            # If the response has the 'X-Debug-Token' header, return the corresponding CWE ID indicating information exposure.
            self.evidence.append("{}: {}".format("X-Debug-Token", msg.headers.get('X-Debug-Token')))
        if self.evidence:
            # return {
            #     'cwe': 'CWE-200: Exposure of Sensitive Information to an Unauthorized Actor',
            #     'evidence': self.evidence,
            #     'title': 'X-Debug-Token Information Leak',
            #     'risk': 'Low',
            #     'summary': "The response contained an X-Debug-Token or X-Debug-Token-Link header. This indicates that Symfony’s Profiler may be in use and exposing sensitive data.",
            #     'solution': "Limit access to Symfony's Profiler, either via authentication/authorization or limiting inclusion of the header to specific clients (by IP, etc.)."
            # }
            return {
                'url': url,
                'method': "GET",
                "parameter": "",
                "attack": "",
                "evidence": self.evidence[0]
            }
        

    def response_has_header(self, msg, header):
        # Check if the response has the specified header
        return header in msg.headers

    def get_headers(self, msg, header):
        matched_headers = []
        headers = msg.headers
        pattern = re.compile("^" + header + ".*", re.IGNORECASE)

        for hdr in headers:
            match = pattern.match(hdr)
            if match:
                matched_headers.append(match.group())

        return matched_headers

def scan(url):
    scanner = XDebugTokenScanRule()
    return scanner.scan_http_response_receive(requests.get(url), url)


# example usage returns none for nsi.isaix.com
# print(scan('http://nsi.isaix.com'))
