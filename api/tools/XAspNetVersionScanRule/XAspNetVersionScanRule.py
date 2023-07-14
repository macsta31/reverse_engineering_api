import requests
from urllib.parse import urlparse

class XAspNetVersionScanRule:
    def __init__(self):
        self.x_asp_net_headers = ['X-AspNet-Version', 'X-AspNetMvc-Version']
        self.evidence = []

    def scan_http_response_receive(self, url):
        # Send an HTTP GET request to the specified URL
        response = requests.get(url)

        for header in self.x_asp_net_headers:
            # Check if the header exists in the response
            found = response.headers.get(header)
            if found:
                self.evidence.append("{}: {}".format(header, found))
                # If the header is found, return the corresponding CWE ID indicating a security misconfiguration
                # return "CWE-933: OWASP Top Ten 2013 Category A5 - Security Misconfiguration"
                # return {
                #     'cwe': "CWE-933: OWASP Top Ten 2013 Category A5 - Security Misconfiguration",
                #     'evidence': self.evidence,
                #     'title': "X-AspNet-Version Response Header",
                #     'risk': 'Low',
                #     'summary': "Server leaks information via “X-AspNet-Version”/“X-AspNetMvc-Version” HTTP response header field(s).",
                #     'solution': "Configure the server so it will not return those headers."
                # }
                return {
                    'url': url,
                    'method': "GET",
                    "parameter": "",
                    "attack": "",
                    "evidence": self.evidence[0]
                }
            
def scan(url):
    # Create an instance of the XAspNetVersionScanRule class
    scanner = XAspNetVersionScanRule()
    # Call the scan_http_response_receive method to perform the scan
    return scanner.scan_http_response_receive(url)


# exmaple usage: returns cwe for nsi.isaix.com
# print(scan('http://nsi.isaix.com'))