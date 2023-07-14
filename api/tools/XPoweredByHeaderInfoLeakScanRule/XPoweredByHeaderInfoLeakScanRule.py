import requests

HEADER_NAME = "X-Powered-By"

class XPoweredByHeaderInfoLeakScanRule:

    def __init__(self):
        self.evidence = []
    def scan_http_response_receive(self, url):
        response = requests.get(url)
        if self.is_XPoweredBy_header_exist(response):
            
            # If the 'X-Powered-By' header exists in the response, return the corresponding CWE ID indicating information exposure.
            xpb_headers = self.get_XPoweredBy_headers(response)
            self.evidence.append("{}: {}".format("X_Powered-By", xpb_headers))
        if self.evidence:
            # return {
            #     'cwe': 'CWE-200: Exposure of Sensitive Information to an Unauthorized Actor',
            #     'evidence': self.evidence,
            #     'title': "Server Leaks Information via 'X-Powered-By' HTTP Response Header Field(s)",
            #     'risk': 'Low',
            #     'summary': "The web/application server is leaking information via one or more “X-Powered-By” HTTP response headers. Access to such information may facilitate attackers identifying other frameworks/components your web application is reliant upon and the vulnerabilities such components may be subject to.",
            #     'solution': "Ensure that your web server, application server, load balancer, etc. is configured to suppress 'X-Powered-By' headers."
            # }
            return {
                'url': url,
                'method': "GET",
                "parameter": "",
                "attack": "",
                "evidence": self.evidence[0]
            }

    def is_XPoweredBy_header_exist(self, response):
        # Check if the 'X-Powered-By' header exists in the response.
        return HEADER_NAME in response.headers

    def get_XPoweredBy_headers(self, response):
        # Get all values of the 'X-Powered-By' header from the response.
        headers = response.headers
        xpb_headers = [value for key, value in headers.items() if key.lower() == HEADER_NAME.lower()]
        return xpb_headers

def scan(url):
    scanner = XPoweredByHeaderInfoLeakScanRule()
    return scanner.scan_http_response_receive(url)


# example usage returns cwe for nsi.isaix.com
# print(scan('http://nsi.isaix.com'))
