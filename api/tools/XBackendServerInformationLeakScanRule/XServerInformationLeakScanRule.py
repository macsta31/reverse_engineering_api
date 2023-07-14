import requests

class XBackendServerInformationLeakScanRule:

    def __init__(self):
        self.evidence = []
    def scan_http_response_receive(self, url):
        # Send an HTTP GET request to the specified URL
        response = requests.get(url)
        
        # Check if the 'X-Backend-Server' header is present in the response
        xbs_option = response.headers.get('X-Backend-Server')

        if xbs_option:  # Header Found
            self.evidence.append("{}: {}".format("X-Backend-Server", xbs_option))
            # If the header is found, return the corresponding CWE ID indicating exposure of sensitive information
            # return {
            #     'cwe': "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor",
            #     'evidence': self.evidence,
            #     'title': "X-Backend-Server Header Information Leak",
            #     'risk': 'Low',
            #     'summary': "The server is leaking information pertaining to backend systems (such as hostnames or IP addresses). Armed with this information an attacker may be able to attack other systems or more directly/efficiently attack those systems.",
            #     'solution': "Ensure that your web server, application server, load balancer, etc. is configured to suppress X-Backend-Server headers."
            # }
            return {
                'url': url,
                'method': "GET",
                "parameter": "",
                "attack": "",
                "evidence": self.evidence[0]
            }
        

def scan(url):
    # Create an instance of the XBackendServerInformationLeakScanRule class
    scanner = XBackendServerInformationLeakScanRule()
    
    # Call the scan_http_response_receive method to perform the scan
    return scanner.scan_http_response_receive(url)


# example usage returns none for nsi.isaix.com
# print(scan('http://nsi.isaix.com'))