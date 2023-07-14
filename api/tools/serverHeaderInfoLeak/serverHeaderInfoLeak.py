import re
import requests

class ServerHeaderInfoLeak:
    def __init__(self):
        self.evidence = []
        self.pattern = re.compile(".*\\d.*")

    def process(self, match):
        # Replace with your specific process here
        print(f"Matched Server Header: {match.group()}")

    def scan_http_response_receive(self, msg: requests.Response, url):
        server = msg.headers.get('Server', '').split(',')  # Gracefully handle if Server header doesn't exist
        if server:
            for s in server:
                match = self.pattern.match(s)
                if match:
                    self.evidence.append(s)

        if self.evidence:
            # return {
            #     'cwe': 'CWE-200: Exposure of Sensitive Information to an Unauthorized Actor',
            #     'evidence': self.evidence,
            #     'title': "Server Leaks Version Information via 'Server' HTTP Response Header Field",
            #     'risk': 'Low',
            #     'summary': "The web/application server is leaking version information via the “Server” HTTP response header. Access to such information may facilitate attackers identifying other vulnerabilities your web/application server is subject to.",
            #     'solution': "Ensure that your web server, application server, load balancer, etc. is configured to suppress the 'Server' header or provide generic details."
            # }
            return {
                'url': url,
                'method': "GET",
                "parameter": "",
                "attack": "",
                "evidence": self.evidence[0]
            }
                    


def scan(url):
    return ServerHeaderInfoLeak().scan_http_response_receive(requests.get(url), url)


# example usage: should return cwe-200 for nsi.isaix.com
# print(scan('http://nsi.isaix.com'))