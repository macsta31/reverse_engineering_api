import re
from urllib.parse import parse_qs, urlparse
import requests

class InformationDisclosureURL:
    # This checks any sensitive information is exposed in the url

    def __init__(self):
        self.evidence = []
        self.patterns = [
            re.compile("\\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,4}\\b"),  # Email pattern
            re.compile("\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\\d{3})\\d{11})\\b"),  # Credit card pattern
            re.compile("\\b[0-9]{3}-[0-9]{2}-[0-9]{4}\\b")  # Social Security Number pattern
        ]

    def scan_http_response(self, msg: requests.Response, url):
        parsedurl = urlparse(msg.url)
        params = parse_qs(parsedurl.query)

        for param in params:
            for pattern in self.patterns:
                match = pattern.search(param)
                if match:
                    self.evidence.append(param)
                    # return "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor"
        if self.evidence:
            # return {
            #     'cwe': "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor",
            #     'evidence': self.evidence,
            #     'title': 'Information Disclosure - Sensitive Information in URL',
            #     'risk': 'Informational',
            #     'summary': "The request appeared to contain sensitive information leaked in the URL. This can violate PCI and most organizational compliance policies. You can configure the list of strings for this check to add or remove values specific to your environment.",
            #     "solution": "Do not pass sensitive information in URIs."
            # }
            return {
                'url': url,
                'method': "GET",
                "parameter": "",
                "attack": "",
                "evidence": self.evidence[0]
            }
    
def scan(url):
    scanner = InformationDisclosureURL()
    return scanner.scan_http_response(requests.get(url), url)


# example usage: should return None for nsi.isaix.com
# print(scan('http://nsi.isaix.com'))