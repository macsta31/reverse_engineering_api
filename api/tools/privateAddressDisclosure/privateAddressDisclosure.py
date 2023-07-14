import re
import requests
from typing import Dict, List

# needs tuning
class PrivateAddressDisclosureScanRule:\

    def __init__(self):

        self.evidence = []
        # Regular expression patterns for private IP addresses
        self.REGULAR_IP_OCTET = "(25[0-5]|2[0-4]\d|[01]?\d{1,2})"
        self.NOT_FOLLOWED_BY_ANOTHER_DOTTED_NUMBER = r"\b(?!.\d)"
        self.NOT_FOLLOWED_BY_ANOTHER_DASHED_NUMBER = r"\b(?!-\d)"
        self.NOT_PRECEDED_BY_ANOTHER_DOTTED_NUMBER = r"(?<!\d.)\b"
        self.PRECEDED_BY_IP_DASH = r"\bip-"

        # Construct the regular expression pattern for private IP addresses
        self.pattern_private_ip = re.compile(
            f"({self.NOT_PRECEDED_BY_ANOTHER_DOTTED_NUMBER}10\.({self.REGULAR_IP_OCTET}\.){2}{self.REGULAR_IP_OCTET}{self.NOT_FOLLOWED_BY_ANOTHER_DOTTED_NUMBER}|"
            f"{self.NOT_PRECEDED_BY_ANOTHER_DOTTED_NUMBER}172\.(3[01]|2\d|1[6-9])\.{self.REGULAR_IP_OCTET}\.{self.REGULAR_IP_OCTET}{self.NOT_FOLLOWED_BY_ANOTHER_DOTTED_NUMBER}|"
            f"{self.NOT_PRECEDED_BY_ANOTHER_DOTTED_NUMBER}192\.168\.{self.REGULAR_IP_OCTET}\.{self.REGULAR_IP_OCTET}{self.NOT_FOLLOWED_BY_ANOTHER_DOTTED_NUMBER}|"
            f"{self.PRECEDED_BY_IP_DASH}10-({self.REGULAR_IP_OCTET}-){2}{self.REGULAR_IP_OCTET}{self.NOT_FOLLOWED_BY_ANOTHER_DOTTED_NUMBER}|"
            f"{self.PRECEDED_BY_IP_DASH}172-(3[01]|2\d|1[6-9])-{self.REGULAR_IP_OCTET}-{self.REGULAR_IP_OCTET}{self.NOT_FOLLOWED_BY_ANOTHER_DASHED_NUMBER}|"
            f"{self.PRECEDED_BY_IP_DASH}192-168-{self.REGULAR_IP_OCTET}-{self.REGULAR_IP_OCTET}{self.NOT_FOLLOWED_BY_ANOTHER_DASHED_NUMBER})"
            f"(:(0|[1-9]\d{{0,3}}|[1-5]\d{{4}}|6[0-4]\d{{3}}|65([0-4]\d{{2}}|5[0-2]\d|53[0-5]))\b)?",
            re.MULTILINE
        )


    def get_cwe_id(self) -> int:
        return 200  # CWE Id 200 - Information Exposure


    def scan_http_response_receive(self, msg: requests.Response, url):
        host = msg.url.split('//')[-1].split('/')[0].split('?')[0]  # Extracting host from URL

        txt_body = msg.text
        matcher = self.pattern_private_ip.search(txt_body)
        txt_found = []
        first_one = None

        # Find private IP addresses in the text body
        while matcher:
            if matcher.group(1).lower() == host.lower():
                continue

            if first_one is None:
                first_one = matcher.group()

            txt_found.append(matcher.group())
            matcher = self.pattern_private_ip.search(txt_body, matcher.start() + 1)

        if txt_found:
            self.evidence.append(txt_found)
            # Raise an alert for exposure of sensitive information
            # return {
            #     'cwe': 'CWE-200: Exposure of Sensitive Information to an Unauthorized Actor',
            #     'evidence': self.evidence,
            #     'title': 'Private IP Disclosure',
            #     'risk': 'Low',
            #     'summary': "A private IP (such as 10.x.x.x, 172.x.x.x, 192.168.x.x) or an Amazon EC2 private hostname (for example, ip-10-0-56-78) has been found in the HTTP response body. This information might be helpful for further attacks targeting internal systems.",
            #     'solution': "Remove the private IP address from the HTTP response body. For comments, use JSP/ASP/PHP comment instead of HTML/JavaScript comment which can be seen by client browsers."
            # }
            return {
                'url': url,
                'method': "GET",
                "parameter": "",
                "attack": "",
                "evidence": self.evidence[0]
            }


def scanPrivateAddressDisclosure(url):
    scanner = PrivateAddressDisclosureScanRule()
    return scanner.scan_http_response_receive(requests.get(url), url)


# example usage: should return none for nsi.isaix.com
# print(scanPrivateAddressDisclosure('http://nsi.isaix.com'))