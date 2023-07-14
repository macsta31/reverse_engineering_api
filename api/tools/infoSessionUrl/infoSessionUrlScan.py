import re
import requests
from urllib.parse import urlparse, parse_qs

class InfoSessionUrlScan:
    # This checks if a jsession id key is present in anything client facing
    def __init__(self):
        self.SESSION_TOKEN_MIN_LENGTH = 8
        self.pattern = re.compile(f'jsessionid=[\\dA-Z]{{{self.SESSION_TOKEN_MIN_LENGTH},}}', re.IGNORECASE)

        self.EXT_LINK = 'https?://([\\w\\.\\-_]+)'

        self.patterns = [
            re.compile(rf'src\s*=\s*[\'"]?{self.EXT_LINK}', re.IGNORECASE),  # Pattern for src attributes
            re.compile(rf'href\s*=\s*[\'"]?{self.EXT_LINK}', re.IGNORECASE),  # Pattern for href attributes
            re.compile(rf'[=\(]\s*[\'"]{self.EXT_LINK}', re.IGNORECASE),  # Pattern for URLs within parentheses or assignments
        ]

        self.evidence = []

    def scan_http_response(self, msg: requests.Response, url):
        self.scan_params(msg)
        self.check_exposure_to_3rd_party(msg)

        if self.evidence:
            # return {
            #     'cwe': "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor",
            #     'evidence': self.evidence,
            #     'title': 'Session ID in URL Rewrite',
            #     'risk': 'Medium',
            #     'summary': "URL rewrite is used to track user session ID. The session ID may be disclosed via cross-site referer header. In addition, the session ID might be stored in browser history or server logs.",
            #     "solution": "For secure content, put session ID in a cookie. To be even more secure consider using a combination of cookie and URL rewrite."
            # }
            return {
                'url': url,
                'method': "GET",
                "parameter": "",
                "attack": "",
                "evidence": self.evidence[0]
            }

    def scan_params(self, msg:requests.Response):
        parsedurl = urlparse(msg.url)
        params = parse_qs(parsedurl.query)
        

        for param in params:
            match = self.pattern.search(param)
            if match:
                self.evidence.append(param)
                # return "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor"

    def check_exposure_to_3rd_party(self, msg: requests.Response):
        body = msg.text
        for pattern in self.patterns:
            match = pattern.search(body)
            if match:
                self.evidence.append(match.group())
                # return "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor"

def scanInfoSessionUrl(url):
    scanner = InfoSessionUrlScan()
    return scanner.scan_http_response(requests.get(url), url)

# Example usage: should return None for nsi.isaix.com
# print(scanInfoSessionUrl('http://nsi.isaix.com'))
