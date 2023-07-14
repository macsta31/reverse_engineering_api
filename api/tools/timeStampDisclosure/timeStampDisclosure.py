import re
import requests

class TimeStampScanRule:

    def __init__(self):
        self.evidence = []
        # Regular expression pattern to match timestamps in the format "yyyyMMdd"
        self.timeStampPattern = re.compile(r"\b(?:1\d|2[0-2])\d{8}\b(?!%)")

        # List of headers to ignore during scanning
        self.headersToIgnore = [
            "_KEEP_ALIVE",
            "CACHE_CONTROL",
            "ETag",
            "Age",
            "Strict-Transport-Security",
            "Report-To",
            "NEL",
            "Expect-CT",
            "RateLimit-Reset",
            "X-RateLimit-Reset",
            "X-Rate-Limit-Reset"
        ]

    def scan_http_response_receive(self, msg: requests.Response, url):
        headers = msg.headers
        responseHeaders = []

        # Filter out headers that should be ignored
        for header in headers:
            if header not in self.headersToIgnore:
                responseHeaders.append(header)

        # Scan each response header for timestamps
        for header in responseHeaders:
            if self.timeStampPattern.match(msg.headers.get(header, '')):
                self.evidence.append(msg.headers.get(header, ''))

        if self.evidence:
            # return {
            #     'cwe': 'CWE-200: Exposure of Sensitive Information to an Unauthorized Actor',
            #     'evidence': self.evidence,
            #     'title': "Timestamp Disclosure",
            #     'risk': 'Low',
            #     'summary': "A timestamp was disclosed by the application/web server",
            #     'solution': "Manually confirm that the timestamp data is not sensitive, and that the data cannot be aggregated to disclose exploitable patterns."
            # }
            return {
                'url': url,
                'method': "GET",
                "parameter": "",
                "attack": "",
                "evidence": self.evidence[0]
            }

def scan(url):
    scanner = TimeStampScanRule()
    return scanner.scan_http_response_receive(requests.get(url), url)


# example usage returns none for nsi.isaix.com
# print(scan('http://nsi.isaix.com'))