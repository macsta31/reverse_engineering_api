import re
from collections import OrderedDict


class HashDisclosureScanRule:
    # Create HashAlert class
    class HashAlert:
        def __init__(self, description, risk, confidence):
            self.description = description
            self.risk = risk
            self.confidence = confidence

    def __init__(self):

        # Create a dictionary of regex patterns for various hash types
        self.hash_patterns = {
            re.compile(r'\$LM\$[a-f0-9]{16}', re.IGNORECASE): "LanMan / DES",
            re.compile(r'\$LM\$[a-f0-9]{16}', re.IGNORECASE): "LanMan / DES",
            re.compile(r"smd5\$[0-9A-Za-z./]{0,8}\$[0-9A-Za-z./]{22}", re.IGNORECASE): "Sun MD5",
            re.compile(r"\$apr1\$[0-9A-Za-z./]{0,8}\$[0-9A-Za-z./]{22}", re.IGNORECASE): "APR1 MD5",
            re.compile(r"\$P\$[0-9A-Za-z./]{31}", re.IGNORECASE): "PHPass Portable",
            re.compile(r"\$H\$[0-9A-Za-z./]{31}", re.IGNORECASE): "PHPass Portable",
            re.compile(r"\$P\$[0-9A-Za-z./]{31}", re.IGNORECASE): "PHPass Wordpress",
            re.compile(r"\$H\$[0-9A-Za-z./]{31}", re.IGNORECASE): "PHPass Wordpress, Joomla, phpBB3",
            re.compile(r"\b[0-9a-f]{16}\b", re.IGNORECASE): "MySQL323",
            re.compile(r"\*+[0-9a-f]{40}\b", re.IGNORECASE): "MySQL4.1/MySQL5",
            re.compile(r"\b[0-9a-f]{16}\b", re.IGNORECASE): "Cisco IOS",
            re.compile(r"\b[A-Za-z0-9/+]{16}\b", re.IGNORECASE): "Cisco PIX MD5",
            re.compile(r"\$8\$[0-9A-Za-z./]{14}\$[0-9A-Za-z./]{43}", re.IGNORECASE): "Cisco $8$",
            re.compile(r"\$9\$[0-9A-Za-z./]{14}\$[0-9A-Za-z./]{43}", re.IGNORECASE): "Cisco $9$",
            re.compile(r"\$1\$[0-9A-Za-z./]{0,8}\$[0-9A-Za-z./]{22}", re.IGNORECASE): "MD5 Unix",
            re.compile(r"\$5\$[0-9A-Za-z./]{0,16}\$[0-9A-Za-z./]{43}", re.IGNORECASE): "SHA-256 Unix",
            re.compile(r"\$6\$[0-9A-Za-z./]{0,16}\$[0-9A-Za-z./]{86}", re.IGNORECASE): "SHA-512 Unix"
        }

    def scan_http_request_send(self, msg):
        # print(f"Checking request of message {msg} for Hashes")
        request_header = msg['request_header']
        request_body = msg['request_body']
        request_parts = [request_header, request_body]
        self.check_for_hashes(msg, request_parts)

    def scan_http_response_receive(self, msg):
        # print(f"Checking response of message {msg} for Hashes")
        response_header = msg['response_header']
        response_body = msg['response_body']
        response_parts = [response_header, response_body]
        self.check_for_hashes(msg, response_parts)

    def check_for_hashes(self, msg, haystacks):
        hash_type = None
        minimum_confidence = "CONFIDENCE_LOW"
        for hash_pattern, hash_alert in self.hash_patterns.items():
            # print(f"Trying Hash Pattern: {hash_pattern} for hash type {hash_type}")
            for haystack in haystacks:
                matches = re.findall(hash_pattern, haystack)
                for match in matches:
                    evidence = match
                    return {
                        'url': url,
                        'method': "GET",
                        "parameter": "",
                        "attack": "",
                        "evidence": self.evidence[0]
                    }
                    # print(f"Found a match for hash type {hash_type} : {evidence}")


def scanForHash(html, url):
    scanner = HashDisclosureScanRule()
    scanner.scan(html, url)
