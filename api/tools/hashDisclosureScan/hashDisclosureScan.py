import re
import requests


class HashDisclosureScanRule:
    # Create HashAlert class
    class HashAlert:
        def __init__(self):
            pass

    def __init__(self):

        # Create a dictionary of regex patterns for various hash types
        self.hash_patterns = {
            re.compile(r"\$LM\$[a-f0-9]{16}", re.IGNORECASE): "LanMan / DES",
            re.compile(r"\$K4\$[a-f0-9]{16},", re.IGNORECASE): "Kerberos AFS DES",
            re.compile(r"\$2a\$05\$[a-z0-9\+\-_./=]{53}", re.IGNORECASE): "OpenBSD Blowfish",
            re.compile(r"\$2y\$05\$[a-z0-9\+\-_./=]{53}", re.IGNORECASE): "OpenBSD Blowfish",
            re.compile(r"\$1\$[./0-9A-Za-z]{0,8}\$[./0-9A-Za-z]{22}"): "MD5 Crypt",
            re.compile(r"\$5\$[./0-9A-Za-z]{0,16}\$[./0-9A-Za-z]{43}"): "SHA-256 Crypt",
            re.compile(r"\$5\$rounds=[0-9]+\$[./0-9A-Za-z]{0,16}\$[./0-9A-Za-z]{43}"): "SHA-256 Crypt",
            re.compile(r"\$6\$[./0-9A-Za-z]{0,16}\$[./0-9A-Za-z]{86}"): "SHA-512 Crypt",
            re.compile(r"\$6\$rounds=[0-9]+\$[./0-9A-Za-z]{0,16}\$[./0-9A-Za-z]{86}"): "SHA-512 Crypt",
            re.compile(r"\$2\$[0-9]{2}\$[./0-9A-Za-z]{53}"): "BCrypt",
            re.compile(r"\$2a\$[0-9]{2}\$[./0-9A-Za-z]{53}"): "BCrypt",
            re.compile(r"\$3\$\$[0-9a-f]{32}"): "NTLM",
            re.compile(r"\$NT\$[0-9a-f]{32}"): "NTLM",
            re.compile(r"\b[0-9A-F]{48}\b"): "Mac OSX salted SHA-1",
            re.compile(r"\b[0-9a-f]{128}\b", re.IGNORECASE): "SHA-512",
            re.compile(r"\b[0-9a-f]{96}\b", re.IGNORECASE): "SHA-384",
            re.compile(r"\b[0-9a-f]{64}\b", re.IGNORECASE): "SHA-256",
            re.compile(r"\b[0-9a-f]{56}\b", re.IGNORECASE): "SHA-224",
            re.compile(r"\b[0-9a-f]{40}\b", re.IGNORECASE): "SHA-1",
            re.compile(r"\b\[0-9a-f]{32}\b"): "LanMan",
            re.compile(r"(?<!jsessionid=)\b[0-9a-f]{32}\b", re.IGNORECASE): "MD4 / MD5"
        }

    # def scan_http_request_send(self, msg: requests.Response, html):
    #     # print(f"Checking request of message {msg} for Hashes")
    #     request_header = msg.headers
    #     request_body = msg['request_body']
    #     request_parts = [request_header, request_body]
    #     self.check_for_hashes(msg, request_parts)

    def scan_http_response_receive(self, msg:requests.Response, html, url):
        # print(f"Checking response of message {msg} for Hashes")
        response_header = msg.headers
        response_body = html
        response_parts = [response_header, response_body]
        return self.check_for_hashes(response_parts, url)

    def check_for_hashes(self, response_parts, url):
        # Iterate over each part of the response (headers, body)
        for part in response_parts:
            # Iterate over each pattern in the hash_patterns dictionary

            for pattern, hash_type in self.hash_patterns.items():
                # Search for the pattern in the current part
                matches = pattern.findall(str(part))
                if matches:
                    # print(f"Found matches: {matches} for pattern: {pattern}")
                    for match in matches:
                        return {
                            'url': url,
                            'method': "GET",
                            "parameter": "",
                            "attack": "",
                            "evidence": 'type: {}, match: {}'.format(hash_type, match)
                        }




def scan(url, html):
    scanner = HashDisclosureScanRule()
    return scanner.scan_http_response_receive(requests.get(url), html, url)


# html_content = """
# <html>
# <head>
#     <title>Test Page</title>
# </head>
# <body>
#     <p>Some content here</p>
#     <p>Hidden hash: $apr1$abcdefg$1234567890abcdefghijkl</p>
# </body>
# </html>
# """

# url = 'http://nsi.isaix.com'
# print(scan(url, html_content))