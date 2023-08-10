import requests
import re

class informationDisclosureReferrer:

    def __init__(self):
        self.sensitive_patterns = {
            re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}\b"): "email_address",
            re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})\b"): "credit_card",
            re.compile(r"\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b"): "us_ssn"
        }

    def scan_http_response_receive(self, msg: requests.Response, url):
            referrer = msg.headers.get("Referrer")
            if not referrer:
                return
            if not referrer.startswith('/') or referrer != url:
                found_patterns = ""
                for pattern, pattern_name in self.sensitive_patterns.items():
                    match = pattern.search(referrer)
                    if match:
                        found_patterns = match.group()
                        break  # break after the first match
                if found_patterns:
                    return {
                        'url': url,
                        'method': "GET",
                        "parameter": "",
                        "attack": "",
                        "evidence": found_patterns
                    }
            else:
                return None

def scan(url):
    scanner = informationDisclosureReferrer()
    return scanner.scan_http_response_receive(requests.get(url), url)

# result = scan('http://nsi.isaix.com')
# if result:
#     print(result)
