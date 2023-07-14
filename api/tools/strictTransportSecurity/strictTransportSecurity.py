import requests
import re


class StrictTransportSecurityScanRule:

    def __init__(self):
        self.evidence = []
    def check_hsts(self, url):
        try:
            response = requests.get(url)
            headers = response.headers

            if "Strict-Transport-Security" in headers:
                hsts_header = headers["Strict-Transport-Security"]
                # print(hsts_header)
                max_age = None

                bad_max_age_pattern = re.compile(r"\bmax-age\s*=\s*['\"]\s*0\s*['\"]\s*", re.IGNORECASE)
                max_age_pattern = re.compile(r"\bmax-age\s*=\s*\d+", re.IGNORECASE)
                malformed_max_age_pattern = re.compile(r"['\"+]\s*max", re.IGNORECASE)
                well_formed_pattern = re.compile(r"[\x20-\x7E]*", re.IGNORECASE)

                for directive in hsts_header.split(";"):
                    directive = directive.strip()
                    if directive.startswith("max-age"):
                        max_age_match = max_age_pattern.search(directive)
                        if max_age_match:
                            max_age = int(max_age_match.group().split("=")[1].strip('\'\"'))
                            break

                if max_age is not None:
                    if max_age == 0:
                        print("HSTS headers are present, but the max-age is set to 0 (disabled).")
                        self.evidence.append("HSTS header Max age: {}".format(max_age))
                        # return "CWE-319: Cleartext Transmission of Sensitive Information"
                    elif bad_max_age_pattern.search(hsts_header):
                        print("HSTS headers are present, but the max-age is set to 0 (disabled).")
                        self.evidence.append("HSTS header: {}".format(hsts_header))
                        # return "CWE-319: Cleartext Transmission of Sensitive Information"
                    elif malformed_max_age_pattern.search(hsts_header):
                        print("HSTS headers are present, but the max-age value is malformed.")
                        self.evidence.append("HSTS header: {}".format(hsts_header))
                        # return "CWE-319: Cleartext Transmission of Sensitive Information"
                    elif not well_formed_pattern.search(hsts_header):
                        print("HSTS headers are present, but the content is malformed.")
                        self.evidence.append("HSTS header: {}".format(hsts_header))
                        # return "CWE-319: Cleartext Transmission of Sensitive Information"
                    else:
                        print("HSTS headers are properly set with a valid max-age value.")
                else:
                    print("HSTS headers are present, but the max-age value is not set or invalid.")
                    self.evidence.append("HSTS header Max Age: {}".format(max_age))
                    return "CWE-319: Cleartext Transmission of Sensitive Information"
            else:
                self.evidence.append("Absent HSTS header")
                # return "CWE-319: Cleartext Transmission of Sensitive Information"
                print("HSTS headers are not set.")
        except requests.exceptions.RequestException as e:
            print("An error occurred:", str(e))

        if self.evidence:
            # return {
            #     'cwe': 'CWE-319: Cleartext Transmission of Sensitive Information',
            #     'evidence': self.evidence,
            #     'title': "Strict-Transport-Security Header",
            #     'risk': '',
            #     'summary': "HTTP Strict Transport Security (HSTS) is a web security policy mechanism whereby a web server declares that complying user agents (such as a web browser) are to interact with it using only secure HTTPS connections (i.e. HTTP layered over TLS/SSL). HSTS is an IETF standards track protocol and is specified in RFC 6797.",
            #     'solution': "Ensure that your web server, application server, load balancer, etc. is configured to enforce Strict-Transport-Security."
            # }
            return {
                'url': url,
                'method': "GET",
                "parameter": "",
                "attack": "",
                "evidence": self.evidence[0]
            }
        

    def scan(self, url):
        return self.check_hsts(url)

def scan(url):
    scanner = StrictTransportSecurityScanRule()
    return scanner.scan(url)

# example usage: returns cwe-319 for nsi.isaix.com

# print(scan('http://nsi.isaix.com'))