from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import requests

class CrossDomainScriptInclusionScanRule:
    # This checks if there are javascript file inclusions from outside the trusted control sphere
    def __init__(self):
        self.trusted_domains = set()  # Set to store trusted domains (placeholder)
        self.alerts = []  # List to store alerts found during scanning
        self.evidence = []

    def scan_http_response_receive(self, msg, url):
        # Extract response body and header
        response_body = msg.content
        response_header = msg.headers

        # Check if the response body is HTML
        if len(response_body) > 0 and 'html' in response_header['Content-Type']:
            soup = BeautifulSoup(response_body, 'html.parser')
            source_elements = soup.find_all('script')
            if source_elements is not None:
                for source_element in source_elements:
                    src = source_element.get("src")
                    if src is not None \
                            and self.is_script_from_other_domain(msg.url, src) \
                            and src not in self.trusted_domains:
                        integrity = source_element.get("integrity")
                        if integrity is None or integrity.strip() == '':
                            # If the script is from another domain and does not have integrity, raise an alert
                            self.alerts.append((msg, src, str(source_element)))
                            self.raise_alert(msg, src, str(source_element))

        if self.evidence:
            # return {
            #     'cwe': "CWE-829: Inclusion of Functionality from Untrusted Control Sphere",
            #     'evidence': self.evidence,
            #     'title': 'Cross-Domain JavaScript Source File Inclusion',
            #     'risk': 'Low',
            #     'summary': "The page includes one or more script files from a third-party domain.",
            #     "solution": "Ensure JavaScript source files are loaded from only trusted sources, and the sources can't be controlled by end users of the application."
            # }
            return {
                'url': url,
                'method': "GET",
                "parameter": "",
                "attack": "",
                "evidence": self.evidence[0]
            }

    def raise_alert(self, msg, cross_domain_script, evidence):
        self.evidence.append(evidence)
        pass

    def is_script_from_other_domain(self, host, script_url):
        # Check if the script is from another domain
        if not script_url.startswith("//") \
                and (script_url.startswith("/") \
                     or script_url.startswith("./") \
                     or script_url.startswith("../")):
            return False
        other_domain = False
        script_uri = urljoin(host, script_url)
        parsed_host = urlparse(host).netloc
        parsed_script_uri = urlparse(script_uri).netloc
        if parsed_script_uri != None and parsed_script_uri.lower() != parsed_host.lower():
            other_domain = True
        return other_domain


def corsScriptInclusion(url):
    # Send a GET request to the specified URL
    msg = requests.get(url)
    # Create an instance of CrossDomainScriptInclusionScanRule
    scanner = CrossDomainScriptInclusionScanRule()
    # Scan the HTTP response received from the specified URL
    return scanner.scan_http_response_receive(msg, url)

# example usage: should return none for nsi.isaix.com / cwe-829 for facebook.com
# print(corsScriptInclusion('https://facebook.com'))
