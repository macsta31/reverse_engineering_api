import requests
from bs4 import BeautifulSoup

class ContentSecurityPolicyMissingScanRule:

# This checks if the content security policy header is present and set correctly
    def __init__(self):
        self.evidence = []


    def scan_http_response_receive(self, url):
        response = requests.get(url)
        self.process_response(response)
        if self.evidence:
            # return {
            #     'cwe': 'CWE-693: Protection Mechanism Failure',
            #     'evidence': self.evidence,
            #     'title': 'Content Security Policy Missing or Incorrectly Set',
            #     'risk': "Medium",
            #     'summary': 'Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.',
            #     'solution': "Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header."
            # }
            return {
                'url': url,
                'method': "GET",
                "parameter": "",
                "attack": "",
                "evidence": self.evidence[0]
            }


    def process_response(self, response):
        # Only applies to HTML responses
        if 'html' not in response.headers.get('Content-Type', ''):
            return

        csp = response.headers.get('Content-Security-Policy', '')
        # print(csp)
        # Check for missing CSP header

        if not self.has_csp_header(response):
            self.evidence.append("CSP Header Missing")


        # Check for obsolete CSP header
        if self.has_obsolete_csp_header(response):
            self.evidence.append("Obsolete CSP Header Present")

        # Check for CSP report only header
        if self.has_csp_report_only_header(response):
            self.evidence.append("CSP Report Only Header Present")


    def has_csp_header(self, response):
       return 'Content-Security-Policy' in response.headers

    def has_obsolete_csp_header(self, response):
        return 'X-Content-Security-Policy' in response.headers or 'X-WebKit-CSP' in response.headers

    def has_csp_report_only_header(self, response):
        return 'Content-Security-Policy-Report-Only' in response.headers

def isMissing(url):
    # Example usage:
    scanner = ContentSecurityPolicyMissingScanRule()
    return scanner.scan_http_response_receive(url)

# uncomment to test, should return cwe-693
# print(isMissing('http://nsi.isaix.com'))
