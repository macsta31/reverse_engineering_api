import requests
from bs4 import BeautifulSoup

class ContentSecurityPolicyScanRule:

    # This checks if the CSP header is set correctly

    def __init__(self):
        self.problems = []  # List to store any problems found during scanning
        self.url = ''

    def scan_http_response_receive(self, url):
        self.url = url
        # Send a GET request to the specified URL
        response = requests.get(url)
        # Process the HTTP response
        self.process_response(response)

    def process_response(self, response):
        # Check if the response contains HTML content
        if 'html' not in response.headers.get('Content-Type', ''):
            return

        csp_header_found = False
        csp_options = response.headers.get("Content-Security-Policy", "").split(";")
        if csp_options[0] != "":
            csp_header_found = True

        # Check for unsafe directives in the Content Security Policy
        self.check_unsafe_directives(csp_options)
        self.check_xcsp(response, csp_header_found)
        self.check_x_webkit_csp(response, csp_header_found)

        if csp_header_found:
            soup = BeautifulSoup(response.content, "html.parser")
            meta_csp = self.has_meta_csp(soup)

            if meta_csp:
                self.check_meta_policy(response, soup, csp_header_found)

        if self.problems:
            # return {
            #     'cwe': "CWE-693: Protection Mechanism Failure",
            #     'evidence': self.problems,
            #     'title': 'Content Security Policy Misconfiguration',
            #     'risk': 'Medium',
            #     'summary': "Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.",
            #     'solution': "Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header."
            # }
            return {
                'url': self.url,
                'method': "GET",
                "parameter": "",
                "attack": "",
                "evidence": self.problems[0]
            }

    def check_unsafe_directives(self, csp_options):
        unsafe_directives = ['unsafe-inline', 'unsafe-eval']
        for option in csp_options:
            if any(directive in option for directive in unsafe_directives):
                problem = "Unsafe directive found in CSP: {}".format(option)
                self.problems.append(problem)
                # Report problem: Unsafe directive found in CSP

    def check_xcsp(self, response, csp_header_found):
        if 'X-Content-Security-Policy' in response.headers:
            # Report problem: X-Content-Security-Policy Header Present
            problem = "X-Content-Security-Policy Header Present"
            self.problems.append(problem)

    def check_x_webkit_csp(self, response, csp_header_found):
        if 'X-WebKit-CSP' in response.headers:
            # Report problem: X-WebKit-CSP Header Present
            problem = "X-WebKit-CSP Header Present"
            self.problems.append(problem)
            pass

    def has_meta_csp(self, soup):
        meta_tags = soup.find_all('meta')
        for tag in meta_tags:
            if tag.get('http-equiv') == 'Content-Security-Policy':
                return True
        return False

    def check_meta_policy(self, response, soup, csp_header_found):
        # Process meta policy
        # Report problem: Meta Policy Found
        problem = "Meta Policy Found"
        self.problems.append(problem)


def hasContentSecurity(url):
    # Create an instance of ContentSecurityPolicyScanRule
    scanner = ContentSecurityPolicyScanRule()
    # Scan the HTTP response received from the specified URL
    return scanner.scan_http_response_receive(url)
    

# Example usage: should return None for nsi.isaix.com
# print(hasContentSecurity('http://nsi.isaix.com'))
