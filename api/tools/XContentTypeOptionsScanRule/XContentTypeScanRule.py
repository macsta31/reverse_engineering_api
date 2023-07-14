import requests
import logging

class XContentTypeOptionsScanRule:

    def __init__(self):
        self.evidence = []

    def scan_http_response_receive(self, url, include_error_redirect_responses=False):
        # Send an HTTP GET request to the specified URL
        response = requests.get(url)

        if response.content:
            status = response.status_code

            if (400 <= status < 500 or 500 <= status < 600 or 300 <= status < 400) and not include_error_redirect_responses:
                # Exclude error and redirect responses based on the flag value
                return None

            # Get the value of the 'X-Content-Type-Options' header from the response
            x_content_type_options = response.headers.get('X-Content-Type-Options', None)

            if not x_content_type_options:
                self.evidence.append("Absence of X-Content-Type Header")
                # If 'X-Content-Type-Options' header is not present, return the corresponding CWE ID indicating a protection mechanism failure
                # return {
                #     'cwe': 'CWE-693: Protection Mechanism Failure',
                #     'evidence': self.evidence,
                #     'title': 'X-Content-Type-Options Header Missing',
                #     'risk': 'Medium',
                #     'summary': "The Anti-MIME-Sniffing header X-Content-Type-Options was not set to ’nosniff’. This allows older versions of Internet Explorer and Chrome to perform MIME-sniffing on the response body, potentially causing the response body to be interpreted and displayed as a content type other than the declared content type. Current (early 2014) and legacy versions of Firefox will use the declared content type (if one is set), rather than performing MIME-sniffing.",
                #     'solution': "Ensure that the application/web server sets the Content-Type header appropriately, and that it sets the X-Content-Type-Options header to 'nosniff' for all web pages. If possible, ensure that the end user uses a standards-compliant and modern web browser that does not perform MIME-sniffing at all, or that can be directed by the web application/web server to not perform MIME-sniffing."
                # }
                return {
                    'url': url,
                    'method': "GET",
                    "parameter": "",
                    "attack": "",
                    "evidence": self.evidence[0]
                }
            else:
                for directive in x_content_type_options.split(','):
                    if 'nosniff' not in directive.lower():
                        self.evidence.append("{}: {}".format("X-Content-Type", directive))
                        # If 'nosniff' directive is not found in the 'X-Content-Type-Options' header, return the corresponding CWE ID indicating a protection mechanism failure
                    #     return {
                    #     'cwe': 'CWE-693: Protection Mechanism Failure',
                    #     'evidence': self.evidence,
                    #     'title': 'X-Content-Type-Options Header Missing',
                    #     'risk': 'Medium',
                    #     'summary': "The Anti-MIME-Sniffing header X-Content-Type-Options was not set to ’nosniff’. This allows older versions of Internet Explorer and Chrome to perform MIME-sniffing on the response body, potentially causing the response body to be interpreted and displayed as a content type other than the declared content type. Current (early 2014) and legacy versions of Firefox will use the declared content type (if one is set), rather than performing MIME-sniffing.",
                    #     'solution': "Ensure that the application/web server sets the Content-Type header appropriately, and that it sets the X-Content-Type-Options header to 'nosniff' for all web pages. If possible, ensure that the end user uses a standards-compliant and modern web browser that does not perform MIME-sniffing at all, or that can be directed by the web application/web server to not perform MIME-sniffing."
                    # }
                    return {
                        'url': url,
                        'method': "GET",
                        "parameter": "",
                        "attack": "",
                        "evidence": self.evidence[0]
                    }

def scan(url):
    # Create an instance of the XContentTypeOptionsScanRule class
    scanner = XContentTypeOptionsScanRule()
    
    # Call the scan_http_response_receive method to perform the scan
    return scanner.scan_http_response_receive(url)


# exmaple usage returns cwe for nsi.isaix.com
# print(scan('http://nsi.isaix.com'))
