import requests

class BigRedirectsScanRule:
    # This checks if the website contains a large redirect
    def __init__(self):

        self.evidence = []

    def scan_http_response_receive(self, msg: requests.Response):
        # Check if the HTTP response is a redirect response
        if self.is_redirect_response(msg):
            # Extract the 'Location' header from the response
            location_header = msg.headers.get("Location")
            if location_header:
                # Get the size of the response received
                response_size = self.get_response_size(msg)
                # Calculate the predicted size of the response based on the 'Location' header
                predicted_size = self.get_predicted_response_size(location_header)
                if response_size > predicted_size:
                    # Raise an alert if the response size is larger than the predicted size
                    self.evidence.append(location_header)
        if self.evidence:
            # return {
            #     'cwe': 'CWE-201: Insertion of Sensitive Information Into Sent Data',
            #     'evidence': self.evidence,
            #     'title': 'Big Redirect Detected (Potential Sensitive Information Leak)',
            #     'risk': "",
            #     'summary': "The server has responded with a redirect that seems to provide a large response. This may indicate that although the server sent a redirect it also responded with body content (which may include sensitive details, PII, etc.).",
            #     'solution': "Ensure that no sensitive information is leaked via redirect responses. Redirect responses should have almost no content."
            # }
            return {
                'url': msg.url,
                'method': "GET",
                "parameter": "",
                "attack": "",
                "evidence": self.evidence[0]
            }

    def is_redirect_response(self, msg: requests.Response):
        # Check if the status code indicates a redirect response (between 300 and 399, excluding 304)
        status_code = msg.status_code
        return 300 <= status_code < 400 and status_code != 304

    def get_response_size(self, msg: requests.Response):
        # Calculate and return the size of the response content
        return len(msg.content)

    def get_predicted_response_size(self, location_header: str):
        # Calculate and return the predicted size of the response based on the 'Location' header
        return len(location_header) + 300

    
def isBigRedirect(url):
    # Create an instance of BigRedirectsScanRule
    scanner = BigRedirectsScanRule()
    # Send a GET request to the specified URL and scan the HTTP response
    return scanner.scan_http_response_receive(requests.get(url, allow_redirects=False))


# Example usage: should return None on nsi.isaix.com
# print(isBigRedirect('http://nsi.isaix.com/c5ip/'))
