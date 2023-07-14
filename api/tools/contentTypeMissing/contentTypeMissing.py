import requests

class ContentTypeMissingScan:
    # This checks if the Content-Type header is set
    def __init__(self):
        # self.evidence = []
        pass

    def scan_http_response(self, url):
        # Send a GET request to the specified URL
        response = requests.get(url)
        if response:
            # Process the HTTP response
            if self.process_response(response):
                return None  # Content-Type header is present
        else:
            # return {
            #     'cwe': "CWE-345: Insufficient Verification of Data Authenticity",
            #     'evidence': "No Content-Type header",
            #     'title': 'Content-Type Header Missing',
            #     'risk': 'Informational',
            #     'summary': "The Content-Type header was either missing or empty.",
            #     'solution': "Ensure each page is setting the specific and appropriate content-type value for the content being delivered."
            # }
            return {
                'url': url,
                'method': "GET",
                "parameter": "",
                "attack": "",
                "evidence": "No Content-Type header"
            }


    def process_response(self, response):
        headers = response.headers
        ct = headers.get('Content-Type', "").split(';')
        if len(ct) > 0:
            return 1  # Content-Type header is present
        else:
            return 0  # Content-Type header is missing
    

def hasContentType(url):
    # Create an instance of ContentTypeMissingScan
    scan = ContentTypeMissingScan()
    # Scan the HTTP response received from the specified URL
    return scan.scan_http_response(url)


# Example usage: should return none for nsi.isaix.com
# print(hasContentType('http://nsi.isaix.com'))
