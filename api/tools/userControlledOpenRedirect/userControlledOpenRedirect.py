import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs
from collections import defaultdict

class UserControlledOpenRedirectScanRule:
    def __init__(self):
        self.headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"
        }
        self.evidence = []

    def get_url_params(self, url):
        # Extract query parameters from the URL
        parsed_url = urlparse(url)
        return parse_qs(parsed_url.query)

    def get_form_params(self, url):
        # Extract form parameters from the HTML of the URL
        response = requests.get(url, headers=self.headers)
        bsoup = BeautifulSoup(response.text, 'html.parser')
        form_data = defaultdict(str)
        for form in bsoup.find_all('form'):
            for input_tag in form.find_all('input'):
                form_data[input_tag.get('name')] = input_tag.get('value')
        return form_data

    def scan_http_response(self, url):
        # Perform the scan on the given URL
        response = requests.get(url, headers=self.headers)

        # Check if the response is a redirection (status code 301 or 302)
        if response.status_code in [301, 302]:
            if 'Location' in response.headers:
                # Extract the URL parameters from the original URL and form parameters from the HTML
                url_params = self.get_url_params(url)
                form_params = self.get_form_params(url)
                params = {**url_params, **form_params}
                if params:
                    retval = self.check_user_controllable_location_header_value(response, params, url)
                    if retval:
                        return retval


    def check_user_controllable_location_header_value(self, response, params, url):
        location_header = response.headers['Location']
        if len(location_header) > 0:
            request_domain = urlparse(response.request.url).netloc
            response_domain = urlparse(location_header).netloc
            if request_domain != response_domain:
                for param, value in params.items():
                    if value.lower() in [response_domain.lower(), location_header.lower()]:
                        # return "CWE-601: URL Redirection to Untrusted Site ('Open Redirect')"
                        # return {
                        #     'cwe': "CWE-601: URL Redirection to Untrusted Site ('Open Redirect')",
                        #     'evidence': self.evidence,
                        #     'title': "User Controllable JavaScript Event (XSS)",
                        #     'risk': '',
                        #     'summary': "Open redirects are one of the OWASP 2010 Top Ten vulnerabilities. This check looks at user-supplied input in query string parameters and POST data to identify where open redirects might be possible. Open redirects occur when an application allows user-supplied input (e.g. http://nottrusted.com) to control an offsite redirect. This is generally a pretty accurate way to find where 301 or 302 redirects could be exploited by spammers or phishing attacks.",
                        #     'solution': "To avoid the open redirect vulnerability, parameters of the application script/program must be validated before sending 302 HTTP code (redirect) to the client browser. Implement safe redirect functionality that only redirects to relative URI's, or a list of trusted domains"
                        # }
                        return {
                            'url': url,
                            'method': "GET",
                            "parameter": "",
                            "attack": "",
                            "evidence": self.evidence[0]
                        }


def scan(url):
    scanner = UserControlledOpenRedirectScanRule()
    return scanner.scan_http_response(url)


# example usage returns none for nsi.isaix.com
# print(scan('http://nsi.isaix.com'))