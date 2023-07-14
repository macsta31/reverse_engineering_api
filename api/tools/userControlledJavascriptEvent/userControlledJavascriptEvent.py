import re
from urllib.parse import urlparse, parse_qs

from bs4 import BeautifulSoup
import requests


class UserControlledJavascriptEventScanRule():
    JAVASCRIPT_EVENTS = [
        "onabort",
        "onbeforeunload",
        # List of JavaScript events to check
        # ...
        "onunload"
    ]

    def __init__(self):
        self.method = None
        self.url = None

    def get_name(self):
        return self._get_message(self.MESSAGE_PREFIX + "name")
    
    def get_form_params(self, html):
        # Extract form parameters from HTML
        soup = html

        params = set()

        forms = soup.find_all('form')
        for form in forms:
            inputs = form.find_all('input')
            for input_tag in inputs:
                name = input_tag.get('name')
                value = input_tag.get('value')
                if name:
                    params.add((name, value))

            selects = form.find_all('select')
            for select in selects:
                name = select.get('name')
                options = select.find_all('option')
                for option in options:
                    value = option.get('value')
                    if name and value:
                        params.add((name, value))

        return params
    
    def get_url_params(self, msg):
        # Extract query parameters from the URL
        parsed_url = urlparse(msg.url)

        # Get the query parameters as a dictionary
        params = parse_qs(parsed_url.query)
        return params

    def scan_http_response_receive(self, msg: requests.Response, source: BeautifulSoup, url):
        if not msg.status_code == 200:
            return

        if not self._is_response_html(msg):
            return

        params = set(self.get_form_params(source)) | set(self.get_url_params(msg))
        if not params:
            return
        evidence = []
        soup = source
        html_elements = soup.find_all()
        for html_element in html_elements:
            attributes = html_element.attrs
            if attributes is None:
                continue

            for attribute in attributes:
                if attribute.lower() in self.JAVASCRIPT_EVENTS:
                    for param in params:
                        if param:
                            out = self._check_javascript_event(msg, id, html_element, attribute, param)
                            if out:
                                evidence.append(out)
        # print(evidence)
        if len(evidence) != 0:
            # return {
            #     'cwe': 'CWE-20: Improper Input Validation',
            #     'evidence': self.evidence,
            #     'title': "User Controllable JavaScript Event (XSS)",
            #     'risk': '',
            #     'summary': "This check looks at user-supplied input in query string parameters and POST data to identify where certain HTML attribute values might be controlled. This provides hot-spot detection for XSS (cross-site scripting) that will require further review by a security analyst to determine exploitability.",
            #     'solution': "Validate all input and sanitize output it before writing to any Javascript on* events."
            # }
            return {
                'url': url,
                'method': "GET",
                "parameter": "",
                "attack": "",
                "evidence": self.evidence[0]
            }

    def _check_javascript_event(self, msg, id, html_element, attribute, param):
        evidence = []
        attribute_value = html_element.get(attribute)
        if attribute_value is None:
            return

        split = re.split(r"[;=,:]", attribute_value)
        if isinstance(param, str):  # If param is a string
            for s in split:
                if param != '':
                    if s and param:
                        if param.lower() in s.lower():
                            evidence.append({param.lower(), s.lower()})
        elif isinstance(param, tuple):  # If param is a tuple of strings
            for p in param:
                if p != '':
                    for s in split:
                        if s and p:
                            if p.lower() in s.lower():
                                evidence.append({p.lower(), s.lower()})
        
        # If the loop completes without returning, no CWE is found
        return evidence

    def _is_response_html(self, message):
        content_type = message.headers.get("Content-Type", '')
        if content_type is None:
            return False

        return "text/html" in content_type or "application/xhtml+xml" in content_type or "application/xhtml" in content_type


def scan(url, html):
    scanner = UserControlledJavascriptEventScanRule()
    msg = requests.get(url)
    soup = BeautifulSoup(html, 'html.parser')
    return scanner.scan_http_response_receive(msg, soup, url)


# example usage returns none for nsi.isaix.com
# print(scan('http://nsi.isaix.com', requests.get('http://nsi.isaix.com').content))
