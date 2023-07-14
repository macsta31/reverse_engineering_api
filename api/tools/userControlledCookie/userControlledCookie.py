import requests
from collections import OrderedDict
from urllib.parse import urlparse, parse_qs

class UserControlledCookieScanRule:

    def __init__(self):
        self.evidence = []


    def scanHttpResponseReceive(self, msg, url):
        cookies = msg.cookies
        # Check if cookies are present in the response
        if not cookies:
            return None

        parsed_url = urlparse(msg.url)

        # Get the query parameters as a dictionary
        params = parse_qs(parsed_url.query)
        # Check if there are query parameters in the URL
        if not params:
            return None

        for cookie in cookies:
            # Decode the cookie value based on the content type
            cookie = self.decodeCookie(cookie, msg.headers.get("Content-Type"))
            if not cookie:
                continue

            cookieSplit = cookie.split(";")
            for cookiePart in cookieSplit:
                # Check if the cookie value matches any of the query parameters
                self.checkUserControllableCookieHeaderValue(msg, params, cookiePart, cookie)

        if self.evidence:
            # return {
            #     'cwe': 'CWE-20: Improper Input Validation',
            #     'evidence': self.evidence,
            #     'title': "Cookie Poisoning",
            #     'risk': '',
            #     'summary': "This check looks at user-supplied input in query string parameters and POST data to identify where cookie parameters might be controlled. This is called a cookie poisoning attack, and becomes exploitable when an attacker can manipulate the cookie in various ways. In some cases this will not be exploitable, however, allowing URL parameters to set cookie values is generally considered a bug.",
            #     'solution': "Do not allow user input to control cookie names and values. If some query string parameters must be set in cookie values, be sure to filter out semicolon's that can serve as name/value pair delimiters."
            # }
            return {
                'url': url,
                'method': "GET",
                "parameter": "",
                "attack": "",
                "evidence": self.evidence[0]
            }

    def decodeCookie(self, cookie, content_type):
        if content_type and "charset=" in content_type:
            charset = content_type.split("charset=")[-1]
            try:
                return requests.utils.unquote_to_bytes(cookie).decode(charset)
            except UnicodeDecodeError:
                pass

        possible_charsets = ["ISO-8859-1", "US-ASCII", "UTF-16", "UTF-16BE", "UTF-16LE", "UTF-8"]
        for charset in possible_charsets:
            try:
                return requests.utils.unquote_to_bytes(cookie).decode(charset)
            except UnicodeDecodeError:
                pass

        return None

    def checkUserControllableCookieHeaderValue(self, msg, params, cookiePart, cookie):
        if not cookiePart:
            return None

        for param in params:
            if param.value and len(param.value) > 1 and param.value == cookiePart:
                self.evidence.append(param)
                # return "CWE-20: Improper Input Validation"

def scan(url):
    scanner = UserControlledCookieScanRule()
    try:
        return scanner.scanHttpResponseReceive(requests.get(url), url)
    except Exception as e:
         return None

# example usage returns none for nsi.isaix.com
# print(scan('https://facebook.com'))