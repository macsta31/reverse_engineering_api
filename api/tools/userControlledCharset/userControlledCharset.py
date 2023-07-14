import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs

class UserControlledCharsetScanRule:

    def __init__(self):
        self.evidence = []
    def scanHttpResponseReceive(self, msg, url):
        # Check if the response status code is 200 (OK)
        if msg.status_code != 200:
            return

        responseBody = msg.text
        # Check if the response body exists
        if not responseBody:
            return

        parsed_url = urlparse(msg.url)
        params = parse_qs(parsed_url.query)
        # Check if there are query parameters in the URL
        if not params:
            return

        soup = BeautifulSoup(responseBody, 'html.parser')

        # Check if the response is HTML
        if self.isResponseHTML(msg.headers):
            # Check the meta tags for charset information
            self.checkMetaContentCharset(msg, soup)

        # Check the Content-Type charset information
        self.checkContentTypeCharset(msg, id, params)
        if self.evidence:
            # return {
            #     'cwe': 'CWE-20: Improper Input Validation',
            #     'evidence': self.evidence,
            #     'title': "User Controllable Charset",
            #     'risk': '',
            #     'summary': "This check looks at user-supplied input in query string parameters and POST data to identify where Content-Type or meta tag charset declarations might be user-controlled. Such charset declarations should always be declared by the application. If an attacker can control the response charset, they could manipulate the HTML to perform XSS or other attacks. For example, an attacker controlling the element charset value is able to declare UTF-7 and is also able to include enough user-controlled payload early in the HTML document to have it interpreted as UTF-7. By encoding their payload with UTF-7 the attacker is able to bypass any server-side XSS protections and embed script in the page.",
            #     'solution': "Force UTF-8 in all charset declarations. If user-input is required to decide a charset declaration, ensure that only an allowed list is used."
            # }
            return {
                'url': url,
                'method': "GET",
                "parameter": "",
                "attack": "",
                "evidence": self.evidence[0]
            }

    def checkMetaContentCharset(self, msg, soup):
        parsed_url = urlparse(msg.url)
        params = parse_qs(parsed_url.query)
        metaElements = soup.find_all('meta')
        # Check if there are meta tags in the HTML
        if not metaElements:
            return

        for metaElement in metaElements:
            httpEquiv = metaElement.get('http-equiv')
            bodyContentType = metaElement.get('content')

            # Check if the meta tag represents the Content-Type
            if not httpEquiv or not bodyContentType or httpEquiv.lower() != 'content-type':
                continue

            bodyContentCharset = self.getBodyContentCharset(bodyContentType)
            if not bodyContentCharset:
                continue

            for param in params:
                if bodyContentCharset.lower() == param.lower():
                    self.evidence.append(param)
                    # return "CWE-20: Improper Input Validation"

    def getBodyContentCharset(self, bodyContentType):
        charset = None
        bodyContentType = bodyContentType.strip()

        if 'charset=' in bodyContentType:
            charset = bodyContentType.split('charset=')[-1]

        return charset

    def checkContentTypeCharset(self, msg, id, params):
        charset = msg.headers.get('Content-Type', '').split('charset=')[-1].strip()
        # Check if the Content-Type header contains a charset
        if not charset:
            return

        for param in params:
            if charset.lower() == param.lower():
                self.evidence.append(param)
                # return "CWE-20: Improper Input Validation"

    def isResponseHTML(self, headers):
        contentType = headers.get("Content-Type", "")
        # Check if the Content-Type indicates HTML content
        return 'text/html' in contentType.lower() or 'application/xhtml+xml' in contentType.lower() or 'application/xhtml' in contentType.lower()

def scan(url, html):
    parsed_url = urlparse(url)
    params = parse_qs(parsed_url.query)
    msg = requests.get(url)
    soup = BeautifulSoup(html, 'html.parser')
    scanner = UserControlledCharsetScanRule()
    return scanner.scanHttpResponseReceive(msg, url)


# example usage returns none for nsi.isaix.com
# print(scan('http://nsi.isaix.com', requests.get('http://nsi.isaix.com').content))


