import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs

class UserControlledHTMLAttributesScanRule:

    def scanHttpResponseReceive(self, msg, url):
        # Check if the response is a successful HTML response
        if msg.status_code != 200 or not self.isResponseHTML(msg.headers):
            return

        # Parse the HTML content using BeautifulSoup
        soup = BeautifulSoup(msg.text, 'html.parser')
        htmlElements = soup.find_all()
        if not htmlElements:
            return

        parsed_url = urlparse(msg.url)

        # Get the query parameters as a dictionary
        params = parse_qs(parsed_url.query)
        if not params:
            return

        evidence = []
        self.checkHtmlElements(msg, params, htmlElements, evidence)

        if evidence:
            # return {
            #     'cwe': 'CWE-20: Improper Input Validation',
            #     'evidence': self.evidence,
            #     'title': "User Controllable HTML Element Attribute (Potential XSS)",
            #     'risk': '',
            #     'summary': "This check looks at user-supplied input in query string parameters and POST data to identify where certain HTML attribute values might be controlled. This provides hot-spot detection for XSS (cross-site scripting) that will require further review by a security analyst to determine exploitability.",
            #     'solution': "Validate all input and sanitize output it before writing to any HTML attributes."
            # }
            return {
                'url': url,
                'method': "GET",
                "parameter": "",
                "attack": "",
                "evidence": self.evidence[0]
            }

    def checkHtmlElements(self, msg, params, htmlElements, evidence):
        for element in htmlElements:
            self.checkHtmlElement(msg, params, element, evidence)

    def checkHtmlElement(self, msg, params, htmlElement, evidence):
        attributes = htmlElement.attrs
        if not attributes:
            return

        for attributeName, attributeValue in attributes.items():
            self.checkHtmlAttribute(msg, params, htmlElement, attributeName, attributeValue, evidence)

    def checkHtmlAttribute(self, msg, params, htmlElement, attributeName, attributeValue, evidence):
        if not attributeValue:
            return

        if isinstance(attributeValue, list):
            for value in attributeValue:
                self.checkSingleHtmlAttribute(msg, params, htmlElement, attributeName, value.lower(), evidence)
        else:
            self.checkSingleHtmlAttribute(msg, params, htmlElement, attributeName, attributeValue.lower(), evidence)

    def checkSingleHtmlAttribute(self, msg, params, htmlElement, attributeName, attributeValue, evidence):
        if htmlElement.name.lower() == "meta" and attributeName.lower() == "content":
            if attributeValue.strip().startswith("url="):
                attributeValue = attributeValue[4:].strip()

        if not attributeValue:
            return {}

        protocol, domain, token = None, None, None

        if "://" in attributeValue:
            try:
                url = requests.utils.urlparse(attributeValue)
                protocol = url.scheme
                domain = url.netloc
                token = url.query.split('&')[0].split('=')[1]
                if '/' in token:
                    token = token[:token.index('/')]
            except Exception:
                return {}

        for param in params:
            if not param:
                return {}

            paramValue = param.lower()

            if htmlElement.name.lower() == "meta" and attributeName.lower() == "content":
                if "charset" in attributeValue:
                    continue

                for value in attributeValue.split(";=,"):
                    if value.strip() == paramValue:
                        evidence.append({paramValue, attributeValue})

            if len(paramValue) > 1:
                if attributeValue.startswith(paramValue) or \
                paramValue == protocol or \
                paramValue == domain or \
                paramValue == token or \
                (":" in attributeValue and attributeValue.startswith(paramValue)):
                    evidence.append({paramValue, attributeValue})

    def isResponseHTML(self, headers):
        contentType = headers.get("Content-Type", "")
        return 'text/html' in contentType.lower() or \
               'application/xhtml+xml' in contentType.lower() or \
               'application/xhtml' in contentType.lower()

def scan(url):
    scanner = UserControlledHTMLAttributesScanRule()
    return scanner.scanHttpResponseReceive(requests.get(url), url)


# example usage returns none for nsi.isaix.com
# print(scan('http://nsi.isaix.com'))