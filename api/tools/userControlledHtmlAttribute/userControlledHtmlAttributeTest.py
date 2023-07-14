import unittest
from unittest.mock import Mock
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs
from userControlledHtmlAttribute import UserControlledHTMLAttributesScanRule


class UserControlledHTMLAttributesScanRuleTest(unittest.TestCase):
    def setUp(self):
        self.scanner = UserControlledHTMLAttributesScanRule()

    def test_scan_http_response_receive(self):
        html_content = """
        <html>
            <body>
                <h1>Test HTML</h1>
                <div data-attribute="CWE-20: Improper Input Validation">Hello, World!</div>
                <div href="javascript:alert('XSS')">Click Me</div>
                <meta content="url=CWE-20: Improper Input Validation" name="description">
            </body>
        </html>
        """

        response = Mock()
        response.status_code = 200
        response.headers = {"Content-Type": "text/html"}
        response.text = html_content
        response.url = "https://example.com/?param=test"

        parsed_url = urlparse(response.url)
        query_params = parse_qs(parsed_url.query)

        # soup = BeautifulSoup(html_content, "html.parser", from_encoding="utf-8")
        print(self.scanner.scanHttpResponseReceive(response))
        self.assertEqual(self.scanner.scanHttpResponseReceive(response), "CWE-20: Improper Input Validation")

        # Perform additional assertions based on the expected behavior of the scanner

if __name__ == "__main__":
    unittest.main()
