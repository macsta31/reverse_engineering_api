import unittest
from unittest.mock import Mock
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs
from userControlledJavascriptEvent import UserControlledJavascriptEventScanRule


class UserControlledJavascriptEventScanRuleTest(unittest.TestCase):
    def setUp(self):
        self.scanner = UserControlledJavascriptEventScanRule()

    def test_scan_http_response_receive(self):
        html_content = """
        <html>
            <body>
                <h1>Test HTML</h1>
                <form>
                    <input type="text" name="username" value="">
                    <input type="password" name="password" value="">
                    <select name="country">
                        <option value="us">United States</option>
                        <option value="uk">United Kingdom</option>
                    </select>
                    <button onclick="alert('Button clicked!')">Click Me</button>
                    <a href="#" onclick="javascript:alert('Link clicked!')">Click Me</a>
                    <button onclick="javascript:alert(us)">Get Username</button>
                </form>
                <input type="text" id="username" value="">
            </body>
        </html>

        """

        response = Mock()
        response.status_code = 200
        response.headers = {"Content-Type": "text/html"}
        response.content = html_content.encode("utf-8")
        response.url = "https://example.com/?username=test&password=123"

        parsed_url = urlparse(response.url)
        query_params = parse_qs(parsed_url.query)

        soup = BeautifulSoup(html_content, "html.parser")
        # self.scanner.scan_http_response_receive(response, soup)
        # print(self.scanner.scan_http_response_receive(response, soup))
        print(self.scanner.scan_http_response_receive(response, soup))
        self.assertEqual(self.scanner.scan_http_response_receive(response, soup),
                     "CWE-200: Improper Input Validation")

if __name__ == "__main__":
    unittest.main()
