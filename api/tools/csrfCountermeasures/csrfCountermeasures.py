from html.parser import HTMLParser
from typing import List
from bs4 import BeautifulSoup
import requests
import sys
import os

# Add the parent directory to the PYTHONPATH
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from csrf_token_names import CSRF_TOKEN_NAMES

class MyHTMLParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms = []  # List to store form attributes
        self.inputs = []  # List to store input attributes
        self.in_form = False
        self.evidence = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form":
            self.in_form = True
            self.forms.append(attrs)
            self.inputs.append([])

        if tag == "input" and self.in_form:
            self.inputs[-1].append(attrs)

    def handle_endtag(self, tag):
        if tag == "form":
            self.in_form = False
# This checks if any known anti csrf token names are present in the forms on the webpage
class CSRFCoutermeasures():
    def __init__(self):
        self.evidence = []

    def csrf_protection_vulnerability_check(self, html: str, url, csrf_token_keywords: list, ignore_list: list) -> None:
        soup = BeautifulSoup(html, 'html.parser')

        forms = soup.find_all('form')

        for form in forms:
            form_id = form.get('id', '')
            form_name = form.get('name', '')

            # Check if form is in the ignore_list
            if form_id in ignore_list or form_name in ignore_list:
                continue

            # Check if form has a parent (in BeautifulSoup, a form without a parent would be a direct child of the soup object)
            if form.parent == soup:
                continue

            inputs = form.find_all('input')

            input_names = [input.get('name', '') for input in inputs]
            input_ids = [input.get('id', '') for input in inputs]

            # Check each input field for anti-CSRF tokens
            found_anti_csrf_tokens = [name for name in input_names + input_ids if name in csrf_token_keywords]

            if found_anti_csrf_tokens:
                print(f"Anti-CSRF tokens found in form {form_id or form_name}: {found_anti_csrf_tokens}")
            else:
                self.evidence.append(f"Potential CSRF vulnerability found in form {form_id or form_name}. No known anti-CSRF tokens found.")
                # print(f"Potential CSRF vulnerability found in form {form_id or form_name}. No known anti-CSRF tokens found.")

        if self.evidence:
            # return {
            #     'cwe': "CWE-352: Cross-Site Request Forgery (CSRF)",
            #     'evidence': self.evidence,
            #     'title': 'Absence of Anti-CSRF Tokens',
            #     'risk': '',
            #     'summary': "A cross-site request forgery is an attack that involves forcing a victim to send an HTTP request to a target destination without their knowledge or intent in order to perform an action as the victim. The underlying cause is application functionality using predictable URL/form actions in a repeatable way. The nature of the attack is that CSRF exploits the trust that a web site has for a user. By contrast, cross-site scripting (XSS) exploits the trust that a user has for a web site. Like XSS, CSRF attacks are not necessarily cross-site, but they can be. Cross-site request forgery is also known as CSRF, XSRF, one-click attack, session riding, confused deputy, and sea surf.CSRF attacks are effective in a number of situations, including: * The victim has an active session on the target site. * The victim is authenticated via HTTP auth on the target site. * The victim is on the same local network as the target site.CSRF has primarily been used to perform an action against a target site using the victim’s privileges, but recent techniques have been discovered to disclose information by gaining access to the response. The risk of information disclosure is dramatically increased when the target site is vulnerable to XSS, because XSS can be used as a platform for CSRF, allowing the attack to operate within the bounds of the same-origin policy.",
            #     "solution": "Phase: Architecture and Design Use a vetted library or framework that does not allow this weakness to occur or provides constructs that make this weakness easier to avoid. For example, use anti-CSRF packages such as the OWASP CSRFGuard. Phase: Implementation Ensure that your application is free of cross-site scripting issues, because most CSRF defenses can be bypassed using attacker-controlled script. Phase: Architecture and Design Generate a unique nonce for each form, place the nonce into the form, and verify the nonce upon receipt of the form. Be sure that the nonce is not predictable (CWE-330). Note that this can be bypassed using XSS. Identify especially dangerous operations. When the user performs a dangerous operation, send a separate confirmation request to ensure that the user intended to perform that operation. Note that this can be bypassed using XSS. Use the ESAPI Session Management control. This control includes a component for CSRF. Do not use the GET method for any request that triggers a state change. Phase: Implementation Check the HTTP Referer header to see if the request originated from an expected page. This could break legitimate functionality, because users or proxies may have disabled sending the Referer for privacy reasons."
            # }
            return {
                'url': url,
                'method': "GET",
                "parameter": "",
                "attack": "",
                "evidence": self.evidence[0]
            }


def csrfVulnCheck(html, url):
    # Call the CSRF vulnerability check function
    scanner = CSRFCoutermeasures()
    return scanner.csrf_protection_vulnerability_check(html, url, CSRF_TOKEN_NAMES, ['ignore'])
    
# example usage should return cwe-352 for nsi.isaix.com, app.py utilizes selenium for js created websites
# print(csrfVulnCheck(requests.get('http://nsi.isaix.com').content))
