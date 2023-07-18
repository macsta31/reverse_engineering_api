import re
import requests
from bs4 import BeautifulSoup, Comment
from collections import defaultdict

class InformationDisclosureSuspiciousCommentsScanRule:

    def __init__(self):
        self.plugin_id = 10027
        self.DEFAULT_PAYLOADS = [
            "TODO", "FIXME", "BUG", "BUGS", "XXX", "QUERY", "DB",
            "ADMIN", "ADMINISTRATOR", "USER", "USERNAME", "SELECT",
            "WHERE", "FROM", "LATER", "DEBUG"]
        self.patterns = self.init_patterns()
        self.evidence = []

    def init_patterns(self):
        target_patterns = []
        for payload in self.DEFAULT_PAYLOADS:
            target_patterns.append(re.compile(r"\b" + payload + r"\b", re.IGNORECASE))
        return target_patterns
    
    def find_comments(self, js_code):
        pattern = r'//.*?$|/\*.*?\*/|\'(?:\\.|[^\\\'])*\'|"(?:\\.|[^\\"])*"'
        matches = re.findall(pattern, js_code, re.MULTILINE|re.DOTALL)
        return matches



    def scan_http_response_receive(self, url):
        try:
            response = requests.get(url)
            soup = BeautifulSoup(response.text, 'html.parser')

            alert_map = defaultdict(list)

            if response.text:
                # print(response.text)
                # Check the comments
                comments = self.find_comments(response.text)
                for comment in comments:
                    for pattern in self.patterns:
                        match = pattern.search(comment)
                        if match:
                            self.evidence.append(match.group())
                            break  # Only need to record this comment once

                # Check the scripts
                scripts = soup.find_all('script')
                for script in scripts:
                    for pattern in self.patterns:
                        match = pattern.search(str(script))
                        if match:
                            self.evidence.append(match.group())
                            break  # Only need to record this script once


            if self.evidence:
                # return {
                #     'cwe': "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor",
                #     'evidence': self.evidence,
                #     'title': 'Information Disclosure - Suspicious Comments',
                #     'risk': 'Informational',
                #     'summary': "The response appears to contain suspicious comments which may help an attacker. Note: Matches made within script blocks or files are against the entire content not only comments.",
                #     "solution": "Remove all comments that return information that may help an attacker and fix any underlying problems they refer to."
                # }   
                return {
                'url': url,
                'method': "GET",
                "parameter": "",
                "attack": "",
                "evidence": self.evidence[0]
            }
            else: return None

        except Exception as e:
            print(f"An error occurred while checking if a URL has suspicious comments: {e}")
            

def hasSusComment(url):
    scanner = InformationDisclosureSuspiciousCommentsScanRule()
    return scanner.scan_http_response_receive(url)

# print(hasSusComment('http://nsi.isaix.com'))