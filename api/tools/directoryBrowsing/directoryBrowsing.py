import re
import requests
from typing import Optional, Tuple

class DirectoryBrowsingScanRule:
    # This checks if directory browsing is enabled on the webpage through a link that navigates to a parent directory of the current application
    def __init__(self):
        self.evidence = []

    server_patterns = {
        re.compile("<title>Index of /[^<]+?</title>", re.MULTILINE | re.DOTALL): "Apache 2",
        re.compile("<pre>.*<a href=\"/[^>]*\">\\[To Parent Directory\\]</a>.*</pre>", re.MULTILINE | re.DOTALL): "Microsoft IIS",
    }
    cwe_id = 'CWE-548: Information Exposure Through Directory Listing'

    def scan_http_response(self, response_body: str, url) -> Optional[str]:
        for pattern, server in self.server_patterns.items():
            if pattern.search(response_body):
                self.evidence.append(response_body)
        
        if self.evidence:
            # return {
            #     'cwe': "CWE-548: Exposure of Information Through Directory Listing",
            #     'evidence': self.evidence,
            #     'title': 'Directory Browsing',
            #     'risk': 'Medium',
            #     'summary': "It is possible to view the directory listing. Directory listing may reveal hidden scripts, include files, backup source files, etc. which can be accessed to read sensitive information.",
            #     "solution": "Disable directory browsing. If this is required, make sure the listed files does not induce risks."
            # }
            return {
                'url': url,
                'method': "GET",
                "parameter": "",
                "attack": "",
                "evidence": self.evidence[0]
            }

# usage
def hasDirectoryBrowsing(html, url):
    scanner = DirectoryBrowsingScanRule()
    response_body = html  # the HTTP response body as a string
    return scanner.scan_http_response(response_body, url)
    

# view app.py for usage
    

