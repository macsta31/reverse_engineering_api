import requests
from bs4 import BeautifulSoup
import xml.etree.ElementTree as ET
import re 

class ApplicationErrorScanRule:
    # This checks if Application Errors are exposed to the client that may leak sensitive information about the server
    def __init__(self, app_errors_file):
        self.app_errors_file = app_errors_file
        self.load_errors()
        self.evidence = []

    def parse_xml(self, xml_file):
        # Parse the XML file using ElementTree
        tree = ET.parse(xml_file)
        root = tree.getroot()

        patterns = []

        # Extract error patterns from XML and store them as dictionaries in a list
        for child in root:
            pattern = {"type": child.attrib["type"], "value": child.text}
            patterns.append(pattern)

        return patterns

    def load_errors(self):
        # Load the application errors from the specified XML file
        self.errors = self.parse_xml(self.app_errors_file)
        

    def scan(self, url):
        # Send a GET request to the specified URL
        response = requests.get(url)

        if response.status_code == 500:
            return 0, "Internal server error"  # Indicate internal server error

        soup = BeautifulSoup(response.content, 'html.parser')
        body = str(soup.body)

        # Check for errors in the HTML body
        for error in self.errors:
            if error["type"] == "string" and error["value"] in body:
                self.evidence.append(error["value"])
                # return 1, "Error found: " + error["value"]  # Indicate error found
            elif error["type"] == "regex" and re.search(error["value"], body):
                self.evidence.append(error["value"])
                # return 1, "Error found: " + error["value"]  # Indicate error found
        if self.evidence:
            # return {
            #     'cwe': 'CWE-200: Exposure of Sensitive Information to an Unauthorized Actor',
            #     'evidence': self.evidence,
            #     'title': 'Application Error Disclosure',
            #     'risk': 'Medium',
            #     'summary': "This page contains an error/warning message that may disclose sensitive information like the location of the file that produced the unhandled exception. This information can be used to launch further attacks against the web application. The alert could be a false positive if the error message is found inside a documentation page.",
            #     'solution': "Review the source code of this page. Implement custom error pages. Consider implementing a mechanism to provide a unique error reference/identifier to the client (browser) while logging the details on the server side and not exposing them to the user."
            # }
            return {
                'url': url,
                'method': "GET",
                "parameter": "",
                "attack": "",
                "evidence": self.evidence[0]
            }


def hasApplicationError(url, appl_errors):
    # Create an instance of ApplicationErrorScanRule with the specified application errors file
    scan = ApplicationErrorScanRule(appl_errors)

    # Scan the URL for application errors
    return scan.scan(url)

# uncomment to run scan should return none on nsi.isaix.com

# print(hasApplicationError('http://nsi.isaix.com', 'backend/api/application_errors.xml'))