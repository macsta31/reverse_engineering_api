import requests
import re


class HeartBleedScan:
    # This checks if the server is vulnerable to the heartbleed issue

    def __init__(self):
        # List of vulnerable OpenSSL versions
        self.openSSLvulnerableVersions = [
            "1.0.1-Beta1",
            "1.0.1-Beta2",
            "1.0.1-Beta3",
            "1.0.1",
            "1.0.1a",
            "1.0.1b",
            "1.0.1c",
            "1.0.1d",
            "1.0.1e",
            "1.0.1f",
            "1.0.2-beta"
        ]

        self.evidence = []

        # Regular expression to identify OpenSSL version in server header
        self.openSSLversionPattern = re.compile("Server:.*?(OpenSSL/([0-9.]+[a-z-0-9]+))", re.IGNORECASE)

    def scan_http_response(self, msg, url):
        """
        Scans the HTTP response for signatures that might indicate the Heartbleed OpenSSL vulnerability.
        """
        responseHeaders = msg.headers

        matcher = self.openSSLversionPattern.search(str(responseHeaders))
        while matcher:
            fullVersionString = matcher.group(1)  # Get the full string e.g. OpenSSL/1.0.1e
            versionNumber = matcher.group(2)  # Get the version e.g. 1.0.1e

            # If the version matches any of the known vulnerable versions, raise an alert.
            for openSSLvulnerableVersion in self.openSSLvulnerableVersions:
                if versionNumber.lower() == openSSLvulnerableVersion.lower():
                    self.evidence.append(fullVersionString)
                    # return self.raise_alert(msg, fullVersionString)
            matcher = self.openSSLversionPattern.search(str(responseHeaders), matcher.end())
        if self.evidence:
            # return {
            #     'cwe': "CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer",
            #     'evidence': self.evidence,
            #     'title': 'Heartbleed OpenSSL Vulnerability',
            #     'risk': 'High',
            #     'summary': "The TLS implementation in OpenSSL 1.0.1 before 1.0.1g does not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information from process memory via crafted packets that trigger a buffer over-read, potentially disclosing sensitive information.",
            #     "solution": "Update to OpenSSL 1.0.1g or later. Re-issue HTTPS certificates. Change asymmetric private keys and shared secret keys, since these may have been compromised, with no evidence of compromise in the server log files."
            # }
            return {
                'url': url,
                'method': "GET",
                "parameter": "",
                "attack": "",
                "evidence": self.evidence[0]
            }

        

    def raise_alert(self, msg, fullVersionString):
        """
        Function to raise an alert for the Heartbleed vulnerability
        """
        # You can customize this function to handle the alert as per your requirements
        # For now, it returns the CVE number as a string
        return "CVE-2014-0160"

    def send_request(self, url):
        """
        Sends a GET request to the provided URL and scans the response
        """
        response = requests.get(url)
        return self.scan_http_response(response, url)

def checkHeartBleed(url):
        """
        Function to check for the Heartbleed vulnerability in the given URL
        """
        scanner = HeartBleedScan()
        return scanner.send_request(url)

# Example usage: should return None for nsi.isaix.com
# print(checkHeartBleed('http://nsi.isaix.com'))
