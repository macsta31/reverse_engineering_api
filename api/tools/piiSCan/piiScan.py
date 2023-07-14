import re
from bs4 import BeautifulSoup
from typing import List, Dict
from luhn import verify
import requests

# This checks if any credit card information is leaked on the webpage using common regular expressions to match with providers and the luhn (MOD 10) algorithm to verify authenticity of numbers

class PiiScan:

    def __init__(self):
        self.evidence = []
        # Credit Card Regex patterns
        self.CREDIT_CARDS = {
            'AMERICAN_EXPRESS': r'\b(?:3[47][0-9]{13})\b',
            'DINERSCLUB': r'\b(?:3(?:0[0-5]|[68][0-9])[0-9]{11})\b',
            'DISCOVER': r'\b(?:6(?:011|5[0-9]{2})(?:[0-9]{12}))\b',
            'JCB': r'\b(?:(?:2131|1800|35\d{3})\d{11})\b',
            'MAESTRO': r'\b(?:(?:5[0678]\d\d|6304|6390|67\d\d)\d{8,15})\b',
            'MASTERCARD': r'\b(?:(?:5[1-5][0-9]{2}|222[1-9]|22[3-9][0-9]|2[3-6][0-9]{2}|27[01][0-9]|2720)[0-9]{12})\b',
            'VISA': r'\b(?:4[0-9]{12})(?:[0-9]{3})?\b'
        }

    class Candidate:
        def __init__(self, original, candidate, containing_string):
            self.original = original
            self.candidate = candidate
            self.containing_string = containing_string

    def scan_http_response_receive(self, msg, url):

        # Check if the URL is using HTTPS
        # if not msg.url.startswith('https'):
        #     return []

        # Check if the response is HTML
        if 'text/html' not in msg.headers.get('Content-Type', ''):
            return None

        html_content = msg.content
        soup = BeautifulSoup(html_content, 'html.parser')
        # print(soup.text)
        # Find number sequences in the text
        candidates = self.get_number_sequences(soup.text)
        # print(candidates[0].containing_string, candidates[0].candidate, candidates[0].original)

        for candidate in candidates:
            for cc in self.CREDIT_CARDS:
                matcher = re.search(self.CREDIT_CARDS[cc], candidate.candidate)
                if matcher:
                    # print(candidate.containing_string)
                    if self.is_decimal(candidate.containing_string) or self.is_sci(candidate.containing_string):
                        continue
                    # print('before verify')
                    # print(candidate.candidate)
                    if verify(candidate.candidate):
                        # print('verified')
                        self.evidence.append(f'Potential PII detected: {candidate.original}, credit card type: {cc}')
        if self.evidence:
            # return {
            #     'cwe': 'CWE-359: Exposure of Private Personal Information to an Unauthorized Actor',
            #     'evidence': self.evidence,
            #     'title': 'PII Disclosure',
            #     'risk': 'High',
            #     'summary': "The response contains Personally Identifiable Information, such as CC number, SSN and similar sensitive data.",
            #     'solution': "Check the response for the potential presence of personally identifiable information (PII), ensure nothing sensitive is leaked by the application."
            # }
            return {
                'url': url,
                'method': "GET",
                "parameter": "",
                "attack": "",
                "evidence": self.evidence[0]
            }
        else: return None


    def is_sci(self, containing_string):
        return 'e' in containing_string.lower()


    def is_decimal(self, containing_string):
        return '.' in containing_string

    def get_number_sequences(self, input_string: str, min_sequence: int = 3) -> List[Candidate]:
        regex_string = r"(?:\d{%d,}\s*)+" % min_sequence
        matches = re.finditer(regex_string, input_string)
        result = []
        for match in matches:
            original = match.group()
            candidate = re.sub(r'\s+', '', original)
            raw_containing_string = input_string[max(match.start()-3, 0):min(match.end()+3, len(input_string))]
            match_in_context = re.search(regex_string, raw_containing_string)
            containing_string = match_in_context.group() if match_in_context else ""
            result.append(self.Candidate(original.strip(), candidate.strip(), containing_string.strip()))
        return result



def scan(url):
    res = PiiScan().scan_http_response_receive(requests.get(url), url)
    return res


# example usage: returns none for nsi.isaix.com
# print(scan('http://nsi.isaix.com'))