import requests
from bs4 import BeautifulSoup

class AntiClickjackingScan:

    # Checks if all anti clickjacking headers are properly set
    # This includes CSP, X-Frame-Option and meta elements

    def __init__(self, url):

        evidence = []
        self.included_in_csp = False
        self.url = url
        self.evidence = []

    def scan(self):
        # get response header from request object
        response = requests.get(self.url)
        noAntiClickjacking = 0

        # get CSP and X-Frame-Options headers from headers
        csp = response.headers.get("Content-Security-Policy", "")
        x_frame_option = response.headers.get("X-Frame-Option", "")

        # if frame-ancestors policy set, update variable
        self.included_in_csp = "frame-ancestors" in csp
        # if not self.included_in_csp: 
        #     if(len(x_frame_option) != 1):
        #         return 0


        # if frame-ancestors and no x-frame-options and "deny" or "same origin" policy set, return error
        if not self.included_in_csp:
            if not x_frame_option:
                self.evidence.append('absence of x-frame-option header')

            elif not any(option in x_frame_option.lower() for option in ["deny", "sameorigin"]):
                self.evidence.append(x_frame_option.lower())

        # if meta tag with http-equiv attribute set with x-frame-options return error
        soup = BeautifulSoup(response.content, 'html.parser')
        for meta in soup.find_all('meta'):
            if 'http-equiv' in meta.attrs and meta['http-equiv'].lower() == 'x-frame-options':
                self.evidence.append(meta)
        
        # Else anticlickjacking is set properly
        hasAntiClickjacking = 1
        if hasAntiClickjacking:
            # return {
            #     'cwe': 'CWE-1021: Improper Restriction of Rendered UI Layers or Frames',
            #     'evidence': self.evidence,
            #     'title': 'Missing Anti ClickJacking Header',
            #     'risk': 'Medium',
            #     'summary': "The response does not include either Content-Security-Policy with ‘frame-ancestors’ directive or X-Frame-Options to protect against ‘ClickJacking’ attacks.",
            #     'solution': "Modern Web browsers support the Content-Security-Policy and X-Frame-Options HTTP headers. Ensure one of them is set on all web pages returned by your site/app. If you expect the page to be framed only by pages on your server (e.g. it's part of a FRAMESET) then you'll want to use SAMEORIGIN, otherwise if you never expect the page to be framed, you should use DENY. Alternatively consider implementing Content Security Policy's 'frame-ancestors' directive."
            # }
            return {
                'url': self.url,
                'method': "GET",
                "parameter": "",
                "attack": "",
                "evidence": self.evidence[0]
            }


# scan = AntiClickjackingScan('http://nsi.isaix.com').scan()


def isVulner(url):
    scan = AntiClickjackingScan(url).scan()
    return scan
    
# uncomment to run test should return cwe-1021 for nsi.isaix.com
# print(isVulner('https://twmgroup.ca'))