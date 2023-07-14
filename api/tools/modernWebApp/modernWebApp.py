from bs4 import BeautifulSoup
import requests

class ModernWebAppScanner:
    # This checks if the webpage shows signs of being a modern web app
    # This includes evidence of using a javascript framework and single page web app characteristics like '#' in links
    def __init__(self):
        self.evidence = []

    def check_modern_web_app(self, soup, url):
        evidence = []
        other_info = []

        # Find all anchor tags in the HTML soup
        links = soup.find_all('a')

        if len(links) == 0:
            # If no links are found, check for script tags
            scripts = soup.find_all('script')
            if len(scripts) > 0:

                self.evidence.append(str(scripts[0]))
                other_info = 'No links found, but scripts present.'
        else:
            # Check each link for specific conditions
            for link in links:
                href = link.get('href')
                if href is None or len(href) == 0 or href == '#':

                    self.evidence.append(str(link))
                    other_info.append('Links with no href found.')
                    break
                target = link.get('target')
                if target is not None and target == '_self':

                    self.evidence.append(str(link))
                    other_info.append('Links with target _self found.')
                    break

        if evidence is None:
            no_script = soup.find('noscript')
            if no_script is not None:
                # Indication that the app works differently without JavaScript

                self.evidence.append(str(no_script))
                other_info.append('No script tag found.')


        if self.evidence is not None and len(self.evidence) > 0:
            # If evidence is found, it indicates a modern web app
            # return {
            #     'cwe': '',
            #     'evidence': self.evidence,
            #     'title': 'Modern Web Application',
            #     'risk': 'Informational',
            #     'summary': "The application appears to be a modern web application. If you need to explore it automatically then the Ajax Spider may well be more effective than the standard one.",
            #     'solution': "This is an informational alert and so no changes are required."
            # }
            return {
                'url': url,
                'method': "GET",
                "parameter": "",
                "attack": "",
                "evidence": self.evidence[0]
            }

def scan(html, url):
    # Parse the HTML content using BeautifulSoup
    input = BeautifulSoup(html, 'html.parser')  # Specify the parser here

    # Create an instance of ModernWebAppScanner
    scanner = ModernWebAppScanner()

    # Check for modern web app indicators in the HTML soup
    return scanner.check_modern_web_app(input, url)

# Example usage: return modern web app for nsi.isaix.com and basically all others because everything is a mwa these days
# html = requests.get('http://nsi.isaix.com').text  # Fetch the HTML content from the URL
# print(scan(html))
