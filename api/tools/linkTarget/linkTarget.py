import requests
from bs4 import BeautifulSoup

class LinkTarget:

    def __init__(self):
        self.trusted_domains = []
    

    def isLinkFromOtherDomain(host, link, context_list):
        if link is None or (not link.startswith("//") and (link.startswith("/") or link.startswith("./") or link.startswith("../"))):
            return False
        other_domain = False
        try:
            link_host = link.split('/')
            if link_host and link_host.lower() != host.lower():
                other_domain = True
            if other_domain:
                pass
        except ValueError:
            pass
        return other_domain and not trusted_domains_included(link)


    def scan_http_response_receive(self, msg:requests.Response, html, url):
        if 'text/html' not in msg.headers['content-type']:
            return
        
        soup = BeautifulSoup(html, 'html.parser')
        anchors = soup.find_all('a')
        areas = soup.find_all('area')

        elements = anchors.append(areas)

        for element in elements:
            if (self.isLinkFromOtherDomain(msg.url, element.get('href') and self.checkElement(element))):
                return

        
