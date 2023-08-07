import requests
from bs4 import BeautifulSoup

class charsetMismatchScanRule:
    def __init__(self):
        pass

    def scan_http_response_receive(self, msg: requests.Response, source, url):

        if not msg.encoding:
            return
        if 'html' in msg.headers['Content-Type']:
            soup = BeautifulSoup(source, 'html.parser')
            meta_tags = soup.find_all('meta', attrs={"http-equiv": True}) + \
                        soup.find_all('meta', attrs={"content": True}) + \
                        soup.find_all('meta', attrs={"charset": True})
        
            meta_charset = None
            http_equiv = None
            for meta_tag in meta_tags:
                attrs = [ 'http-equiv', 'content', 'charset' ]
                for attr in attrs:
                    if attr in meta_tag.attrs:
                        # print(attr, meta_tag[attr])
                        if attr == 'http-equiv':
                            http_equiv = meta_tag[attr]
                        if attr == 'charset':
                            meta_charset = meta_tag[attr]


            if meta_charset and meta_charset != msg.encoding:
                return {
                    'url': url,
                    'method': "GET",
                    "parameter": "",
                    "attack": "",
                    "evidence": 'meta_charset: {}, header_charset: {}'.format(meta_charset, msg.encoding)
                }

                            

        


def scan(url, html):
    scanner = charsetMismatchScanRule()
    return scanner.scan_http_response_receive(requests.get(url), html, url)

# scan('http://nsi.isaix.com')