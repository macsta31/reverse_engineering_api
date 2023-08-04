class cookieLooselyScopedScanRule:
    def __init__(self):
        pass

    def scan_http_response_receive(self, cookies, url):
        for cookie in cookies:
            if not cookie.get('secure'):
                return {
                    'url': url,
                    'method': "GET",
                    "parameter": "",
                    "attack": "",
                    "evidence": cookie
                }
            

def scan(cookies, url):
    scanner = cookieLooselyScopedScanRule()
    return scanner.scan_http_response_receive(cookies, url)