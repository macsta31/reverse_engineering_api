class cookieSecureFlagScanRule:
    def __init__(self):
        pass

    def scan_http_response_receive(self, cookies, url):
        for cookie in cookies:
            if cookie.get('domain').count('.') < 2:
                return {
                    'url': url,
                    'method': "GET",
                    "parameter": "",
                    "attack": "",
                    "evidence": cookie
                }
            

def scan(cookies, url):
    scanner = cookieSecureFlagScanRule()
    return scanner.scan_http_response_receive(cookies, url)