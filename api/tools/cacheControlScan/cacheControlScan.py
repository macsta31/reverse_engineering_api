import requests
from bs4 import BeautifulSoup


class CacheControlScanRule:
    def __init__(self):
        self.CACHE_CONTROL_HEADER = "Cache-Control"
        self.evidence = []

    def scan_http_response_receive(self, msg, url):
        if msg.headers.get("Content-Type") and "text" in msg.headers.get("Content-Type"):
            if not msg.headers.get("Cache-Control") or "no-store" not in msg.headers.get("Cache-Control") or "no-cache" \
                not in msg.headers.get("Cache-Control") or "must-revalidate" not in msg.headers.get("Cache-Control"):
                
                self.evidence.append(msg.headers.get("Cache-Control"))
        if self.evidence:
            # return {
            #     'cwe': "CWE-525: Use of Web Browser Cache Containing Sensitive Information",
            #     'evidence': self.evidence,
            #     'title': 'Re-examine Cache-control Directives',
            #     'risk': 'Informational',
            #     'summary': "The cache-control header has not been set properly or is missing, allowing the browser and proxies to cache content. For static assets like css, js, or image files this might be intended, however, the resources should be reviewed to ensure that no sensitive content will be cached.",
            #     "solution": "For secure content, ensure the cache-control HTTP header is set with 'no-cache, no-store, must-revalidate'. If an asset should be cached consider setting the directives 'public, max-age, immutable'."
            # }
            return {
                'url': url,
                'method': "GET",
                "parameter": "",
                "attack": "",
                "evidence": self.evidence[0] if self.evidence[0] else ""
            }
        else: return None

def badCacheControl(url):
    response = requests.get(url)
    scanner = CacheControlScanRule()
    return scanner.scan_http_response_receive(response, url)


# print(badCacheControl('https://darkwebscanner.mackstathis.dev'))

