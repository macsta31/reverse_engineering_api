import requests
from bs4 import BeautifulSoup

class RetrievedFromCacheScanRule:

    def __init__(self):
        self.evidence = []

    def scan_http_response_receive(self, url):
        try:
            response = requests.get(url)
            soup = BeautifulSoup(response.text, 'html.parser')

            xcache_headers = response.headers.get('X-Cache')
            if xcache_headers:
                xcache_headers = xcache_headers.split(',')
                for xcache_header in xcache_headers:
                    proxy_server_details = xcache_header.strip().split(' ')
                    hit_or_miss = proxy_server_details[0].upper()  # HIT or MISS
                    if hit_or_miss == 'HIT':
                        self.evidence.append(f"{url} was served from a cache, due to presence of a 'HIT' in the 'X-Cache' response header")
                        # return {
                        #     'cwe': '',
                        #     'evidence': self.evidence,
                        #     'title': 'Retrieved from Cache',
                        #     'risk': "",
                        #     'summary': 'The content was retrieved from a shared cache. If the response data is sensitive, personal or user-specific, this may result in sensitive information being leaked. In some cases, this may even result in a user gaining complete control of the session of another user, depending on the configuration of the caching components in use in their environment. This is primarily an issue where caching servers such as “proxy” caches are configured on the local network. This configuration is typically found in corporate or educational environments, for instance.',
                        #     'solution': "Validate that the response does not contain sensitive, personal or user-specific information. If it does, consider the use of the following HTTP response headers, to limit, or prevent the content being stored and retrieved from the cache by another user: Cache-Control: no-cache, no-store, must-revalidate, private Pragma: no-cache Expires: 0 This configuration directs both HTTP 1.0 and HTTP 1.1 compliant caching servers to not store the response, and to not retrieve the response (without validation) from the cache, in response to a similar request."
                        # }
                        return {
                            'url': url,
                            'method': "GET",
                            "parameter": "",
                            "attack": "",
                            "evidence": self.evidence[0]
                        }

            age_headers = response.headers.get('Age')
            if age_headers:
                age_as_long = int(age_headers)
                if age_as_long >= 0:
                    self.evidence.append(f"{url} was served from a HTTP/1.1 cache, due to presence of a valid (non-negative decimal integer) 'Age' response header value")
                    return {
                        'url': url,
                        'method': "GET",
                        "parameter": "",
                        "attack": "",
                        "evidence": self.evidence[0]
                    }
                
            return None

        except Exception as e:
            print("An error occurred while checking if a URL was served from a cache", e)

def isRetrievedFromCache(url):
    scanner = RetrievedFromCacheScanRule()
    return scanner.scan_http_response_receive(url)

# print(isRetrievedFromCache('https://darkwebscanner.mackstathis.dev/robots.txt'))

