import requests
import base64
import re


class insecureAuthenticationScan:
    def __init__(self):
        pass

    def scan_http_request_send(self, msg:requests.Response, url):
        if url.startswith('https://'):  # Assuming this is a method or property in the `msg` class.
            return

        headers = msg.headers

        auth_header_values = headers.get('Authorization', [])
        if not auth_header_values:
            return

        for auth_header_value in auth_header_values:
            auth_mechanism = None
            if "basic " in auth_header_value.lower() or "digest " in auth_header_value.lower():
                username = None
                password = None

                auth_mechanism = auth_header_value.split()[0].strip().lower()

                # Handle Basic Auth
                if auth_mechanism == "basic":
                    auth_values = auth_header_value.split()
                    if len(auth_values) == 2:
                        try:
                            decoded = base64.b64decode(auth_values[1]).decode('utf-8')
                            parts = decoded.split(":", 1)
                            username = parts[0]
                            if len(parts) > 1:
                                password = parts[1]
                            if password:
                                return
                            # return ((alert_risk, uri, method, auth_mechanism, username, password))
                            return {
                                'url': url,
                                'method': "GET",
                                "parameter": "",
                                "attack": "",
                                "evidence": 'auth mechanism: {}, username: {}, password: {}'.format(auth_mechanism, username, password)
                            }
                        except Exception:
                            print(f"Invalid Base64 value for {auth_mechanism} Authentication: {auth_values[1]}")
                    else:
                        print(f"Malformed {auth_mechanism} Authentication Header: [{auth_header_value}]")


                # Handle Digest Auth
                elif auth_mechanism == "digest":
                    auth_values = auth_header_value.split(None, 1)
                    if len(auth_values) == 2:
                        pattern = r'.*username="([^"]+)".*'
                        matcher = re.search(pattern, auth_values[1])
                        if matcher:
                            username = matcher.group(1)
                            # return ((Alert.RISK_MEDIUM, uri, method, auth_mechanism, username, None))
                            return {
                                'url': url,
                                'method': "GET",
                                "parameter": "",
                                "attack": "",
                                "evidence": 'auth mechanism: {}, username: {}'.format(auth_mechanism, username)
                            }
                        else:
                            print(f"Malformed {auth_mechanism} Authentication Header: [{auth_header_value}]. No username was found")
                    else:
                        print(f"Malformed {auth_mechanism} Authentication Header: [{auth_header_value}]")


def scan(url):
    scanner = insecureAuthenticationScan()
    return scanner.scan_http_request_send(requests.get(url), url)

# print(scan('http://nsi.isaix.com'))