import requests
from bs4 import BeautifulSoup
import base64
import gzip
from io import BytesIO

class insecureJSFViewState:
    def __init__(self):
        pass


    def decompress(self, value):
        if len(value) < 4:
            return value

        # Check if the data has GZIP magic header
        head = (value[0] & 0xff) | ((value[1] << 8) & 0xff00)
        GZIP_MAGIC = 0x8b1f  # this is the GZIP magic number
        if GZIP_MAGIC != head:
            return value

        # If the value is GZIP-compressed, decompress it
        output = BytesIO()
        with gzip.GzipFile(fileobj=BytesIO(value)) as input_gzip:
            output.write(input_gzip.read())
        return output.getvalue()

    def is_raw_view_state_secure(self, view_state):
        if not view_state:
            return True

        # Look for string values like 'java' to determine that it's insecure.
        # TODO: Improve this to look for more than just 'java'. It's possible
        # we could even have a false positive here.
        if "java" in view_state:
            return False

        return True

    def viewStateStoredOnServer(self, val):

        return (val and ':' in val)
    
    def isViewStateSecure(self, val, charset):
        if val or val == "":
            return True
        
        try:
            view_state_decode_bytes = self.decompress(base64.b64decode(val))
        except (IOError, ValueError) as e:
            # ViewState might be unencoded which is theoretically possible.
            return self.is_raw_view_state_secure(val)
        
        str_decodedViewState = str(view_state_decode_bytes)
        if not self.is_raw_view_state_secure(view_state_decode_bytes):
            return False
        else: return True
    
    def scan_http_response_receive(self, msg:requests.Response, html):
        soup = BeautifulSoup(html, 'html.parser')
        sourceElements = soup.find_all('input')
        if sourceElements:
            for sourceElement in sourceElements:
                src = sourceElement.get('id')
                if src and 'viewstate' in str.lower(src):
                    val = sourceElement.get('value')
                    if val and val.startswith('_'):
                        return
                    
                    if self.viewStateStoredOnServer(val):
                        return
                    
                    if not self.isViewStateSecure(val, msg.encoding):
                        return 'vulnerability found'


def scan(url):
    scanner = insecureJSFViewState()
    return scanner.scan_http_response_receive(requests.get(url), requests.get(url).content)


# print(scan('http://nsi.isaix.com'))
