from bs4 import BeautifulSoup
import requests

# This checks for proper configuration of cookie attributes

def check_cookies(cookies):
    ns = "CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute"
    nohttp = "CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag"
    noSameSite = "CWE-1275: Sensitive Cookie with Improper SameSite Attribute"
    broad_domain = 'CWE-565: Reliance on Cookies without Validation and Integrity'
    broad_path = []
    retval = {
        
    }

    for cookie in cookies:
        retval[cookie.get('name')] = {
            'cookiesSecure': ns if cookie.get('secure') == False else None,
            'cookiesHttpOnly': nohttp if cookie.get('httpOnly') == False else None,
            'cookiesSameSite': noSameSite if cookie.get('sameSite') == 'None' else None,
            'cookiesBroadDomain': broad_domain if cookie.get('domain').count('.') < 2 else None,
        }
    return {'cookies': retval}



# view usage in app.py