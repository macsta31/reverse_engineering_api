import unittest
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from urllib.parse import urlparse
import traceback
import json


from anticlickjacking.anticlickjacking import isVulner as antiClickJacking
from applicationError.applicationErrorScan import hasApplicationError
from bigRedirect.bigRedicrects import isBigRedirect
from contentSecurityMissing.contentSecurityMissing import isMissing as csMissing
from contentSecurityPolicy.contentSecurityPolicy import hasContentSecurity as csProper
from contentTypeMissing.contentTypeMissing import hasContentType
from corsScans.corsMisconfig import corsConfig
from corsScans.corsScriptInclusion import corsScriptInclusion
from csrfCountermeasures.csrfCountermeasures import csrfVulnCheck
from directoryBrowsing.directoryBrowsing import hasDirectoryBrowsing
from heartBleedScan.heartBleedScan import checkHeartBleed
from privateAddressDisclosure.privateAddressDisclosure import scanPrivateAddressDisclosure
from retrievedFromCacheScan.retrievedFromCache import isRetrievedFromCache
from informationDisclosureURL.informationDisclosureURL import scan as infodisclosurescan
from insecureFormLoad.insecureFormLoad import scan as insecureFormLoadScan
from insecureFormPost.insecureFormPost import scan as insecureFormPostScan
from modernWebApp.modernWebApp import scan as modernWebAppScan
from mixedContentScan.mixedContentScan import scan as mixedContentScan
from piiSCan.piiScan import scan as piiScan
from serverHeaderInfoLeak.serverHeaderInfoLeak import scan as serverHeaderInfoLeakScan
from timeStampDisclosure.timeStampDisclosure import scan as timeStampScan
from userControlledCharset.userControlledCharset import scan as userControlledCharsetScan
from userControlledCookie.userControlledCookie import scan as userControlledCookieScan
from userControlledHtmlAttribute.userControlledHtmlAttribute import scan as userControlledHtmlScan
from userControlledJavascriptEvent.userControlledJavascriptEvent import scan as userControlledJsScan
from userControlledOpenRedirect.userControlledOpenRedirect import scan as userControlledOpenRedirectScan
from XAspNetVersionScanRule.XAspNetVersionScanRule import scan as XAspNetVersionScan
from XBackendServerInformationLeakScanRule.XServerInformationLeakScanRule import scan as XBackendServerScan
from XChromeLoggerDataInfoLeakScanRule.XChromeLoggerDataInfoLeakScanRule import scan as XChromeLoggerScan
from XContentTypeOptionsScanRule.XContentTypeScanRule import scan as XContentTypeScan
from XDebugTokenScanRule.XDebugTokenScanRule import scan as XDebugScan
from XPoweredByHeaderInfoLeakScanRule.XPoweredByHeaderInfoLeakScanRule import scan as XPoweredByScan
from informationDisclosureSusComment.informationDisclosureSusComment import hasSusComment
from cacheControlScan.cacheControlScan import badCacheControl
from cookieHttpOnlyScanRule.cookieHttpOnlyScanRule import scan as httpOnlyScan
from cookieLooselyScopedScanRule.cookieLooselyScopedScanRule import scan as looselyScopedScan
from cookieSecureFlagScanRule.cookieSecureFlagScanRule import scan as secureFlagScan
from charsetMismatchScanRule.charsetMismatchScanRule import scan as charsetMismatchScan
from hashDisclosureScan.hashDisclosureScan import scan as hashDisclosureScan
from informationDisclosureReferrer.informationDisclosureReferrer import scan as referrerScan
from insecureAuthenticationScan.insecureAuthenticationScan import scan as insecureAuthScan
from insecureJsfViewState.insecureJsfPassiveViewState import scan as insecureJsfScan

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    RESET = '\033[0m'

    
class CustomTestResult(unittest.TextTestResult):
    def addSuccess(self, test):
        pass

    def addError(self, test, err):
        # This method gets called when there's an error (exception) in a test.
        # The default behavior is to print an "E", which you don't want.
        # So, capture the error but don't print the "E".
        print("Exception Occured")
        self.errors.append((test, self._exc_info_to_string(err, test)))


class CustomTextTestRunner(unittest.TextTestRunner):
    resultclass = CustomTestResult
    def __init__(self, *args, **kwargs):
        super(CustomTextTestRunner, self).__init__(*args, **kwargs)

    def formatError(self, test, err):
        # This method is responsible for formatting the error. 
        # Since you're interested in changing the format of successful tests, you can leave this as it is.
        return super(CustomTextTestRunner, self).formatError(test, err)

    def formatFailure(self, test, err):
        # Similarly, you can leave the failure format as it is.
        return super(CustomTextTestRunner, self).formatFailure(test, err)




class WebScanTests(unittest.TestCase):

    def setUp(self):
        self.url = 'http://nsi.isaix.com'

        if not self.url_ok(self.url):
            print("Invalid URL, modify and try again")
            return
        
        try:
            options = Options()
            options.add_argument('--headless')
            options.add_argument('--no-sandbox')
            options.add_argument('--disable-dev-shm-usage')
            driver = webdriver.Chrome(options=options)
            driver.get(self.url)
            self.html = driver.page_source
            self.cookies = driver.get_cookies()
        except Exception as e:
            print('error while booting selenium on url {}: {}'.format(self.url, traceback.print_exc()))
            

    def _runTest(self, scan_function, name, *args, **kwargs):
        print(f"Running test {name}: ", end="")
        try:
            result = scan_function(*args, **kwargs)
            if result:
                print(f"{Colors.GREEN}Found{Colors.RESET}", end=" ")
                # print(result['evidence'], end="")  # Uncomment for evidence
                print("")
            else:
                print(f"{Colors.RED}Not Found{Colors.RESET}")
        except Exception as e:
            print("Exception Occurred")


    def url_ok(self, url):
        try:
            result = urlparse(url)
            # Check if scheme is either http or https and netloc is not empty
            return all([result.scheme in ['http', 'https'], result.netloc])
        except ValueError:
            return False

    def test_antiClickJacking(self):
        self._runTest(antiClickJacking, "Anti ClickJacking Scan", self.url)

    def test_hasApplicationError(self):
        self._runTest(hasApplicationError, "Application Error Scan", self.url, '../application_errors.xml')

    def test_isBigRedirect(self):
        self._runTest(isBigRedirect, "Big Redirect Scan", self.url)

    def test_csMissing(self):
        self._runTest(csMissing, "Content Security Missing Scan", self.url)

    def test_csProper(self):
        self._runTest(csProper, "Content Security Configuration Scan", self.url)

    def test_hasContentType(self):
        self._runTest(hasContentType, "Content Type Scan", self.url)

    def test_corsConfig(self):
        self._runTest(corsConfig, "CORS Config Scan", self.url)

    def test_corsScriptInclusion(self):
        self._runTest(corsScriptInclusion, "Cors Script Inclusion Scan", self.url)

    def test_csrfVulnCheck(self):
        self._runTest(csrfVulnCheck, "CSRF Vulnerability Scan", self.html, self.url)

    def test_hasDirectoryBrowsing(self):
        self._runTest(hasDirectoryBrowsing, "Directory Browsing Scan", self.html, self.url)

    def test_checkHeartBleed(self):
        self._runTest(checkHeartBleed, "HeartBleed Scan", self.url)

    def test_scanPrivateAddressDisclosure(self):
        self._runTest(scanPrivateAddressDisclosure, "Private Address Disclosure Scan", self.url)

    def test_isRetrievedFromCache(self):
        self._runTest(isRetrievedFromCache, "Retrieved From Cache Scan", self.url)

    def test_infodisclosurescan(self):
        self._runTest(infodisclosurescan, "Information Disclosure Scan", self.url)

    def test_insecureFormLoadScan(self):
        self._runTest(insecureFormLoadScan, "Insecure Form Load Scan", self.url, self.html)

    def test_insecureFormPostScan(self):
        self._runTest(insecureFormPostScan, "Insecure Form Post Scan", self.url, self.html)

    def test_modernWebAppScan(self):
        self._runTest(modernWebAppScan, "Modern Web App Scan", self.html, self.url)

    def test_mixedContentScan(self):
        self._runTest(mixedContentScan, "Mixed Content Scan", self.url)

    def test_piiScan(self):
        self._runTest(piiScan, "PII Scan", self.url)

    def test_serverHeaderInfoLeakScan(self):
        self._runTest(serverHeaderInfoLeakScan, "Server Header Leak Scan", self.url)

    def test_timeStampScan(self):
        self._runTest(timeStampScan, "TimeStamp Scan", self.url)

    def test_userControlledCharsetScan(self):
        self._runTest(userControlledCharsetScan, "User Controlled Charset Scan", self.url, self.html)

    def test_userControlledCookieScan(self):
        self._runTest(userControlledCookieScan, "User Controlled Cookie Scan", self.url)

    def test_userControlledHtmlScan(self):
        self._runTest(userControlledHtmlScan, "User Controlled HTML Scan", self.url)

    def test_userControlledJsScan(self):
        self._runTest(userControlledJsScan, "User Controlled JavaScript Scan", self.url, self.html)

    def test_userControlledOpenRedirectScan(self):
        self._runTest(userControlledOpenRedirectScan, "User Controlled Open Redirect Scan", self.url)

    def test_XAspNetVersionScan(self):
        self._runTest(XAspNetVersionScan, "X-ASP-NET Version Scan", self.url)

    def test_XBackendServerScan(self):
        self._runTest(XBackendServerScan, "X-Backend-Server Scan", self.url)

    def test_XChromeLoggerScan(self):
        self._runTest(XChromeLoggerScan, "X-Chrome Logger Scan", self.url)

    def test_XContentTypeScan(self):
        self._runTest(XContentTypeScan, "X-Content-Type Scan", self.url)

    def test_XDebugScan(self):
        self._runTest(XDebugScan, "X-Debug Scan", self.url)

    def test_XPoweredByScan(self):
        self._runTest(XPoweredByScan, "X-Powered-By Scan", self.url)

    def test_hasSusComment(self):
        self._runTest(hasSusComment, "Suspicious Comment Scan", self.url)

    def test_badCacheControl(self):
        self._runTest(badCacheControl, "Bad Cache Control Scan", self.url)



    def test_httpOnlyScan(self):
        self._runTest(httpOnlyScan, "Cookie HTTP Only Scan", self.cookies, self.url)

    def test_looselyScopedScan(self):
        self._runTest(looselyScopedScan, "Cookie Loosely Scoped Scan", self.cookies, self.url)

    def test_secureFlagScan(self):
        self._runTest(secureFlagScan, "Cookie Secure Scan", self.cookies, self.url)

    def test_charsetMismatchScan(self):
        self._runTest(charsetMismatchScan, "Charset Mismatch Scan", self.url, self.html)

    def test_hashDisclosureScan(self):
        self._runTest(hashDisclosureScan, "Hash Disclosure Scan", self.url, self.html)

    def test_referrerScan(self):
        self._runTest(referrerScan, "Information Disclosure Referrer Scan", self.url)

    def test_insecureAuthScan(self):
        self._runTest(insecureAuthScan, "Insecure Auth Scan", self.url)

    def test_insecureJsfScan(self):
        self._runTest(insecureJsfScan, "Insecure JSF Scan", self.url)


    

if __name__ == "__main__":
    unittest.main(testRunner=CustomTextTestRunner())

