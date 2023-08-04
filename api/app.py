from flask import Flask, request, jsonify
from flask_cors import CORS, cross_origin
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from bs4 import BeautifulSoup
import traceback
from urllib.parse import urlparse, parse_qs

from tools.anticlickjacking.anticlickjacking import isVulner as antiClickJacking
from tools.applicationError.applicationErrorScan import hasApplicationError
from tools.bigRedirect.bigRedicrects import isBigRedirect
from tools.contentSecurityMissing.contentSecurityMissing import isMissing as csMissing
from tools.contentSecurityPolicy.contentSecurityPolicy import hasContentSecurity as csProper
from tools.contentTypeMissing.contentTypeMissing import hasContentType
from tools.cookies.cookies import check_cookies
from tools.corsScans.corsMisconfig import corsConfig
from tools.corsScans.corsScriptInclusion import corsScriptInclusion
from tools.csrfCountermeasures.csrfCountermeasures import csrfVulnCheck
from tools.directoryBrowsing.directoryBrowsing import hasDirectoryBrowsing
from tools.heartBleedScan.heartBleedScan import checkHeartBleed
from tools.privateAddressDisclosure.privateAddressDisclosure import scanPrivateAddressDisclosure
from tools.retrievedFromCacheScan.retrievedFromCache import isRetrievedFromCache
from tools.informationDisclosureURL.informationDisclosureURL import scan as infodisclosurescan
from tools.insecureFormLoad.insecureFormLoad import scan as insecureFormLoadScan
from tools.insecureFormPost.insecureFormPost import scan as insecureFormPostScan
from tools.modernWebApp.modernWebApp import scan as modernWebAppScan
from tools.mixedContentScan.mixedContentScan import scan as mixedContentScan
from tools.piiSCan.piiScan import scan as piiScan
from tools.serverHeaderInfoLeak.serverHeaderInfoLeak import scan as serverHeaderInfoLeakScan
from tools.timeStampDisclosure.timeStampDisclosure import scan as timeStampScan
from tools.userControlledCharset.userControlledCharset import scan as userControlledCharsetScan
from tools.userControlledCookie.userControlledCookie import scan as userControlledCookieScan
from tools.userControlledHtmlAttribute.userControlledHtmlAttribute import scan as userControlledHtmlScan
from tools.userControlledJavascriptEvent.userControlledJavascriptEvent import scan as userControlledJsScan
from tools.userControlledOpenRedirect.userControlledOpenRedirect import scan as userControlledOpenRedirectScan
from tools.XAspNetVersionScanRule.XAspNetVersionScanRule import scan as XAspNetVersionScan
from tools.XBackendServerInformationLeakScanRule.XServerInformationLeakScanRule import scan as XBackendServerScan
from tools.XChromeLoggerDataInfoLeakScanRule.XChromeLoggerDataInfoLeakScanRule import scan as XChromeLoggerScan
from tools.XContentTypeOptionsScanRule.XContentTypeScanRule import scan as XContentTypeScan
from tools.XDebugTokenScanRule.XDebugTokenScanRule import scan as XDebugScan
from tools.XPoweredByHeaderInfoLeakScanRule.XPoweredByHeaderInfoLeakScanRule import scan as XPoweredByScan
from tools.informationDisclosureSusComment.informationDisclosureSusComment import hasSusComment
from tools.cacheControlScan.cacheControlScan import badCacheControl
from tools.directoryListing.directoryListing import listDirectory
from tools.cookieHttpOnlyScanRule.cookieHttpOnlyScanRule import scan as httpOnlyScan
from tools.cookieLooselyScopedScanRule.cookieLooselyScopedScanRule import scan as looselyScopedScan
from tools.cookieSecureFlagScanRule.cookieSecureFlagScanRule import scan as secureFlagScan
import requests 
import multiprocessing

#  TODO: Convert to class

NUM_PROC = 3

def url_ok(url):
    try:
        result = urlparse(url)
        # Check if scheme is either http or https and netloc is not empty
        return all([result.scheme in ['http', 'https'], result.netloc])
    except ValueError:
        return False


##add location of csrf token

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

class Scanner:
    def __init__(self):
        self.vulnerabilities = {}

    def handle_500(self, error):
        response = jsonify({'error': 'Internal server error'})
        response.status_code = 500
        return cross_origin()(response)  # Apply CORS to this response

    def create_vuln_entry(self, name, description, wasc_id, cweid, reference, solution, risk):
        return {
            "name": name,
            "description": description,
            "urls": [],
            "instances": 0,
            "wasc_id": wasc_id,
            "cweid": cweid,
            "plugin_id": "",
            "reference": reference,
            "solution": solution,
            "risk": risk
        }

    def add_urls(self, name, url_entry):
        if url_entry != None:
            vuln_entry = self.vulnerabilities[name].copy()
            vuln_entry["urls"].append(url_entry)
            vuln_entry['instances'] = vuln_entry['instances'] + 1
            self.vulnerabilities[name] = vuln_entry

    def execute_scans(self, url):
        try:
            try:
                options = Options()
                options.add_argument('--headless')
                options.add_argument('--no-sandbox')
                options.add_argument('--disable-dev-shm-usage')
                driver = webdriver.Chrome(options=options)
                driver.get(url)
                html = driver.page_source
                cookies = driver.get_cookies()
            except Exception as e:
                print('error while booting selenium on url {}: {}'.format(url, e.with_traceback()))
            retval = {}
            anticlickjacking = antiClickJacking(url)
            # print(not self.vulnerabilities['Missing Anti ClickJacking Header'])
            if antiClickJacking:
                if 'Missing Anti ClickJacking Header' not in self.vulnerabilities:
                    self.vulnerabilities['Missing Anti ClickJacking Header'] = self.create_vuln_entry('Missing Anti ClickJacking Header', "The response does not include either Content-Security-Policy with ‘frame-ancestors’ directive or X-Frame-Options to protect against ‘ClickJacking’ attacks.", 15, "CWE-1021: Improper Restriction of Rendered UI Layers or Frames", " https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options", "Modern Web browsers support the Content-Security-Policy and X-Frame-Options HTTP headers. Ensure one of them is set on all web pages returned by your site/app. If you expect the page to be framed only by pages on your server (e.g. it's part of a FRAMESET) then you'll want to use SAMEORIGIN, otherwise if you never expect the page to be framed, you should use DENY. Alternatively consider implementing Content Security Policy's 'frame-ancestors' directive.", 'Medium')

                self.add_urls('Missing Anti ClickJacking Header', anticlickjacking)

            applicationError = hasApplicationError(url, './application_errors.xml') # Use this line for local
            if applicationError:
                if 'Application Error Disclosure' not in self.vulnerabilities:
                    self.vulnerabilities['Application Error Disclosure'] = self.create_vuln_entry('Application Error Disclosure', "This page contains an error/warning message that may disclose sensitive information like the location of the file that produced the unhandled exception. This information can be used to launch further attacks against the web application. The alert could be a false positive if the error message is found inside a documentation page.", 13, "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor", "", "Review the source code of this page. Implement custom error pages. Consider implementing a mechanism to provide a unique error reference/identifier to the client (browser) while logging the details on the server side and not exposing them to the user.", "Medium")

                self.add_urls('Application Error Disclosure', applicationError)
            bigRedirect = isBigRedirect(url)
            if bigRedirect:
                if 'Big Redirect' not in self.vulnerabilities:
                    self.vulnerabilities['Big Redirect'] = self.create_vuln_entry('Big Redirect Detected (Potential Sensitive Information Leak)', "The server has responded with a redirect that seems to provide a large response. This may indicate that although the server sent a redirect it also responded with body content (which may include sensitive details, PII, etc.).", "", "", "", "Ensure that no sensitive information is leaked via redirect responses. Redirect responses should have almost no content.", "")

                self.add_urls('Big Redirect', bigRedirect)

            contentSecurityMissing = csMissing(url)
            if contentSecurityMissing:
                if 'Content Security Missing' not in self.vulnerabilities:
                    self.vulnerabilities['Content Security Missing'] = self.create_vuln_entry('Content Security Policy (CSP) Header Not Set', 'Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks, including Cross Site Scripting (XSS) and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.', 15, 'CWE-693: Protection Mechanism Failure', "https://developer.mozilla.org/en-US/docs/Web/Security/CSP/Introducing_Content_Security_Policy", "Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.", "Medium")

                self.add_urls('Content Security Missing', contentSecurityMissing)


            contentSecurityProper = csProper(url)
            if contentSecurityProper:
                if 'Content Security Policy' not in self.vulnerabilities:
                    self.vulnerabilities['Content Security Policy'] = self.create_vuln_entry('CSP: X-Content-Security-Policy', "Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks. Including (but not limited to) Cross Site Scripting (XSS), and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.", 15, "CWE-693: Protection Mechanism Failure", "http://www.w3.org/TR/CSP2/", "Ensure that your web server, application server, load balancer, etc. is properly configured to set the Content-Security-Policy header.", "Low")

                self.add_urls('Content Security Policy', contentSecurityProper)
            
            contentType = hasContentType(url)
            if contentType:
                if 'Missing Content Type Header' not in self.vulnerabilities:
                    self.vulnerabilities['Missing Content Type Header'] = self.create_vuln_entry('Content-Type Header Missing', 'The Content-Type header was either missing or empty.', 12, "CWE-345: Insufficient Verification of Data Authenticity", " http://msdn.microsoft.com/en-us/library/ie/gg622941%28v=vs.85%29.aspx", "Ensure each page is setting the specific and appropriate content-type value for the content being delivered.", "Informational")

                self.add_urls('Missing Content Type Header', contentType)
            # TODO: modify cookies return value for this

            # cookies = check_cookies(cookies)
            # for key in cookies:
            #     if cookies[key]:
            #         retval[key] = cookies[key]

            corsMisconfig = corsConfig(url)
            if corsMisconfig:
                if 'Cross Domain Misconfiguration' not in self.vulnerabilities:
                    self.vulnerabilities['Cross Domain Misconfiguration'] = self.create_vuln_entry('CORS Misconfiguration', 'This CORS misconfiguration could allow an attacker to perform AJAX queries to the vulnerable website from a malicious page loaded by the victim’s user agent. In order to perform authenticated AJAX queries, the server must specify the header “Access-Control-Allow-Credentials: true” and the “Access-Control-Allow-Origin” header must be set to null or the malicious page’s domain. Even if this misconfiguration doesn’t allow authenticated AJAX requests, unauthenticated sensitive content can still be accessed (e.g intranet websites). A malicious page can belong to a malicious website but also a trusted website with flaws (e.g XSS, support of HTTP without TLS allowing code injection through MITM, etc).', 14, 'CWE-942: Permissive Cross-domain Policy with Untrusted Domains', "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS", "If a web resource contains sensitive information, the origin should be properly specified in the Access-Control-Allow-Origin header. Only trusted websites needing this resource should be specified in this header, with the most secured protocol supported.", "Medium")

                self.add_urls('Cross Domain Misconfiguration', corsMisconfig)

            corsScriptInclusionTest = corsScriptInclusion(url)
            if corsScriptInclusionTest:
                if 'Cross-Domain JavaScript Source File Inclusion' not in self.vulnerabilities:
                    self.vulnerabilities['Cross-Domain JavaScript Source File Inclusion'] = self.create_vuln_entry('Cross-Domain JavaScript Source File Inclusion', 'The page includes one or more script files from a third-party domain.', 15, 'CWE-829: Inclusion of Functionality from Untrusted Control Sphere', "", "Ensure JavaScript source files are loaded from only trusted sources, and the sources can't be controlled by end users of the application.", "Low")

                self.add_urls('Cross-Domain JavaScript Source File Inclusion', corsScriptInclusionTest)

            csrfCountermeasures = csrfVulnCheck(html, url)
            if csrfCountermeasures:
                if 'Absence of Anti-CSRF Tokens' not in self.vulnerabilities:
                    self.vulnerabilities['Absence of Anti-CSRF Tokens'] = self.create_vuln_entry('Absence of Anti-CSRF Tokens', "A cross-site request forgery is an attack that involves forcing a victim to send an HTTP request to a target destination without their knowledge or intent in order to perform an action as the victim. The underlying cause is application functionality using predictable URL/form actions in a repeatable way. The nature of the attack is that CSRF exploits the trust that a web site has for a user. By contrast, cross-site scripting (XSS) exploits the trust that a user has for a web site. Like XSS, CSRF attacks are not necessarily cross-site, but they can be. Cross-site request forgery is also known as CSRF, XSRF, one-click attack, session riding, confused deputy, and sea surf. CSRF attacks are effective in a number of situations, including: * The victim has an active session on the target site. * The victim is authenticated via HTTP auth on the target site. * The victim is on the same local network as the target site.CSRF has primarily been used to perform an action against a target site using the victim’s privileges, but recent techniques have been discovered to disclose information by gaining access to the response. The risk of information disclosure is dramatically increased when the target site is vulnerable to XSS, because XSS can be used as a platform for CSRF, allowing the attack to operate within the bounds of the same-origin policy.", 9, "CWE-352: Cross-Site Request Forgery (CSRF)", "http://projects.webappsec.org/Cross-Site-Request-Forgery", "Phase: Architecture and Design Use a vetted library or framework that does not allow this weakness to occur or provides constructs that make this weakness easier to avoid. For example, use anti-CSRF packages such as the OWASP CSRFGuard. Phase: Implementation Ensure that your application is free of cross-site scripting issues, because most CSRF defenses can be bypassed using attacker-controlled script. Phase: Architecture and Design Generate a unique nonce for each form, place the nonce into the form, and verify the nonce upon receipt of the form. Be sure that the nonce is not predictable (CWE-330). Note that this can be bypassed using XSS. Identify especially dangerous operations. When the user performs a dangerous operation, send a separate confirmation request to ensure that the user intended to perform that operation. Note that this can be bypassed using XSS. Use the ESAPI Session Management control. This control includes a component for CSRF. Do not use the GET method for any request that triggers a state change. Phase: Implementation Check the HTTP Referer header to see if the request originated from an expected page. This could break legitimate functionality, because users or proxies may have disabled sending the Referer for privacy reasons.", "")

                self.add_urls('Absence of Anti-CSRF Tokens', csrfCountermeasures)

            directBrowsing = hasDirectoryBrowsing(html, url)
            if directBrowsing:
                if 'Directory Browsing' not in self.vulnerabilities:
                    self.vulnerabilities['Directory Browsing'] = self.create_vuln_entry('Directory Browsing', "It is possible to view the directory listing. Directory listing may reveal hidden scripts, include files, backup source files, etc. which can be accessed to read sensitive information.", 48, "CWE-548: Exposure of Information Through Directory Listing", "http://httpd.apache.org/docs/mod/core.html#options", "Disable directory browsing. If this is required, make sure the listed files does not induce risks.", "Medium")

                self.add_urls('Directory Browsing', directBrowsing)

            heartbleed = checkHeartBleed(url)
            if heartbleed:
                if 'HeartBleed' not in self.vulnerabilities:
                    self.vulnerabilities['HeartBleed'] = self.create_vuln_entry('Heartbleed OpenSSL Vulnerability', "The TLS implementation in OpenSSL 1.0.1 before 1.0.1g does not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information from process memory via crafted packets that trigger a buffer over-read, potentially disclosing sensitive information.", 20, "CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer", " https://nvd.nist.gov/vuln/detail/CVE-2014-0160", "Update to OpenSSL 1.0.1g or later. Re-issue HTTPS certificates. Change asymmetric private keys and shared secret keys, since these may have been compromised, with no evidence of compromise in the server log files.", "High")

                self.add_urls('HeartBleed', heartbleed)

            privadd = scanPrivateAddressDisclosure(url)
            if privadd:
                if 'Private Address' not in self.vulnerabilities:
                    self.vulnerabilities['Private Address'] = self.create_vuln_entry('Private IP Disclosure', "A private IP (such as 10.x.x.x, 172.x.x.x, 192.168.x.x) or an Amazon EC2 private hostname (for example, ip-10-0-56-78) has been found in the HTTP response body. This information might be helpful for further attacks targeting internal systems.", 13, 'CWE-200: Exposure of Sensitive Information to an Unauthorized Actor', " https://tools.ietf.org/html/rfc1918", "Remove the private IP address from the HTTP response body. For comments, use JSP/ASP/PHP comment instead of HTML/JavaScript comment which can be seen by client browsers.", "Low")

                self.add_urls('Private Address', privadd)

            cacheRet = isRetrievedFromCache(url)
            if cacheRet:
                if 'Retrieved From Cache' not in self.vulnerabilities:
                    self.vulnerabilities['Retrieved From Cache'] = self.create_vuln_entry('Retrieved from Cache', "The content was retrieved from a shared cache. If the response data is sensitive, personal or user-specific, this may result in sensitive information being leaked. In some cases, this may even result in a user gaining complete control of the session of another user, depending on the configuration of the caching components in use in their environment. This is primarily an issue where caching servers such as “proxy” caches are configured on the local network. This configuration is typically found in corporate or educational environments, for instance.", "", "", " https://tools.ietf.org/html/rfc7234", "Validate that the response does not contain sensitive, personal or user-specific information. If it does, consider the use of the following HTTP response headers, to limit, or prevent the content being stored and retrieved from the cache by another user: Cache-Control: no-cache, no-store, must-revalidate, private Pragma: no-cache Expires: 0 This configuration directs both HTTP 1.0 and HTTP 1.1 compliant caching servers to not store the response, and to not retrieve the response (without validation) from the cache, in response to a similar request.", "")

                self.add_urls('Retrieved From Cache', cacheRet)

            infodisclosureurl = infodisclosurescan(url)
            if infodisclosureurl:
                if 'Information Disclosure URL' not in self.vulnerabilities:
                    self.vulnerabilities['Information Disclosure URL'] = self.create_vuln_entry('Information Disclosure URL', 'The request appeared to contain sensitive information leaked in the URL. This can violate PCI and most organizational compliance policies. You can configure the list of strings for this check to add or remove values specific to your environment.', 13, 'CWE-200: Exposure of Sensitive Information to an Unauthorized Actor', "", "Do not pass sensitive information in URIs.", "Informational")

                self.add_urls('Information Disclosure URL', infodisclosureurl)

            insecureFormLoad = insecureFormLoadScan(url, html)
            if insecureFormLoad:
                if 'Insecure Form Load' not in self.vulnerabilities:
                    self.vulnerabilities['Insecure Form Load'] = self.create_vuln_entry('HTTP to HTTPS Insecure Transition in Form Post', 'This check looks for insecure HTTP pages that host HTTPS forms. The issue is that an insecure HTTP page can easily be hijacked through MITM and the secure HTTPS form can be replaced or spoofed.', "", "", "", "Use HTTPS for landing pages that host secure forms.", "")

                self.add_urls('Insecure Form Load', insecureFormLoad)

            insecureFormPost = insecureFormPostScan(url, html)
            if insecureFormPost:
                if 'Insecure Form Post' not in self.vulnerabilities:
                    self.vulnerabilities['Insecure Form Post'] = self.create_vuln_entry('HTTPS to HTTP Insecure Transition in Form Post', 'This check identifies secure HTTPS pages that host insecure HTTP forms. The issue is that a secure page is transitioning to an insecure page when data is uploaded through a form. The user may think they’re submitting data to a secure page when in fact they are not.', "", "", "", "Ensure sensitive data is only sent over secured HTTPS channels.", "")

                self.add_urls('Insecure Form Post', insecureFormPost)

            mwa = modernWebAppScan(html, url)
            if mwa:
                if 'Modern Web App' not in self.vulnerabilities:
                    self.vulnerabilities['Modern Web App'] = self.create_vuln_entry('Modern Web Application', 'The application appears to be a modern web application. If you need to explore it automatically then the Ajax Spider may well be more effective than the standard one.', "", "", "", "This is an informational alert and so no changes are required.", "")

                self.add_urls('Modern Web App', mwa)


            mixedContent = mixedContentScan(url)
            if mixedContent:
                if "Mixed Content" not in self.vulnerabilities:
                    self.vulnerabilities["Mixed Content"] = self.create_vuln_entry('Secure Pages Include Mixed Content', 'The page includes mixed content, that is content accessed via HTTP instead of HTTPS.', 4, 'CWE-311: Missing Encryption of Sensitive Data', 'https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html', 'A page that is available over SSL/TLS must be comprised completely of content which is transmitted over SSL/TLS. The page must not contain any content that is transmitted over unencrypted HTTP. This includes content from third party sites.', "")

            self.add_urls("Mixed Content", mixedContent)

            pii = piiScan(url)
            if pii:
                if 'PII' not in self.vulnerabilities:
                    self.vulnerabilities['PII'] = self.create_vuln_entry('PII Disclosure', 'The response contains Personally Identifiable Information, such as CC number, SSN and similar sensitive data.', 13, 'CWE-359: Exposure of Private Personal Information to an Unauthorized Actor', "", 'Check the response for the potential presence of personally identifiable information (PII), ensure nothing sensitive is leaked by the application.', "High")

                self.add_urls('PII', pii)


            serverInfoLeak = serverHeaderInfoLeakScan(url)
            if serverInfoLeak:
                if 'Server Header Info Leak' not in self.vulnerabilities:
                    self.vulnerabilities['Server Header Info Leak'] = self.create_vuln_entry("Server Leaks Version Information via 'Server' HTTP Response Header Field", 'The web/application server is leaking version information via the “Server” HTTP response header. Access to such information may facilitate attackers identifying other self.vulnerabilities your web/application server is subject to.', 13, 'CWE-200: Exposure of Sensitive Information to an Unauthorized Actor', ' http://httpd.apache.org/docs/current/mod/core.html#servertokens', "Ensure that your web server, application server, load balancer, etc. is configured to suppress the 'Server' header or provide generic details.", "Low")

                self.add_urls('Server Header Info Leak', serverInfoLeak)


            timeStampDisclosure = timeStampScan(url)
            if timeStampDisclosure:
                if 'Timestamp Disclosure' not in self.vulnerabilities:
                    self.vulnerabilities['Timestamp Disclosure'] = self.create_vuln_entry('Timestamp Disclosure', 'A timestamp was disclosed by the application/web server', 13, 'CWE-200: Exposure of Sensitive Information to an Unauthorized Actor', 'http://projects.webappsec.org/w/page/13246936/Information%20Leakage', 'Manually confirm that the timestamp data is not sensitive, and that the data cannot be aggregated to disclose exploitable patterns.', "Low")

                self.add_urls('Timestamp Disclosure', timeStampDisclosure)

            userControlledCharset = userControlledCharsetScan(url, html)
            if userControlledCharset:
                if 'User Controlled Charset' not in self.vulnerabilities:
                    self.vulnerabilities['User Controlled Charset'] = self.create_vuln_entry('User Controllable Charset', 'This check looks at user-supplied input in query string parameters and POST data to identify where Content-Type or meta tag charset declarations might be user-controlled. Such charset declarations should always be declared by the application. If an attacker can control the response charset, they could manipulate the HTML to perform XSS or other attacks. For example, an attacker controlling the element charset value is able to declare UTF-7 and is also able to include enough user-controlled payload early in the HTML document to have it interpreted as UTF-7. By encoding their payload with UTF-7 the attacker is able to bypass any server-side XSS protections and embed script in the page.', "", "", "", 'Force UTF-8 in all charset declarations. If user-input is required to decide a charset declaration, ensure that only an allowed list is used.', "")


                self.add_urls('User Controlled Charset', userControlledCharset)



            userControlledCookie = userControlledCookieScan(url)
            if userControlledCookie:
                if 'User Controlled Cookie' not in self.vulnerabilities:
                    self.vulnerabilities['User Controlled Cookie'] = self.create_vuln_entry('Cookie Poisoning', 'This check looks at user-supplied input in query string parameters and POST data to identify where cookie parameters might be controlled. This is called a cookie poisoning attack, and becomes exploitable when an attacker can manipulate the cookie in various ways. In some cases this will not be exploitable, however, allowing URL parameters to set cookie values is generally considered a bug.', "", "", " http://websecuritytool.codeplex.com/wikipage?title=Checks#user-controlled-cookie", "Do not allow user input to control cookie names and values. If some query string parameters must be set in cookie values, be sure to filter out semicolon's that can serve as name/value pair delimiters.", "")

                self.add_urls('User Controlled Cookie', userControlledCookie)


            userControlledHTML = userControlledHtmlScan(url)
            if userControlledHTML:
                if 'User Controlled HTML' not in self.vulnerabilities:
                    self.vulnerabilities['User Controlled HTML'] = self.create_vuln_entry('User Controllable HTML Element Attribute (Potential XSS)', 'This check looks at user-supplied input in query string parameters and POST data to identify where certain HTML attribute values might be controlled. This provides hot-spot detection for XSS (cross-site scripting) that will require further review by a security analyst to determine exploitability.', "", "", "http://websecuritytool.codeplex.com/wikipage?title=Checks#user-controlled-html-attribute", 'Validate all input and sanitize output it before writing to any HTML attributes.', "")

                self.add_urls('User Controlled HTML', userControlledHTML)

            userControlledJS = userControlledJsScan(url, html)
            if userControlledJS:
                if 'User Controlled JS' not in self.vulnerabilities:
                    self.vulnerabilities['User Controlled JS'] = self.create_vuln_entry('User Controllable JavaScript Event (XSS)', 'This check looks at user-supplied input in query string parameters and POST data to identify where certain HTML attribute values might be controlled. This provides hot-spot detection for XSS (cross-site scripting) that will require further review by a security analyst to determine exploitability.', "", "", "http://websecuritytool.codeplex.com/wikipage?title=Checks#user-javascript-event", "Validate all input and sanitize output it before writing to any Javascript on* events.", "")

                self.add_urls('User Controlled JS', userControlledJS)

            userControlledOpenRedirect = userControlledOpenRedirectScan(url)
            if userControlledOpenRedirect:
                if 'User Controlled Open Redirect' not in self.vulnerabilities:
                    self.vulnerabilities['User Controlled Open Redirect'] = self.create_vuln_entry('Open Redirect', "Open redirects are one of the OWASP 2010 Top Ten self.vulnerabilities. This check looks at user-supplied input in query string parameters and POST data to identify where open redirects might be possible. Open redirects occur when an application allows user-supplied input (e.g. http://nottrusted.com) to control an offsite redirect. This is generally a pretty accurate way to find where 301 or 302 redirects could be exploited by spammers or phishing attacks. For example an attacker could supply a user with the following link: http://example.com/example.php?url=http://malicious.example.com.", "", "", "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html", "To avoid the open redirect vulnerability, parameters of the application script/program must be validated before sending 302 HTTP code (redirect) to the client browser. Implement safe redirect functionality that only redirects to relative URI's, or a list of trusted domains", "")

                self.add_urls('User Controlled Open Redirect', userControlledOpenRedirect)

            
            xaspnetVersion = XAspNetVersionScan(url)
            if xaspnetVersion:
                if 'X-AspNet-Version Response Header' not in self.vulnerabilities:
                    self.vulnerabilities['X-AspNet-Version Response Header'] = self.create_vuln_entry('X ASPNET X-AspNet-Version Response Header', 'Server leaks information via “X-AspNet-Version”/“X-AspNetMvc-Version” HTTP response header field(s).', 14, 'CWE CATEGORY: OWASP Top Ten 2013 Category A5 - Security Misconfiguration', 'https://www.troyhunt.com/shhh-dont-let-your-response-headers/', 'Configure the server so it will not return those headers.', "Low")

                self.add_urls('X-AspNet-Version Response Header', xaspnetVersion)


            xbackendServer = XBackendServerScan(url)
            if xbackendServer:
                if 'X Backend Version' not in self.vulnerabilities:
                    self.vulnerabilities['X Backend Version'] = self.create_vuln_entry('X-Backend-Server Header Information Leak', 'The server is leaking information pertaining to backend systems (such as hostnames or IP addresses). Armed with this information an attacker may be able to attack other systems or more directly/efficiently attack those systems.', 13, 'CWE-200: Exposure of Sensitive Information to an Unauthorized Actor', "", 'Ensure that your web server, application server, load balancer, etc. is configured to suppress X-Backend-Server headers.', "Low")

                self.add_urls('X Backend Version', xbackendServer)

            xChromeLogger = XChromeLoggerScan(url)
            if xChromeLogger:
                if 'X Chrome Logger' not in self.vulnerabilities:
                    self.vulnerabilities['X Chrome Logger'] = self.create_vuln_entry('X-ChromeLogger-Data (XCOLD) Header Information Leak', 'The server is leaking information through the X-ChromeLogger-Data (or X-ChromePhp-Data) response header. The content of such headers can be customized by the developer, however it is not uncommon to find: server file system locations, vhost declarations, etc.', 13, 'CWE-200: Exposure of Sensitive Information to an Unauthorized Actor', 'https://craig.is/writing/chrome-logger', 'Disable this functionality in Production when it might leak information that could be leveraged by an attacker. Alternatively ensure that use of the functionality is tied to a strong authorization check and only available to administrators or support personnel for troubleshooting purposes not general users.', "Medium")

                self.add_urls('X Chrome Logger', xChromeLogger)

            xContentType = XContentTypeScan(url)
            if xContentType:
                if 'X Content Type' not in self.vulnerabilities:
                    self.vulnerabilities['X Content Type'] = self.create_vuln_entry('X-Content-Type-Options Header Missing', 'The Anti-MIME-Sniffing header X-Content-Type-Options was not set to ’nosniff’. This allows older versions of Internet Explorer and Chrome to perform MIME-sniffing on the response body, potentially causing the response body to be interpreted and displayed as a content type other than the declared content type. Current (early 2014) and legacy versions of Firefox will use the declared content type (if one is set), rather than performing MIME-sniffing.', 15, 'CWE-693: Protection Mechanism Failure', 'http://msdn.microsoft.com/en-us/library/ie/gg622941%28v=vs.85%29.aspx', "Ensure that the application/web server sets the Content-Type header appropriately, and that it sets the X-Content-Type-Options header to 'nosniff' for all web pages. If possible, ensure that the end user uses a standards-compliant and modern web browser that does not perform MIME-sniffing at all, or that can be directed by the web application/web server to not perform MIME-sniffing.", "Low")

                self.add_urls('X Content Type', xContentType)


            xDebug = XDebugScan(url)
            if xDebug:
                if 'X Debug' not in self.vulnerabilities:
                    self.vulnerabilities['X Debug'] = self.create_vuln_entry('X-Debug-Token Information Leak', 'The response contained an X-Debug-Token or X-Debug-Token-Link header. This indicates that Symfony’s Profiler may be in use and exposing sensitive data.', 13, 'CWE-200: Exposure of Sensitive Information to an Unauthorized Actor', 'https://symfony.com/doc/current/cookbook/profiler/profiling_data.html', "Limit access to Symfony's Profiler, either via authentication/authorization or limiting inclusion of the header to specific clients (by IP, etc.).", "Low")

                self.add_urls('X Debug', xDebug)


            xPoweredBy = XPoweredByScan(url)
            if xPoweredBy:
                if 'X Powered By' not in self.vulnerabilities:
                    self.vulnerabilities['X Powered By'] = self.create_vuln_entry("Server Leaks Information via 'X-Powered-By' HTTP Response Header Field(s)", "The web/application server is leaking information via one or more “X-Powered-By” HTTP response headers. Access to such information may facilitate attackers identifying other frameworks/components your web application is reliant upon and the self.vulnerabilities such components may be subject to.", 13, 'CWE-200: Exposure of Sensitive Information to an Unauthorized Actor', 'http://blogs.msdn.com/b/varunm/archive/2013/04/23/remove-unwanted-http-response-headers.aspx', "Ensure that your web server, application server, load balancer, etc. is configured to suppress 'X-Powered-By' headers.", "Low")

                self.add_urls('X Powered By', xPoweredBy)

            susComment = hasSusComment(url)
            if susComment:
                if 'Suspicious Comment' not in self.vulnerabilities:
                    self.vulnerabilities['Suspicious Comment'] = self.create_vuln_entry('Information Disclosure - Suspicious Comments', "The response appears to contain suspicious comments which may help an attacker. Note: Matches made within script blocks or files are against the entire content not only comments.", 13, "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor", "", "Remove all comments that return information that may help an attacker and fix any underlying problems they refer to.", "Informational")

                self.add_urls('Suspicious Comment', susComment)

            cacheControlDirective = badCacheControl(url)
            if cacheControlDirective:
                if 'Cache Control' not in self.vulnerabilities:
                    self.vulnerabilities['Cache Control'] = self.create_vuln_entry('Re-examine Cache-control Directives', "The cache-control header has not been set properly or is missing, allowing the browser and proxies to cache content. For static assets like css, js, or image files this might be intended, however, the resources should be reviewed to ensure that no sensitive content will be cached.", 13, "CWE-525: Use of Web Browser Cache Containing Sensitive Information", "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html#web-content-caching", "For secure content, ensure the cache-control HTTP header is set with 'no-cache, no-store, must-revalidate'. If an asset should be cached consider setting the directives 'public, max-age, immutable'.", "Informational")

                self.add_urls('Cache Control', cacheControlDirective)

            notHttpCookie = httpOnlyScan(cookies, url)
            if notHttpCookie:
                if 'HttpOnly' not in self.vulnerabilities:
                    self.vulnerabilities['HttpOnly'] = self.create_vuln_entry('Cookie No HttpOnly Flag', 'A cookie has been set without the HttpOnly flag, which means that the cookie can be accessed by JavaScript. If a malicious script can be run on this page then the cookie will be accessible and can be transmitted to another site. If this is a session cookie then session hijacking may be possible.', 13, "CWE-1004: Sensitive Cookie Without 'HttpOnly' Flag", "https://owasp.org/www-community/HttpOnly", 'Ensure that the HttpOnly flag is set for all cookies.', 'Low')

                self.add_urls('HttpOnly', notHttpCookie)

            looselyScopedCookie = looselyScopedScan(cookies, url)
            if looselyScopedCookie:
                if 'LooselyScopedCookie' not in self.vulnerabilities:
                    self.vulnerabilities['LooselyScopedCookie'] = self.create_vuln_entry('Loosely Scoped Cookie', "Cookies can be scoped by domain or path. This check is only concerned with domain scope.The domain scope applied to a cookie determines which domains can access it. For example, a cookie can be scoped strictly to a subdomain e.g. www.nottrusted.com, or loosely scoped to a parent domain e.g. nottrusted.com. In the latter case, any subdomain of nottrusted.com can access the cookie. Loosely scoped cookies are common in mega-applications like google.com and live.com. Cookies set from a subdomain like app.foo.bar are transmitted only to that domain by the browser. However, cookies scoped to a parent-level domain may be transmitted to the parent, or any subdomain of the parent.", 15, 'CWE-565: Reliance on Cookies without Validation and Integrity Checking', "https://tools.ietf.org/html/rfc6265#section-4.1", "Always scope cookies to a FQDN (Fully Qualified Domain Name).", "Informational")

                self.add_urls("LooselyScopedCookie", looselyScopedCookie)

            secureFlagCookie = secureFlagScan(cookies, url)
            if secureFlagCookie:
                if 'SecureFlagCookie' not in self.vulnerabilities:
                    self.vulnerabilities['SecureFlagCookie'] = self.create_vuln_entry("Cookie Without Secure Flag", "A cookie has been set without the secure flag, which means that the cookie can be accessed via unencrypted connections.", 13, "CWE-614: Sensitive Cookie in HTTPS Session Without 'Secure' Attribute", "https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes.html", "Whenever a cookie contains sensitive information or is a session token, then it should always be passed using an encrypted channel. Ensure that the secure flag is set for cookies containing such sensitive information.", "Low")

                self.add_urls("SecureFlagCookie", secureFlagCookie)


            driver.quit()
            # self.vulnerabilities[url] = retval
        except Exception as e:
            print('error while scanning url {}: {}'.format(url, e.with_traceback()))

    # def reformat_data(retval):
        

    @app.route('/scan', methods=['POST'])
    def process_data():
        # Get JSON data from the request
        scanner = Scanner()
        data = request.get_json()
        try:
            # Check if data is not None and it has 'input' key
            if data and 'input' in data:
                input_data = data['input']
                if(not url_ok(input_data)):
                    return jsonify({'error': 'Invalid url'}), 400

                directoryList = [input_data]
                # Default depth is 1 and default max_retries is 3
                newFiles = listDirectory(input_data)
                for file in newFiles:
                    directoryList.append(file)

                # manager = multiprocessing.Manager()
                # self.vulnerabilities = manager.dict()

                # with multiprocessing.Pool(processes=4) as pool: # create a Pool with 4 processes
                #     pool.starmap(self.execute_scans, [(url) for url in directoryList])
                vulnerabilities = {}
                for url in directoryList:
                    try:
                        scanner.execute_scans(url)
                
                    except Exception as e:
                        traceback.print_exc()

                output = {
                    'alerts': dict(scanner.vulnerabilities)
                }
                return jsonify(output), 200 
            else:
                return jsonify({'error': 'Invalid request'}), 400
        except Exception as e:
            traceback.print_exc()
            return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)



