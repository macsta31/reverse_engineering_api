import hashlib
import re
import time
from abc import ABC, abstractmethod
from bs4 import BeautifulSoup

# DOES NOT WORK AS OF YET

import requests

def get_helper():
    pass

class AlertBuilder:
    pass

class HttpMessage:
    pass

class User:
    def __init__(self, id, name):
        self.id = id
        self.name = name

class PluginPassiveScanner(ABC):
    @abstractmethod
    def scan_http_response_receive(self, msg, source):
        pass

class UsernameIdorScanRule(PluginPassiveScanner):
    DEFAULT_USERNAMES = ["Admin", "admin"]

    def __init__(self):
        self.payload_provider = self.DEFAULT_USERNAMES

    def get_users(self):
        users_list = [User(-1, payload) for payload in self.payload_provider]
        users_list.extend(get_helper().get_users())
        return users_list

    def scan_http_response_receive(self, msg, id, source):
        scan_users = self.get_users()
        if not scan_users:
            print("There does not appear to be any contexts with configured users.")
            return

        start = time.time()

        response = msg.get_response_header().to_string() + msg.get_response_body().to_string()

        for user in scan_users:
            username = user.get_name()
            hashes = {
                "MD5": hashlib.md5(username.encode()).hexdigest(),
                "SHA1": hashlib.sha1(username.encode()).hexdigest(),
                "SHA256": hashlib.sha256(username.encode()).hexdigest()
                # Add other hash types here if necessary
            }

            for hash_type, hash_value in hashes.items():
                if self.match(response, re.compile(hash_value, re.IGNORECASE)):
                    return "CWE-284: Improper Access Control"

        print(f"Scan of record {id} took {time.time() - start} ms")


    def match(self, contents, pattern):
        match = pattern.search(contents)
        if match:
            return match.group()
        return None
    

def scan(url):
    scanner = UsernameIdorScanRule()
    source = BeautifulSoup(requests.get(url).content, 'html.parser')
    print(scanner.scan_http_response_receive(requests.get(url)), source)
