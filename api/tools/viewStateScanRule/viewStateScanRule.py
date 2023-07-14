import base64

# DOES NOT WORK AS OF YET

class ViewstateVersion:
    # Class not provided in the initial code, placeholder for now
    pass

class Viewstate:
    def __init__(self, s, was_split=False):
        self.base64_value = None
        self.decoded_value = None
        self.is_valid = False
        self.is_split = False
        self.version = ViewstateVersion()
        
        if s is not None:
            self.is_split = was_split
            self.base64_value = s.get('value') if isinstance(s, dict) else s  # Adjusted for Python dictionary
            try:
                self.decoded_value = self.base64_decode(self.base64_value)
                self.is_valid = True
                self.set_version()
            except ValueError:
                # Incorrect Base64 value.
                pass

    def is_valid(self):
        return self.is_valid and (self.get_version() != ViewstateVersion.UNKNOWN)

    def is_split(self):
        return self.is_split

    def has_MAC_test1(self):
        l = len(self.decoded_value)
        last_chars_before_mac = self.decoded_value[l - 22: l - 20]

        if self.version == ViewstateVersion.ASPNET2:
            return last_chars_before_mac == "dd"

        if self.version == ViewstateVersion.ASPNET1:
            return last_chars_before_mac == ">>"

        return True

    def has_MAC_test2(self):
        l = len(self.decoded_value)
        last_chars_before_mac = self.decoded_value[l - 2:]

        if self.version == ViewstateVersion.ASPNET2:
            return last_chars_before_mac != "dd"

        if self.version == ViewstateVersion.ASPNET1:
            return last_chars_before_mac != ">>"

        return True

    def get_decoded_value(self):
        return self.decoded_value

    def is_latest_asp_net_version(self):
        return self.get_version().is_latest()

    def get_version(self):
        return self.version

    def set_version(self):
        self.version = ViewstateVersion.UNKNOWN

        if self.base64_value.startswith("/w"):
            self.version = ViewstateVersion.ASPNET2

        if self.base64_value.startswith("dD"):
            self.version = ViewstateVersion.ASPNET1

    def get_object_tree(self):
        raise Exception("Not implemented (yet)")

    def get_state_bag_tree(self):
        raise Exception("Not implemented (yet)")

    def get_serialized_components_tree(self):
        raise Exception("Not implemented (yet)")

    @staticmethod
    def base64_decode(value):
        try:
            decoded_bytes = base64.b64decode(value)
        except (ValueError, TypeError):
            try:
                decoded_bytes = base64.b64decode(value[:-1])
            except (ValueError, TypeError):
                raise ValueError('Invalid base64 value.')

        return decoded_bytes.decode('utf-8')
