import os
from typing import List, Optional

from models import Password, Cookie, AutoFill, CreditCard, SystemInfo
from .base import BaseParser


class RedlineParser(BaseParser):
    STEALER_NAME = "Redline"

    def parse_passwords(self) -> List[Password]:
        passwords = []
        files = self._find_all_files(['Passwords.txt', 'passwords.txt'])
        for fpath in files:
            content = self._read_file(fpath)
            if content:
                passwords.extend(self._parse_password_blocks(content))
        return passwords

    def parse_cookies(self) -> List[Cookie]:
        cookies = []

        cookie_dir = os.path.join(self.log_dir, 'Cookies')
        if os.path.isdir(cookie_dir):
            for f in os.listdir(cookie_dir):
                if f.endswith('.txt'):
                    content = self._read_file(os.path.join(cookie_dir, f))
                    if content and '\t' in content:
                        cookies.extend(self._parse_cookie_netscape(content))
                    elif content:
                        cookies.extend(self._parse_cookie_blocks(content))

        files = self._find_all_files(['Cookies.txt', 'cookies.txt'])
        for fpath in files:
            content = self._read_file(fpath)
            if content and '\t' in content:
                cookies.extend(self._parse_cookie_netscape(content))
            elif content:
                cookies.extend(self._parse_cookie_blocks(content))

        return cookies

    def parse_autofills(self) -> List[AutoFill]:
        autofills = []

        af_dir = os.path.join(self.log_dir, 'AutoFill')
        if os.path.isdir(af_dir):
            for f in os.listdir(af_dir):
                if f.endswith('.txt'):
                    content = self._read_file(os.path.join(af_dir, f))
                    if content:
                        autofills.extend(self._parse_autofill_blocks(content))

        files = self._find_all_files(['AutoFill.txt', 'autofill.txt'])
        for fpath in files:
            content = self._read_file(fpath)
            if content:
                autofills.extend(self._parse_autofill_blocks(content))

        return autofills

    def parse_credit_cards(self) -> List[CreditCard]:
        cards = []

        cc_dir = os.path.join(self.log_dir, 'CreditCards')
        if os.path.isdir(cc_dir):
            for f in os.listdir(cc_dir):
                if f.endswith('.txt'):
                    content = self._read_file(os.path.join(cc_dir, f))
                    if content:
                        cards.extend(self._parse_creditcard_blocks(content))

        files = self._find_all_files(self.CC_FILES)
        for fpath in files:
            content = self._read_file(fpath)
            if content:
                cards.extend(self._parse_creditcard_blocks(content))

        return cards

    def parse_system_info(self) -> Optional[SystemInfo]:
        fpath = self._find_file(['UserInformation.txt', 'SystemInfo.txt'])
        if not fpath:
            return None
        content = self._read_file(fpath)
        if not content:
            return None
        return self._parse_system_info_kv(content)
