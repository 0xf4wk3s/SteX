import os
from typing import List, Optional

from models import Password, Cookie, AutoFill, CreditCard, SystemInfo
from .base import BaseParser


class MetaParser(BaseParser):
    """META Stealer - similar to Redline with minor differences."""
    STEALER_NAME = "META"

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

        for cdir in ('Cookies', 'cookies'):
            cookie_path = os.path.join(self.log_dir, cdir)
            if os.path.isdir(cookie_path):
                for f in os.listdir(cookie_path):
                    if f.endswith('.txt'):
                        content = self._read_file(os.path.join(cookie_path, f))
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

        for adir in ('AutoFill', 'autofill'):
            af_path = os.path.join(self.log_dir, adir)
            if os.path.isdir(af_path):
                for f in os.listdir(af_path):
                    if f.endswith('.txt'):
                        content = self._read_file(os.path.join(af_path, f))
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
        files = self._find_all_files(self.CC_FILES)
        for fpath in files:
            content = self._read_file(fpath)
            if content:
                cards.extend(self._parse_creditcard_blocks(content))
        return cards

    def parse_system_info(self) -> Optional[SystemInfo]:
        fpath = self._find_file(self.SYSINFO_FILES)
        if not fpath:
            return None
        content = self._read_file(fpath)
        if not content:
            return None
        return self._parse_system_info_kv(content)
