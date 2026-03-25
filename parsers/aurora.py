from typing import List, Optional

from models import Password, Cookie, AutoFill, CreditCard, SystemInfo
from .base import BaseParser


class AuroraParser(BaseParser):
    STEALER_NAME = "Aurora"

    def parse_passwords(self) -> List[Password]:
        passwords = []
        files = self._find_all_files(['passwords.txt', 'Passwords.txt'])
        for fpath in files:
            content = self._read_file(fpath)
            if content:
                passwords.extend(self._parse_password_blocks(content))
        return passwords

    def parse_cookies(self) -> List[Cookie]:
        cookies = []
        files = self._find_all_files(['cookies.txt', 'Cookies.txt'])
        for fpath in files:
            content = self._read_file(fpath)
            if content and '\t' in content:
                cookies.extend(self._parse_cookie_netscape(content))
            elif content:
                cookies.extend(self._parse_cookie_blocks(content))
        return cookies

    def parse_autofills(self) -> List[AutoFill]:
        autofills = []
        files = self._find_all_files(['autofills.txt', 'autofill.txt', 'AutoFill.txt'])
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
        fpath = self._find_file(['system.txt', 'System.txt', 'system_info.txt'])
        if not fpath:
            return None
        content = self._read_file(fpath)
        if not content:
            return None
        return self._parse_system_info_kv(content)
