import os
from typing import Optional

from .base import BaseParser
from .redline import RedlineParser
from .raccoon import RaccoonParser
from .vidar import VidarParser
from .meta_stealer import MetaParser
from .aurora import AuroraParser
from .risepro import RiseProParser
from .lumma import LummaParser
from .stealc import StealCParser


class GenericParser(BaseParser):
    """Fallback parser that tries all common formats."""
    STEALER_NAME = "Generic"

    def parse_passwords(self):
        passwords = []
        for fpath in self._find_all_files(self.PASSWORD_FILES):
            content = self._read_file(fpath)
            if content:
                passwords.extend(self._parse_password_blocks(content))
        return passwords

    def parse_cookies(self):
        cookies = []
        for fpath in self._find_all_files(self.COOKIE_FILES):
            content = self._read_file(fpath)
            if content and '\t' in content:
                cookies.extend(self._parse_cookie_netscape(content))
            elif content:
                cookies.extend(self._parse_cookie_blocks(content))
        return cookies

    def parse_autofills(self):
        autofills = []
        for fpath in self._find_all_files(self.AUTOFILL_FILES):
            content = self._read_file(fpath)
            if content:
                autofills.extend(self._parse_autofill_blocks(content))
        return autofills

    def parse_credit_cards(self):
        cards = []
        for fpath in self._find_all_files(self.CC_FILES):
            content = self._read_file(fpath)
            if content:
                cards.extend(self._parse_creditcard_blocks(content))
        return cards

    def parse_system_info(self):
        fpath = self._find_file(self.SYSINFO_FILES)
        if not fpath:
            return None
        content = self._read_file(fpath)
        return self._parse_system_info_kv(content) if content else None


PARSER_MAP = {
    'Redline': RedlineParser,
    'Raccoon': RaccoonParser,
    'Vidar': VidarParser,
    'META': MetaParser,
    'Aurora': AuroraParser,
    'RisePro': RiseProParser,
    'Lumma': LummaParser,
    'StealC': StealCParser,
    'Generic': GenericParser,
}


class StealerDetector:
    @staticmethod
    def detect(log_dir: str) -> str:
        if not os.path.isdir(log_dir):
            return 'Unknown'

        files_lower = set()
        dirs_lower = set()

        for item in os.listdir(log_dir):
            full = os.path.join(log_dir, item)
            if os.path.isfile(full):
                files_lower.add(item.lower())
            elif os.path.isdir(full):
                dirs_lower.add(item.lower())

        if 'userinformation.txt' in files_lower:
            if 'passwords.txt' in files_lower or 'cookies' in dirs_lower:
                return 'Redline'

        if 'system info.txt' in files_lower and 'passwords.txt' in files_lower:
            if 'cookies' not in dirs_lower and 'autofill' not in dirs_lower:
                return 'Raccoon'

        if 'information.txt' in files_lower:
            return 'Vidar'

        if 'autofills.txt' in files_lower and 'system.txt' in files_lower:
            return 'Aurora'

        if 'system_info.txt' in files_lower and 'passwords.txt' in files_lower:
            return 'StealC'

        if 'passwords.txt' in files_lower and ('browsers' in dirs_lower or 'browser' in dirs_lower):
            return 'RisePro'

        if 'system info.txt' in files_lower:
            return 'Lumma'

        if 'passwords.txt' in files_lower and ('cookies' in dirs_lower or 'autofill' in dirs_lower):
            return 'META'

        if any(f in files_lower for f in ('passwords.txt', 'password.txt', 'cookies.txt')):
            return 'Generic'

        return 'Unknown'


def get_parser(stealer_type: str, log_dir: str) -> BaseParser:
    parser_cls = PARSER_MAP.get(stealer_type, GenericParser)
    return parser_cls(log_dir)
