import os
import re
from abc import ABC, abstractmethod
from typing import List, Optional

from models import (
    Password, Cookie, AutoFill, CreditCard, SystemInfo,
    CryptoWallet, Screenshot, GrabbedFile, VictimLog
)


class BaseParser(ABC):
    STEALER_NAME = "Unknown"

    PASSWORD_FILES = ['passwords.txt', 'Passwords.txt', 'password.txt']
    COOKIE_FILES = ['cookies.txt', 'Cookies.txt', 'cookie.txt']
    AUTOFILL_FILES = ['autofill.txt', 'AutoFill.txt', 'autofills.txt']
    CC_FILES = ['CC.txt', 'CreditCards.txt', 'cards.txt', 'credit_cards.txt']
    SYSINFO_FILES = [
        'UserInformation.txt', 'System Info.txt', 'information.txt',
        'system.txt', 'system_info.txt', 'SystemInfo.txt'
    ]
    SCREENSHOT_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.bmp'}
    WALLET_NAMES = [
        'Exodus', 'Electrum', 'Atomic', 'Jaxx', 'Ethereum', 'Bitcoin',
        'Coinomi', 'Guarda', 'Wasabi', 'Metamask', 'Phantom', 'TronLink',
        'BinanceChain', 'Ronin', 'Brave', 'Nifty', 'Math',
        'Trust', 'TokenPocket', 'BitKeep', 'Keplr', 'Solflare'
    ]

    def __init__(self, log_dir: str):
        self.log_dir = log_dir
        self.errors: List[str] = []

    def parse(self) -> VictimLog:
        victim = VictimLog(
            folder_name=os.path.basename(self.log_dir),
            stealer_type=self.STEALER_NAME
        )

        parse_methods = [
            ('passwords', self.parse_passwords),
            ('cookies', self.parse_cookies),
            ('autofills', self.parse_autofills),
            ('credit_cards', self.parse_credit_cards),
            ('wallets', self.parse_wallets),
            ('screenshots', self.parse_screenshots),
            ('grabbed_files', self.parse_grabbed_files),
        ]

        for attr, method in parse_methods:
            try:
                setattr(victim, attr, method())
            except Exception as e:
                self.errors.append(f"{attr} parsing error: {e}")

        try:
            victim.system_info = self.parse_system_info()
        except Exception as e:
            self.errors.append(f"system_info parsing error: {e}")

        return victim

    @abstractmethod
    def parse_passwords(self) -> List[Password]:
        pass

    @abstractmethod
    def parse_cookies(self) -> List[Cookie]:
        pass

    @abstractmethod
    def parse_autofills(self) -> List[AutoFill]:
        pass

    @abstractmethod
    def parse_credit_cards(self) -> List[CreditCard]:
        pass

    @abstractmethod
    def parse_system_info(self) -> Optional[SystemInfo]:
        pass

    def parse_wallets(self) -> List[CryptoWallet]:
        wallets = []
        wallet_dirs = ['Wallets', 'wallets', 'Crypto', 'crypto']

        for wdir in wallet_dirs:
            wallet_path = os.path.join(self.log_dir, wdir)
            if not os.path.isdir(wallet_path):
                continue
            for root, dirs, files in os.walk(wallet_path):
                for f in files:
                    fpath = os.path.join(root, f)
                    rel = os.path.relpath(fpath, wallet_path)
                    wallets.append(CryptoWallet(
                        wallet_type=self._detect_wallet_type(rel),
                        wallet_name=f,
                        path=rel
                    ))

        return wallets

    def parse_screenshots(self) -> List[Screenshot]:
        screenshots = []

        for f in os.listdir(self.log_dir):
            if any(f.lower().endswith(ext) for ext in self.SCREENSHOT_EXTENSIONS):
                if any(kw in f.lower() for kw in ('screenshot', 'screen', 'desktop', 'capture')):
                    screenshots.append(Screenshot(
                        filename=f,
                        path=os.path.join(self.log_dir, f)
                    ))

        for sdir in ('Screenshots', 'screenshots', 'Screen'):
            ss_path = os.path.join(self.log_dir, sdir)
            if not os.path.isdir(ss_path):
                continue
            for f in os.listdir(ss_path):
                if any(f.lower().endswith(ext) for ext in self.SCREENSHOT_EXTENSIONS):
                    screenshots.append(Screenshot(
                        filename=f,
                        path=os.path.join(ss_path, f)
                    ))

        return screenshots

    def parse_grabbed_files(self) -> List[GrabbedFile]:
        grabbed = []
        for fdir in ('FileGrabber', 'Files', 'files', 'Grabber'):
            fpath = os.path.join(self.log_dir, fdir)
            if not os.path.isdir(fpath):
                continue
            for root, dirs, files in os.walk(fpath):
                for f in files:
                    full_path = os.path.join(root, f)
                    try:
                        size = os.path.getsize(full_path)
                    except OSError:
                        size = 0
                    grabbed.append(GrabbedFile(
                        filename=f,
                        path=os.path.relpath(full_path, self.log_dir),
                        size=size
                    ))
        return grabbed

    # ── Helper methods ────────────────────────────────────────────────

    def _read_file(self, filepath: str) -> str:
        if not os.path.isfile(filepath):
            return ""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception:
            try:
                with open(filepath, 'r', encoding='latin-1', errors='ignore') as f:
                    return f.read()
            except Exception:
                return ""

    def _find_file(self, filenames: List[str], subdir: str = None) -> Optional[str]:
        search_dir = os.path.join(self.log_dir, subdir) if subdir else self.log_dir
        if not os.path.isdir(search_dir):
            return None

        existing = {f.lower(): f for f in os.listdir(search_dir) if os.path.isfile(os.path.join(search_dir, f))}
        for fname in filenames:
            if fname.lower() in existing:
                return os.path.join(search_dir, existing[fname.lower()])

        return None

    def _find_all_files(self, filenames: List[str]) -> List[str]:
        target_names = {f.lower() for f in filenames}
        found = []
        for root, dirs, files in os.walk(self.log_dir):
            for f in files:
                if f.lower() in target_names:
                    found.append(os.path.join(root, f))
        return found

    def _parse_password_blocks(self, content: str) -> List[Password]:
        passwords = []
        blocks = re.split(r'\n\s*\n|\n={3,}\n|\n-{3,}\n|\n\*{3,}\n', content)

        for block in blocks:
            block = block.strip()
            if not block:
                continue

            pw = Password()
            for line in block.split('\n'):
                line = line.strip()
                if not line:
                    continue
                lower = line.lower()
                if lower.startswith(('url:', 'host:')):
                    pw.url = line.split(':', 1)[1].strip()
                elif lower.startswith(('login:', 'username:', 'user:')):
                    pw.username = line.split(':', 1)[1].strip()
                elif lower.startswith(('password:', 'pass:')):
                    pw.password = line.split(':', 1)[1].strip()
                elif lower.startswith(('application:', 'soft:', 'browser:', 'app:')):
                    pw.application = line.split(':', 1)[1].strip()

            if pw.url or pw.username or pw.password:
                passwords.append(pw)

        return passwords

    def _parse_cookie_netscape(self, content: str) -> List[Cookie]:
        cookies = []
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split('\t')
            if len(parts) >= 7:
                cookies.append(Cookie(
                    host=parts[0],
                    is_http_only=parts[1].upper() == 'TRUE',
                    path=parts[2],
                    is_secure=parts[3].upper() == 'TRUE',
                    expires=parts[4],
                    name=parts[5],
                    value='\t'.join(parts[6:])
                ))
        return cookies

    def _parse_cookie_blocks(self, content: str) -> List[Cookie]:
        cookies = []
        blocks = re.split(r'\n\s*\n|\n={3,}\n|\n-{3,}\n', content)

        for block in blocks:
            block = block.strip()
            if not block:
                continue
            cookie = Cookie()
            for line in block.split('\n'):
                line = line.strip()
                lower = line.lower()
                if lower.startswith(('host:', 'domain:')):
                    cookie.host = line.split(':', 1)[1].strip()
                elif lower.startswith('name:'):
                    cookie.name = line.split(':', 1)[1].strip()
                elif lower.startswith('value:'):
                    cookie.value = line.split(':', 1)[1].strip()
                elif lower.startswith('path:'):
                    cookie.path = line.split(':', 1)[1].strip()
                elif lower.startswith(('expires:', 'expiry:')):
                    cookie.expires = line.split(':', 1)[1].strip()
                elif lower.startswith('secure:'):
                    cookie.is_secure = 'true' in line.split(':', 1)[1].strip().lower()

            if cookie.host or cookie.name:
                cookies.append(cookie)

        return cookies

    def _parse_autofill_blocks(self, content: str) -> List[AutoFill]:
        autofills = []
        blocks = re.split(r'\n\s*\n|\n={3,}\n|\n-{3,}\n', content)

        for block in blocks:
            block = block.strip()
            if not block:
                continue
            af = AutoFill()
            for line in block.split('\n'):
                line = line.strip()
                lower = line.lower()
                if lower.startswith(('name:', 'field:')):
                    af.name = line.split(':', 1)[1].strip()
                elif lower.startswith('value:'):
                    af.value = line.split(':', 1)[1].strip()
            if af.name or af.value:
                autofills.append(af)

        return autofills

    def _parse_creditcard_blocks(self, content: str) -> List[CreditCard]:
        cards = []
        blocks = re.split(r'\n\s*\n|\n={3,}\n|\n-{3,}\n', content)

        for block in blocks:
            block = block.strip()
            if not block:
                continue
            card = CreditCard()
            for line in block.split('\n'):
                line = line.strip()
                lower = line.lower()
                if lower.startswith(('number:', 'card number:', 'card:')):
                    card.number = line.split(':', 1)[1].strip()
                elif lower.startswith(('holder:', 'cardholder:')):
                    card.holder = line.split(':', 1)[1].strip()
                elif lower.startswith(('exp month:', 'expmonth:', 'month:')):
                    card.exp_month = line.split(':', 1)[1].strip()
                elif lower.startswith(('exp year:', 'expyear:', 'year:')):
                    card.exp_year = line.split(':', 1)[1].strip()
                elif lower.startswith(('exp:', 'expiry:', 'expires:')):
                    val = line.split(':', 1)[1].strip()
                    if '/' in val:
                        parts = val.split('/')
                        card.exp_month = parts[0].strip()
                        card.exp_year = parts[1].strip() if len(parts) > 1 else ""
                elif lower.startswith(('type:', 'card type:')):
                    card.card_type = line.split(':', 1)[1].strip()

            if card.number:
                if not card.card_type:
                    card.card_type = self._detect_card_type(card.number)
                cards.append(card)

        return cards

    def _parse_system_info_kv(self, content: str) -> SystemInfo:
        info = SystemInfo()
        kv_map = {
            ('ip', 'ip address', 'public ip'): 'ip',
            ('country', 'location'): 'country',
            ('city',): 'city',
            ('zip', 'zip code', 'postal'): 'zip_code',
            ('hwid', 'machine id', 'machineid', 'hardware id'): 'hwid',
            ('os', 'operating system', 'windows'): 'os',
            ('cpu', 'processor'): 'cpu',
            ('gpu', 'videocard', 'video card', 'graphics'): 'gpu',
            ('ram', 'memory', 'total ram'): 'ram',
            ('screen', 'screen resolution', 'resolution', 'display'): 'screen_resolution',
            ('computer', 'machine name', 'computername', 'pc name', 'hostname', 'computer name'): 'machine_name',
            ('username', 'user', 'current user'): 'username',
            ('language', 'layout', 'keyboard', 'keyboard languages'): 'language',
            ('timezone', 'time zone'): 'timezone',
        }

        for line in content.split('\n'):
            line = line.strip()
            if ':' not in line:
                continue
            key, _, value = line.partition(':')
            key = key.strip().lower()
            value = value.strip()
            if not value:
                continue

            for keys, attr in kv_map.items():
                if key in keys:
                    setattr(info, attr, value)
                    break

        return info

    def _detect_wallet_type(self, path: str) -> str:
        path_lower = path.lower()
        for wallet in self.WALLET_NAMES:
            if wallet.lower() in path_lower:
                return wallet
        return "Unknown"

    def _detect_card_type(self, number: str) -> str:
        number = re.sub(r'\D', '', number)
        if not number:
            return ''
        if number.startswith('4'):
            return 'Visa'
        elif number.startswith(('51', '52', '53', '54', '55')):
            return 'Mastercard'
        elif number.startswith(('34', '37')):
            return 'Amex'
        elif number.startswith(('6011', '65')):
            return 'Discover'
        return ''
