from dataclasses import dataclass, field
from typing import Optional, List


@dataclass
class Password:
    url: str = ""
    username: str = ""
    password: str = ""
    application: str = ""


@dataclass
class Cookie:
    host: str = ""
    name: str = ""
    value: str = ""
    path: str = "/"
    expires: str = ""
    is_secure: bool = False
    is_http_only: bool = False


@dataclass
class AutoFill:
    name: str = ""
    value: str = ""


@dataclass
class CreditCard:
    number: str = ""
    holder: str = ""
    exp_month: str = ""
    exp_year: str = ""
    card_type: str = ""


@dataclass
class SystemInfo:
    ip: str = ""
    country: str = ""
    city: str = ""
    zip_code: str = ""
    hwid: str = ""
    os: str = ""
    cpu: str = ""
    gpu: str = ""
    ram: str = ""
    screen_resolution: str = ""
    machine_name: str = ""
    username: str = ""
    language: str = ""
    timezone: str = ""
    installed_software: List[str] = field(default_factory=list)
    running_processes: List[str] = field(default_factory=list)


@dataclass
class CryptoWallet:
    wallet_type: str = ""
    wallet_name: str = ""
    address: str = ""
    path: str = ""


@dataclass
class GrabbedFile:
    filename: str = ""
    path: str = ""
    size: int = 0


@dataclass
class Screenshot:
    filename: str = ""
    path: str = ""


@dataclass
class VictimLog:
    folder_name: str = ""
    stealer_type: str = "Unknown"
    passwords: List[Password] = field(default_factory=list)
    cookies: List[Cookie] = field(default_factory=list)
    autofills: List[AutoFill] = field(default_factory=list)
    credit_cards: List[CreditCard] = field(default_factory=list)
    system_info: Optional[SystemInfo] = None
    wallets: List[CryptoWallet] = field(default_factory=list)
    screenshots: List[Screenshot] = field(default_factory=list)
    grabbed_files: List[GrabbedFile] = field(default_factory=list)


@dataclass
class ParseResult:
    filename: str = ""
    stealer_type: str = "Unknown"
    victims: List[VictimLog] = field(default_factory=list)
    total_passwords: int = 0
    total_cookies: int = 0
    total_autofills: int = 0
    total_cards: int = 0
    total_wallets: int = 0
    total_screenshots: int = 0
    total_files: int = 0
    errors: List[str] = field(default_factory=list)

    def calculate_totals(self):
        self.total_passwords = sum(len(v.passwords) for v in self.victims)
        self.total_cookies = sum(len(v.cookies) for v in self.victims)
        self.total_autofills = sum(len(v.autofills) for v in self.victims)
        self.total_cards = sum(len(v.credit_cards) for v in self.victims)
        self.total_wallets = sum(len(v.wallets) for v in self.victims)
        self.total_screenshots = sum(len(v.screenshots) for v in self.victims)
        self.total_files = sum(len(v.grabbed_files) for v in self.victims)
