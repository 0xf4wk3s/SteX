"""Automatic detection of high-value findings in parsed stealer logs."""
import re
from dataclasses import dataclass, field
from typing import List
from models import Password, ParseResult


@dataclass
class HighlightItem:
    category: str
    label: str
    url: str
    username: str
    password: str
    archive: str = ""
    victim: str = ""


CATEGORIES = {
    'banking': {
        'label': 'Banking',
        'color': 'red',
        'icon': 'M3 10h18M7 15h1m4 0h1m-7 4h12a3 3 0 003-3V8a3 3 0 00-3-3H6a3 3 0 00-3 3v8a3 3 0 003 3z',
        'patterns': [
            'paypal', 'bank', 'chase', 'wellsfargo', 'bankofamerica', 'hsbc',
            'barclays', 'citibank', 'capitalone', 'revolut', 'wise.com',
            'transferwise', 'ziraatbank', 'garanti', 'akbank', 'isbank',
            'yapikredi', 'halkbank', 'vakifbank', 'enpara', 'papara',
            'stripe.com', 'square.com', 'payoneer',
        ],
    },
    'crypto': {
        'label': 'Crypto Exchange',
        'color': 'amber',
        'icon': 'M12 8c-1.657 0-3 .895-3 2s1.343 2 3 2 3 .895 3 2-1.343 2-3 2m0-8c1.11 0 2.08.402 2.599 1M12 8V7m0 1v8m0 0v1m0-1c-1.11 0-2.08-.402-2.599-1M21 12a9 9 0 11-18 0 9 9 0 0118 0z',
        'patterns': [
            'binance', 'coinbase', 'kraken', 'bybit', 'okx.com', 'kucoin',
            'gate.io', 'bitfinex', 'gemini', 'crypto.com', 'ftx.com',
            'bitstamp', 'bittrex', 'huobi', 'mexc', 'blockchain.com',
            'exodus', 'metamask', 'phantom', 'uniswap', 'opensea',
            'paribu', 'btcturk', 'bitexen',
        ],
    },
    'admin': {
        'label': 'Admin Panel',
        'color': 'purple',
        'icon': 'M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.066 2.573c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.573 1.066c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.066-2.573c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z M15 12a3 3 0 11-6 0 3 3 0 016 0z',
        'patterns': [
            '/admin', '/wp-admin', '/cpanel', '/whm', '/plesk',
            '/phpmyadmin', '/adminer', '/manager', '/dashboard/admin',
            '/webmin', '/directadmin', '/panel', ':2083', ':2087',
            '/administrator', '/wp-login', 'admin.', 'panel.',
        ],
    },
    'email': {
        'label': 'Email Provider',
        'color': 'cyan',
        'icon': 'M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z',
        'patterns': [
            'mail.google', 'gmail', 'outlook.live', 'outlook.office',
            'mail.yahoo', 'protonmail', 'proton.me', 'tutanota',
            'mail.yandex', 'zoho.com/mail', 'aol.com', 'icloud.com',
            'mail.com', 'gmx.', 'fastmail',
        ],
    },
    'social': {
        'label': 'Social Media',
        'color': 'blue',
        'icon': 'M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z',
        'patterns': [
            'facebook.com', 'instagram.com', 'twitter.com', 'x.com/i/',
            'tiktok.com', 'linkedin.com', 'reddit.com', 'discord.com',
            'telegram.org', 'snapchat.com', 'pinterest.com',
        ],
    },
    'gaming': {
        'label': 'Gaming',
        'color': 'emerald',
        'icon': 'M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z M21 12a9 9 0 11-18 0 9 9 0 0118 0z',
        'patterns': [
            'steampowered', 'store.steam', 'epicgames', 'origin.com',
            'ea.com', 'riotgames', 'blizzard', 'battle.net',
            'xbox.com', 'playstation.com', 'twitch.tv', 'roblox.com',
        ],
    },
    'cloud': {
        'label': 'Cloud / Hosting',
        'color': 'teal',
        'icon': 'M3 15a4 4 0 004 4h9a5 5 0 10-.1-9.999 5.002 5.002 0 10-9.78 2.096A4.001 4.001 0 003 15z',
        'patterns': [
            'aws.amazon', 'console.aws', 'portal.azure', 'cloud.google',
            'digitalocean', 'heroku', 'vercel', 'netlify', 'cloudflare',
            'hetzner', 'ovh.com', 'godaddy', 'namecheap', 'github.com',
            'gitlab.com', 'bitbucket',
        ],
    },
}


def analyze_password(pw: Password) -> str | None:
    url_lower = (pw.url or '').lower()
    for cat_id, cat in CATEGORIES.items():
        for pattern in cat['patterns']:
            if pattern in url_lower:
                return cat_id
    return None


def extract_highlights(result: ParseResult, archive_name: str = "") -> dict:
    findings: dict[str, list[HighlightItem]] = {cat: [] for cat in CATEGORIES}
    total = 0

    for victim in result.victims:
        for pw in victim.passwords:
            cat = analyze_password(pw)
            if cat:
                findings[cat].append(HighlightItem(
                    category=cat,
                    label=CATEGORIES[cat]['label'],
                    url=pw.url,
                    username=pw.username,
                    password=pw.password,
                    archive=archive_name,
                    victim=victim.folder_name,
                ))
                total += 1

    non_empty = {k: v for k, v in findings.items() if v}
    return {
        'findings': non_empty,
        'total': total,
        'categories': {k: CATEGORIES[k] for k in non_empty},
    }
