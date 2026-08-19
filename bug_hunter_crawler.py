#!/usr/bin/env python3
"""
bug_hunter_crawler.py
=====================

Production-grade bug-bounty reconnaissance crawler.

Features
--------
  * Concurrent crawler with strict in-scope enforcement
  * Full WAF / bot-detection evasion (UA + header rotation, IP-spoof headers,
    adaptive rate-limiting, path-encoding bypasses, method switching)
  * Deep JavaScript analysis (endpoints, parameters, secrets, source-maps)
  * Smart path discovery (config files, admin panels, leaks, debug endpoints)
  * Structured JSON report + colourised terminal summary

Use only on targets you are authorised to test.

Examples
--------
    python3 ~/tools/bug_hunter_crawler.py --target https://example.com
    python3 ~/tools/bug_hunter_crawler.py --target https://example.com --stealth --delay 2
    python3 ~/tools/bug_hunter_crawler.py --target https://example.com \\
        --headers '{"Cookie": "session=abc123"}'
    python3 ~/tools/bug_hunter_crawler.py --target https://example.com --js-only --verbose
"""

from __future__ import annotations

import argparse
import hashlib
import importlib
import ipaddress
import json
import logging
import os
import random
import re
import subprocess
import string
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import (
    urljoin, urlparse, urlsplit, urlunsplit, parse_qsl, quote, unquote,
)


# ---------------------------------------------------------------------------
# Auto-install required dependencies
# ---------------------------------------------------------------------------

_REQUIRED = {
    "requests": "requests>=2.31.0",
    "bs4": "beautifulsoup4>=4.12.0",
    "colorama": "colorama>=0.4.6",
    "urllib3": "urllib3>=2.0.0",
}


def _ensure_deps() -> None:
    missing = []
    for module_name, pkg_spec in _REQUIRED.items():
        try:
            importlib.import_module(module_name)
        except ImportError:
            missing.append(pkg_spec)
    if missing:
        print(f"[setup] Installing missing dependencies: {', '.join(missing)}")
        try:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", "--quiet",
                 "--disable-pip-version-check", *missing]
            )
        except subprocess.CalledProcessError as exc:
            print(f"[setup] pip install failed: {exc}", file=sys.stderr)
            sys.exit(1)


_ensure_deps()

import requests  # noqa: E402
import urllib3  # noqa: E402
from bs4 import BeautifulSoup, Comment  # noqa: E402
from colorama import Fore, Style, init as _colorama_init  # noqa: E402

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
_colorama_init(autoreset=True)


# ---------------------------------------------------------------------------
# Constants — User-Agents, headers, paths, regexes
# ---------------------------------------------------------------------------

USER_AGENTS: List[str] = [
    # ---- Chrome (Windows) ----
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    # ---- Chrome (macOS) ----
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    # ---- Chrome (Linux) ----
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
    # ---- Firefox (Windows) ----
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:115.0) Gecko/20100101 Firefox/115.0",
    # ---- Firefox (macOS) ----
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.3; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13.6; rv:122.0) Gecko/20100101 Firefox/122.0",
    # ---- Firefox (Linux) ----
    "Mozilla/5.0 (X11; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
    # ---- Safari (macOS) ----
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
    # ---- Edge (Windows) ----
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Edg/121.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    # ---- Edge (macOS) ----
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
    # ---- Opera ----
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 OPR/107.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
    # ---- Brave (uses Chrome UA) ----
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Brave/121",
    # ---- iOS Safari (iPhone) ----
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1",
    # ---- iPad Safari ----
    "Mozilla/5.0 (iPad; CPU OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1",
    # ---- Chrome iOS ----
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/121.0.6167.66 Mobile/15E148 Safari/604.1",
    # ---- Android Chrome ----
    "Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; SM-A536B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 12; SM-G998U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Mobile Safari/537.36",
    # ---- Android Firefox ----
    "Mozilla/5.0 (Android 14; Mobile; rv:122.0) Gecko/122.0 Firefox/122.0",
    "Mozilla/5.0 (Android 13; Mobile; rv:121.0) Gecko/121.0 Firefox/121.0",
    # ---- Samsung Internet ----
    "Mozilla/5.0 (Linux; Android 13; SAMSUNG SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/23.0 Chrome/115.0.0.0 Mobile Safari/537.36",
    # ---- Older but still common ----
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_7_10) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; rv:115.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    # ---- Niche desktop ----
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36 Vivaldi/6.5",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Vivaldi/6.4",
]


ACCEPT_LANGUAGES: List[str] = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
    "en-US,en;q=0.5",
    "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7",
    "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7",
    "es-ES,es;q=0.9,en-US;q=0.8,en;q=0.7",
    "ar-SA,ar;q=0.9,en-US;q=0.8,en;q=0.7",
    "ja-JP,ja;q=0.9,en-US;q=0.8,en;q=0.7",
    "pt-BR,pt;q=0.9,en;q=0.8",
    "ru-RU,ru;q=0.9,en;q=0.8",
    "it-IT,it;q=0.9,en;q=0.8",
    "nl-NL,nl;q=0.9,en;q=0.8",
]


ACCEPT_HEADERS: Dict[str, str] = {
    "html": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "script": "*/*",
    "json": "application/json,text/plain,*/*;q=0.5",
    "any": "*/*",
}


# WAF detection signatures: name -> {headers, cookies, body markers}
WAF_SIGNATURES: Dict[str, Dict[str, List[str]]] = {
    "Cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "server: cloudflare"],
        "cookies": ["__cfduid", "__cf_bm", "cf_clearance"],
        "body": ["attention required! | cloudflare", "cf-error-details", "cloudflare-nginx", "error code: 1020"],
    },
    "Akamai": {
        "headers": ["akamai-grn", "x-akamai-transformed", "x-akamai-request-id"],
        "cookies": ["_abck", "ak_bmsc", "bm_sz", "bm_sv"],
        "body": ["reference&#32;&#35;", "akamai", "access denied"],
    },
    "AWS WAF": {
        "headers": ["x-amzn-requestid", "x-amzn-errortype", "x-amz-cf-id"],
        "cookies": ["awswaf"],
        "body": ["aws waf", "request blocked"],
    },
    "Imperva/Incapsula": {
        "headers": ["x-cdn: incapsula", "x-iinfo"],
        "cookies": ["incap_ses", "visid_incap", "nlbi_"],
        "body": ["incapsula incident", "request unsuccessful"],
    },
    "Sucuri": {
        "headers": ["x-sucuri-id", "x-sucuri-cache", "server: sucuri"],
        "cookies": [],
        "body": ["access denied - sucuri website firewall"],
    },
    "ModSecurity": {
        "headers": ["server: mod_security", "mod_security"],
        "cookies": [],
        "body": ["mod_security", "noyb", "not acceptable!"],
    },
    "F5 BigIP": {
        "headers": ["x-cnection", "x-wa-info"],
        "cookies": ["bigipserver", "f5avr", "ts0"],
        "body": ["the requested url was rejected"],
    },
    "Barracuda": {
        "headers": [],
        "cookies": ["barra_counter_session", "barracuda_"],
        "body": ["barracuda"],
    },
    "Wordfence": {
        "headers": ["x-firewall-protection"],
        "cookies": ["wfwaf-authcookie"],
        "body": ["generated by wordfence"],
    },
    "FortiWeb": {
        "headers": [],
        "cookies": ["fortiwafsid"],
        "body": ["fortiweb", "fortiguard"],
    },
    "DDoS-Guard": {
        "headers": ["server: ddos-guard"],
        "cookies": ["__ddg"],
        "body": ["ddos-guard"],
    },
    "Reblaze": {
        "headers": ["server: reblaze"],
        "cookies": ["rbzid", "rbzsessionid"],
        "body": ["reblaze"],
    },
}


SMART_PATHS: List[str] = [
    # robots / sitemaps
    "/robots.txt", "/sitemap.xml", "/sitemap_index.xml", "/sitemap-index.xml",
    # config / env / vcs
    "/.env", "/.env.local", "/.env.production", "/.env.development", "/.env.bak",
    "/.git/config", "/.git/HEAD", "/.git/index", "/.gitignore",
    "/.svn/entries", "/.svn/wc.db", "/.hg/store/00manifest.i", "/.bzr/checkout/dirstate",
    "/.DS_Store", "/Thumbs.db", "/.htaccess", "/.htpasswd",
    # api / docs
    "/api", "/api/", "/api/v1", "/api/v2", "/api/v3", "/api/v1/", "/api/v2/",
    "/api/docs", "/api/swagger.json", "/api/openapi.json", "/api/swagger-ui.html",
    "/swagger.json", "/swagger.yaml", "/openapi.json", "/openapi.yaml",
    "/swagger-ui/", "/swagger-ui.html", "/api-docs", "/docs",
    "/graphql", "/graphiql", "/playground", "/altair", "/voyager",
    # admin / dashboards
    "/admin", "/admin/", "/administrator", "/administrator/", "/admin-panel",
    "/dashboard", "/cpanel", "/phpmyadmin/", "/manager/html",
    "/wp-admin/", "/wp-admin", "/wp-login.php", "/xmlrpc.php", "/wp-json/",
    "/wp-json/wp/v2/users",
    # actuator / debug
    "/debug", "/trace", "/actuator", "/actuator/health", "/actuator/env",
    "/actuator/mappings", "/actuator/heapdump", "/actuator/loggers",
    "/actuator/threaddump", "/actuator/configprops",
    "/elmah.axd", "/trace.axd", "/web.config",
    "/server-status", "/server-info", "/nginx-status",
    "/console", "/h2-console/", "/druid/index.html",
    "/phpinfo.php", "/info.php", "/test.php", "/shell.php",
    # build / package files
    "/webpack.config.js", "/package.json", "/composer.json", "/Gemfile",
    "/yarn.lock", "/package-lock.json", "/composer.lock",
    # JS build manifests (modern SPAs reference chunks via these)
    "/manifest.json", "/asset-manifest.json", "/build-manifest.json",
    "/import-map.json", "/admin-import-map.json", "/importmap.json",
    "/loadable-stats.json", "/webpack-stats.json", "/_next/static/build-manifest.json",
    "/static/build-manifest.json", "/dist/manifest.json",
    # security / well-known
    "/.well-known/security.txt", "/security.txt",
    "/.well-known/openid-configuration",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    # backups / dumps
    "/backup", "/backup.zip", "/backup.tar.gz", "/backup.sql",
    "/db.sql", "/dump.sql", "/database.sql",
    # auth flows
    "/login", "/signin", "/register", "/signup",
    "/forgot-password", "/reset-password", "/oauth/authorize",
    # uploads / files
    "/upload", "/uploads/", "/files/", "/media/", "/images/", "/documents/",
    "/cgi-bin/", "/bin/", "/scripts/",
    # config / settings
    "/config", "/configuration", "/settings", "/setup", "/install",
    "/install.php", "/setup.php",
    # status / health
    "/status", "/health", "/healthcheck", "/healthz", "/ready", "/readyz",
    "/ping", "/version", "/info", "/metrics", "/prometheus",
    # CI/CD / cloud leaks
    "/.aws/credentials", "/.docker/config.json", "/.npmrc", "/.pypirc",
    "/Dockerfile", "/docker-compose.yml",
]


# ---- Secret detection patterns ----
# (label, regex, severity)
SECRET_PATTERNS: List[Tuple[str, re.Pattern, str]] = [
    ("AWS_ACCESS_KEY",       re.compile(r"\b(AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16}\b"), "CRITICAL"),
    ("AWS_SECRET_KEY",       re.compile(r"(?i)aws[_\-]?(?:secret|sec)[_\-]?(?:access[_\-]?)?key[\"'\s:=]{1,5}([A-Za-z0-9/+=]{40})"), "CRITICAL"),
    ("FIREBASE_API_KEY",     re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"), "HIGH"),
    ("GOOGLE_OAUTH",         re.compile(r"\bya29\.[0-9A-Za-z\-_]{20,}\b"), "HIGH"),
    ("GOOGLE_OAUTH_SECRET",  re.compile(r"\bGOCSPX-[0-9A-Za-z\-_]{28}\b"), "HIGH"),
    ("STRIPE_LIVE_SECRET",   re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}\b"), "CRITICAL"),
    ("STRIPE_LIVE_PUBLIC",   re.compile(r"\bpk_live_[0-9a-zA-Z]{24,}\b"), "MEDIUM"),
    ("STRIPE_TEST",          re.compile(r"\b(?:sk|pk|rk)_test_[0-9a-zA-Z]{24,}\b"), "LOW"),
    ("GITHUB_PAT",           re.compile(r"\bgh[oprsu]_[A-Za-z0-9]{36,255}\b"), "CRITICAL"),
    ("GITHUB_FINEGRAINED",   re.compile(r"\bgithub_pat_[A-Za-z0-9_]{82}\b"), "CRITICAL"),
    ("GITLAB_PAT",           re.compile(r"\bglpat-[0-9A-Za-z\-_]{20}\b"), "CRITICAL"),
    ("SLACK_TOKEN",          re.compile(r"\bxox[baprso]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,}\b"), "CRITICAL"),
    ("SLACK_WEBHOOK",        re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"), "HIGH"),
    ("MAILGUN_KEY",          re.compile(r"\bkey-[0-9a-zA-Z]{32}\b"), "HIGH"),
    ("SENDGRID_KEY",         re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"), "HIGH"),
    ("MAILCHIMP_KEY",        re.compile(r"\b[0-9a-f]{32}-us[0-9]{1,2}\b"), "HIGH"),
    ("SQUARE_TOKEN",         re.compile(r"\bsq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}\b"), "HIGH"),
    ("TWILIO_KEY",           re.compile(r"\bSK[0-9a-fA-F]{32}\b"), "HIGH"),
    ("TWILIO_ACCOUNT_SID",   re.compile(r"\bAC[0-9a-fA-F]{32}\b"), "MEDIUM"),
    ("HEROKU_API_KEY",       re.compile(r"(?i)heroku[_\-]?api[_\-]?key[\"'\s:=]{1,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"), "HIGH"),
    ("JWT",                  re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}(?:\.[A-Za-z0-9_\-]+)?\b"), "MEDIUM"),
    ("PRIVATE_KEY",          re.compile(r"-----BEGIN[ A-Z0-9]{0,40}PRIVATE KEY-----"), "CRITICAL"),
    ("BEARER_TOKEN",         re.compile(r"(?i)bearer\s+[A-Za-z0-9\-._~+/]{20,}=*"), "MEDIUM"),
    ("BASIC_AUTH",           re.compile(r"(?i)basic\s+[A-Za-z0-9+/]{16,}={0,2}"), "MEDIUM"),
    ("DB_URL_MONGO",         re.compile(r"mongodb(?:\+srv)?://[^\s'\"<>{}]{6,}"), "CRITICAL"),
    ("DB_URL_POSTGRES",      re.compile(r"postgres(?:ql)?://[^\s'\"<>{}]{6,}"), "CRITICAL"),
    ("DB_URL_MYSQL",         re.compile(r"mysql://[^\s'\"<>{}]{6,}"), "CRITICAL"),
    ("DB_URL_REDIS",         re.compile(r"redis(?:s)?://[^\s'\"<>{}]{6,}"), "CRITICAL"),
    ("DB_URL_AMQP",          re.compile(r"amqp(?:s)?://[^\s'\"<>{}]{6,}"), "CRITICAL"),
    ("INTERNAL_IP",          re.compile(r"(?<![\d.])(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|127\.0\.0\.1)(?![\d.])"), "LOW"),
    ("GENERIC_SECRET",       re.compile(r"(?i)(?:secret|token|password|passwd|api[_\-]?key|apikey|access[_\-]?key|auth[_\-]?token|client[_\-]?secret)[\"'\s:=]{1,8}[\"']?([A-Za-z0-9_\-+/=]{16,})[\"']?"), "LOW"),
]

# Common false-positive substrings for the GENERIC_SECRET catch-all.
_GENERIC_SECRET_DENYLIST = re.compile(
    r"^(?:undefined|null|true|false|none|placeholder|example|sample|your[_\-]?api|your[_\-]?key|"
    r"changeme|xxxxx+|0{8,}|test|demo|dummy|todo|fixme)$",
    re.IGNORECASE,
)


# ---- JS analysis regexes ----
JS_QUOTED_PATH_RE = re.compile(
    r"""(['"`])(?P<u>(?:https?:)?//[^\s'"`<>{}\\]{1,500}|/[A-Za-z0-9_\-./~][^\s'"`<>{}\\]{0,500})\1"""
)
JS_WS_RE = re.compile(r"""(['"`])(wss?://[^\s'"`<>]{1,500})\1""")
JS_TEMPLATE_PATH_RE = re.compile(r"`(/[A-Za-z0-9_\-./~][^`]{0,400})`")
JS_FETCH_RE = re.compile(
    r"""(?:fetch|axios(?:\.\w+)?|XMLHttpRequest\(\)|\.open|\$\.ajax|\$\.get|\$\.post|"""
    r"""\.get|\.post|\.put|\.delete|\.patch|\.request)\s*\(\s*['"`]([^'"`]{1,400})['"`]"""
)
JS_ROUTE_RE = re.compile(
    r"""(?:app|router|route|server|api|express|fastify|hapi|koa)"""
    r"""\.(?:get|post|put|delete|patch|all|use|options|head)\s*\(\s*['"`]([^'"`]{1,300})['"`]"""
)
JS_OBJECT_KEY_RE = re.compile(
    r"""(?:url|path|endpoint|href|link|route|action|api|src|uri)\s*:\s*['"`]([^'"`]{1,300})['"`]""",
    re.IGNORECASE,
)
JS_PARAM_OBJ_KEY_RE = re.compile(r"""['"]([A-Za-z_][A-Za-z0-9_]{1,40})['"]\s*:""")
JS_QUERY_PARAM_RE = re.compile(r"""[?&]([A-Za-z_][A-Za-z0-9_\-]{0,40})=""")
JS_FORMDATA_RE = re.compile(r"""\.append\s*\(\s*['"]([A-Za-z_][A-Za-z0-9_\-]{0,60})['"]""")
JS_LOCALSTORAGE_RE = re.compile(
    r"""(?:localStorage|sessionStorage)\.(?:setItem|getItem|removeItem)\s*\(\s*['"]([A-Za-z_][A-Za-z0-9_\-]{0,60})['"]"""
)
JS_SOURCEMAP_RE = re.compile(r"//[#@]\s*sourceMappingURL\s*=\s*([^\s]+)")
JS_GRAPHQL_RE = re.compile(r"""\b(?:query|mutation|subscription)\s+([A-Za-z_][A-Za-z0-9_]*)\s*[({]""")

# Broad API-path fragment extractor. A single LINEAR run of path characters — including
# ${...} template-interpolation and ':' (protocol-relative) — that ends at the first char
# NOT in the class (any quote, whitespace, comma, paren, operator). One bounded quantifier
# over an exclusive character class, no nested quantifiers => no catastrophic backtracking,
# so it is safe to run over multi-MB single-line minified bundles. This catches /api/...
# embedded in template literals and string concatenations that the quoted-string and
# leading-slash template regexes miss, e.g.  `${proxy?p:""}/api/v2/${id}`.
JS_PATH_TOKEN_RE = re.compile(r"/[A-Za-z0-9_.\-/~%:${}]{1,220}")

# Marker gate for the broad scan: only keep path tokens that look like real API / app
# surface, so a vendor bundle's thousands of library-internal paths don't flood the report.
# Anchored to a path segment boundary (start or "/") so "video" doesn't match the "v\d" arm.
_API_PATH_MARKER_RE = re.compile(
    r"(?:^|/)(?:api|apis|rest|graphql|graphiql|gql|oauth2?|auth|sso|saml|oidc|"
    r"session|token|refresh|internal|admin|manage|console|debug|actuator|"
    r"webhooks?|hooks|rpc|jsonrpc|services?|graph|wp-json|_next/data|_api|"
    r"\.well-known|v[1-9]\d?)(?:/|\?|$)",
    re.IGNORECASE,
)

# Parameter-name denylist — these are almost always artefacts of JS minification
# (Webpack/Terser auto-generated single-letter vars, common runtime helpers, JS
# keywords that surface as object keys), not real API parameters.
JS_PARAM_NOISE: Set[str] = {
    # All single ASCII letters — minifiers exhaust a..z before lengthening.
    *(chr(c) for c in range(ord("a"), ord("z") + 1)),
    *(chr(c) for c in range(ord("A"), ord("Z") + 1)),
    # Common minifier runtime helpers / 2-letter generated names.
    "fn", "tt", "rr", "ee", "nn", "ii", "oo", "tt", "ts", "ns", "op", "kv",
    "rn", "fe", "te", "le", "se", "ce", "de", "he", "we", "be", "me", "pe",
    "ve", "ge", "re", "ye", "xe", "ze", "ke", "qe", "je", "Ee", "Te", "Re",
    # JS keywords that occasionally fall through as keys in `params:{}` blocks.
    "if", "in", "do", "of", "as", "is", "fn",
    # Obvious junk
    "_", "__",
}


def _is_noise_param(name: str) -> bool:
    """True if `name` is almost certainly minifier noise, not a real parameter."""
    if not name:
        return True
    if name in JS_PARAM_NOISE:
        return True
    # All-numeric or all-underscore tokens.
    if name.isdigit() or set(name) == {"_"}:
        return True
    return False


INTEREST_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("admin_check", re.compile(r"\b(?:isAdmin|is_admin|userRole|user_role|admin_role|hasPermission|hasRole|isStaff|is_staff|isSuperuser|role\s*===?\s*['\"]admin)")),
    ("debug_flag",  re.compile(r"\b(?:debug|devMode|testMode|verbose|trace)\s*[:=]\s*(?:true|1|['\"]on['\"]|['\"]yes['\"])")),
    ("env_var",     re.compile(r"\b(?:NODE_ENV|REACT_APP_[A-Z_]+|VUE_APP_[A-Z_]+|NEXT_PUBLIC_[A-Z_]+|VITE_[A-Z_]+|EXPO_PUBLIC_[A-Z_]+)\b")),
    ("cloud_storage", re.compile(r"\b[A-Za-z0-9.\-]{1,80}\.(?:s3\.amazonaws\.com|s3-[a-z0-9\-]+\.amazonaws\.com|s3\.[a-z0-9\-]+\.amazonaws\.com|storage\.googleapis\.com|blob\.core\.windows\.net|digitaloceanspaces\.com)\b")),
    ("comment_marker", re.compile(r"//\s*(TODO|FIXME|HACK|XXX|BUG|TEMP|HARDCODE|REMOVE)\b[: ]?([^\n]{0,160})")),
    ("version_info", re.compile(r"\b(?:version|build|commit|release)\s*[:=]\s*['\"]([0-9][^'\"]{0,40})['\"]")),
    ("feature_flag", re.compile(r"\b(?:feature[_\-]?flag|enable[A-Z][A-Za-z]+|disable[A-Z][A-Za-z]+|FEATURE_[A-Z_]+)\b")),
]


# ---- HTTP / IP-spoof headers ----
IP_HEADERS = [
    "X-Forwarded-For", "X-Real-IP", "X-Originating-IP",
    "X-Remote-IP", "X-Remote-Addr", "X-Client-IP",
    "True-Client-IP", "X-Cluster-Client-IP", "Forwarded",
]


# ---------------------------------------------------------------------------
# Logger
# ---------------------------------------------------------------------------

logger = logging.getLogger("bug_hunter")


def _setup_logger(verbose: bool) -> None:
    """Configure root logger with a clean format and verbosity level."""
    level = logging.DEBUG if verbose else logging.INFO
    handler = logging.StreamHandler(sys.stderr)
    fmt = "%(asctime)s [%(levelname).1s] %(message)s"
    handler.setFormatter(logging.Formatter(fmt, datefmt="%H:%M:%S"))
    logger.handlers.clear()
    logger.addHandler(handler)
    logger.setLevel(level)
    logger.propagate = False


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class EndpointInfo:
    url: str
    method: str = "GET"
    parameters: List[str] = field(default_factory=list)


@dataclass
class SecretInfo:
    type: str
    value: str
    redacted: str
    found_in: str
    line: int
    severity: str


@dataclass
class JSFileInfo:
    url: str
    size_bytes: int
    endpoints_found: int
    secrets_found: int
    source_map_available: bool
    source_map_url: str = ""


@dataclass
class FormInfo:
    action: str
    method: str
    inputs: List[str]
    found_in: str


@dataclass
class PathInfo:
    path: str
    status_code: int
    bypass_attempted: bool = False
    bypass_result: str = ""
    note: str = ""


@dataclass
class WAFBlockedPath:
    path: str
    status: int
    waf: str
    bypass_attempts: List[str]
    bypass_successful: bool


@dataclass
class ParameterInfo:
    name: str
    type: str = "query_param"


@dataclass
class SourceMapInfo:
    url: str
    contains_original_source: bool
    note: str


# ---------------------------------------------------------------------------
# Protection evader (UA + header rotation, IP-spoof, adaptive delay)
# ---------------------------------------------------------------------------

class ProtectionEvader:
    """Builds randomised, browser-like request headers and tracks rate-limit state."""

    HARD_RATE_LIMIT_THRESHOLD = 4

    def __init__(self, stealth: bool, base_delay: float):
        self.stealth = stealth
        self.base_delay = base_delay
        # Adaptive delay state (per-host).
        self._lock = threading.Lock()
        self._last_request_at: Dict[str, float] = {}
        self._adaptive_delay: Dict[str, float] = {}
        self._consecutive_429: Dict[str, int] = {}
        self._last_ua: Dict[int, str] = {}  # thread-id -> last UA used
        self.bypass_methods_used: Set[str] = set()
        # Hosts we've given up on — every subsequent call returns immediately.
        self.aborted_hosts: Set[str] = set()
        self._abort_logged: Set[str] = set()

    # ---------- header building ----------

    def _pick_user_agent(self) -> str:
        tid = threading.get_ident()
        last = self._last_ua.get(tid)
        ua = random.choice(USER_AGENTS)
        # Make sure we don't repeat the exact same UA twice in a row from this thread.
        attempts = 0
        while ua == last and attempts < 8:
            ua = random.choice(USER_AGENTS)
            attempts += 1
        self._last_ua[tid] = ua
        self.bypass_methods_used.add("UA rotation")
        return ua

    @staticmethod
    def _random_public_ip() -> str:
        """Generate a plausible-looking public IPv4 address (skips reserved ranges)."""
        while True:
            octets = [random.randint(1, 254) for _ in range(4)]
            try:
                addr = ipaddress.IPv4Address(".".join(map(str, octets)))
            except ValueError:
                continue
            if addr.is_private or addr.is_reserved or addr.is_loopback or addr.is_multicast:
                continue
            return str(addr)

    @staticmethod
    def _sec_ch_ua_for(ua: str) -> str:
        """Return a Sec-CH-UA hint matching the major Chrome/Edge version in the UA."""
        m = re.search(r"Chrome/(\d+)", ua)
        if not m:
            return ""
        major = m.group(1)
        if "Edg/" in ua:
            return f'"Microsoft Edge";v="{major}", "Chromium";v="{major}", "Not(A:Brand";v="24"'
        if "OPR/" in ua:
            return f'"Opera";v="{major}", "Chromium";v="{major}", "Not(A:Brand";v="24"'
        return f'"Google Chrome";v="{major}", "Chromium";v="{major}", "Not(A:Brand";v="24"'

    @staticmethod
    def _platform_for(ua: str) -> str:
        if "Windows" in ua:
            return '"Windows"'
        if "Macintosh" in ua or "Mac OS X" in ua:
            return '"macOS"'
        if "Android" in ua:
            return '"Android"'
        if "iPhone" in ua or "iPad" in ua or "iOS" in ua:
            return '"iOS"'
        if "Linux" in ua:
            return '"Linux"'
        return '"Unknown"'

    def build_headers(
        self,
        url: str,
        *,
        kind: str = "html",
        referer: Optional[str] = None,
        extra: Optional[Dict[str, str]] = None,
    ) -> Dict[str, str]:
        """Compose a randomised, browser-shaped header set for `url`."""
        ua = self._pick_user_agent()
        is_chromium = ("Chrome/" in ua) or ("Edg/" in ua) or ("OPR/" in ua)
        is_mobile = any(t in ua for t in ("iPhone", "Android", "iPad", "Mobile"))

        headers: Dict[str, str] = {
            "User-Agent": ua,
            "Accept": ACCEPT_HEADERS.get(kind, ACCEPT_HEADERS["html"]),
            "Accept-Language": random.choice(ACCEPT_LANGUAGES),
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "DNT": str(random.choice([0, 1])),
            "Cache-Control": random.choice(["no-cache", "max-age=0"]),
        }

        # Sec-Fetch-* (Chromium / Firefox both send these on modern versions).
        if kind == "html":
            headers["Sec-Fetch-Dest"] = "document"
            headers["Sec-Fetch-Mode"] = "navigate"
            headers["Sec-Fetch-Site"] = "none" if referer is None else "same-origin"
            headers["Sec-Fetch-User"] = "?1"
        elif kind == "script":
            headers["Sec-Fetch-Dest"] = "script"
            headers["Sec-Fetch-Mode"] = "no-cors"
            headers["Sec-Fetch-Site"] = "same-origin"
        elif kind == "json":
            headers["Sec-Fetch-Dest"] = "empty"
            headers["Sec-Fetch-Mode"] = "cors"
            headers["Sec-Fetch-Site"] = "same-origin"

        if is_chromium:
            ch = self._sec_ch_ua_for(ua)
            if ch:
                headers["Sec-CH-UA"] = ch
            headers["Sec-CH-UA-Mobile"] = "?1" if is_mobile else "?0"
            headers["Sec-CH-UA-Platform"] = self._platform_for(ua)

        if referer:
            headers["Referer"] = referer
            self.bypass_methods_used.add("Referer chain")

        # IP-spoof headers — rotate a different random IP per header on every call.
        for name in IP_HEADERS:
            ip = self._random_public_ip()
            headers[name] = f"for={ip}" if name == "Forwarded" else ip
        self.bypass_methods_used.add("IP-spoof headers")

        if extra:
            headers.update(extra)
        return headers

    # ---------- adaptive rate limiting ----------

    def wait_before_request(self, host: str) -> None:
        """Sleep enough to honour adaptive per-host delay + jitter, mimicking a human."""
        with self._lock:
            adaptive = self._adaptive_delay.get(host, self.base_delay)
            last = self._last_request_at.get(host, 0.0)
        # Random jitter — never fixed cadence.
        if self.stealth:
            jitter = random.uniform(0.6, 2.5)
            wait_target = max(adaptive, self.base_delay) + jitter
        else:
            jitter = random.uniform(-0.2, 0.5)
            wait_target = max(adaptive + jitter, 0.0)
        elapsed = time.time() - last
        if elapsed < wait_target:
            time.sleep(wait_target - elapsed)
        with self._lock:
            self._last_request_at[host] = time.time()

    def report_response(self, host: str, status: int) -> None:
        """Adapt per-host delay based on status: speed up on success, back off on 429/403."""
        with self._lock:
            cur = self._adaptive_delay.get(host, self.base_delay)
            if status == 429 or status == 503:
                self._consecutive_429[host] = self._consecutive_429.get(host, 0) + 1
                # Exponential back-off on rate-limit.
                cur = min(cur * 2 + 1.5, 30.0)
                self.bypass_methods_used.add("Adaptive back-off")
            elif status == 403:
                cur = min(cur * 1.5 + 0.5, 15.0)
                self.bypass_methods_used.add("Adaptive back-off")
            elif 200 <= status < 400:
                self._consecutive_429[host] = 0
                # Slowly recover toward base delay.
                cur = max(cur * 0.9, self.base_delay)
            self._adaptive_delay[host] = cur

    def is_rate_limited_hard(self, host: str) -> bool:
        """True once a host has tripped the hard-limit threshold. Sticky: once True, stays True.

        Used as a global circuit-breaker so workers stop firing requests at a host that is
        clearly blocking us, instead of spinning through queued URLs returning None.
        """
        with self._lock:
            if host in self.aborted_hosts:
                return True
            if self._consecutive_429.get(host, 0) >= self.HARD_RATE_LIMIT_THRESHOLD:
                self.aborted_hosts.add(host)
                return True
            return False

    def claim_abort_log(self, host: str) -> bool:
        """Return True only the first time a host's abort should be logged (one-shot)."""
        with self._lock:
            if host in self._abort_logged:
                return False
            self._abort_logged.add(host)
            return True


# ---------------------------------------------------------------------------
# WAF detection
# ---------------------------------------------------------------------------

class WAFDetector:
    """Inspects responses for WAF / bot-mitigation fingerprints."""

    def __init__(self) -> None:
        self.detected: Set[str] = set()
        self._lock = threading.Lock()

    def inspect(self, resp: requests.Response) -> Optional[str]:
        """Return the matched WAF name if any signature fires on this response."""
        try:
            header_blob = " ".join(f"{k.lower()}: {v.lower()}" for k, v in resp.headers.items())
            cookie_blob = " ".join(c.lower() for c in resp.cookies.keys())
            body_snippet = ""
            if resp.content and len(resp.content) < 200_000:
                try:
                    body_snippet = resp.text[:8000].lower()
                except Exception:
                    body_snippet = ""
        except Exception:
            return None

        for waf, sig in WAF_SIGNATURES.items():
            for h in sig.get("headers", []):
                if h.lower() in header_blob:
                    self._mark(waf)
                    return waf
            for c in sig.get("cookies", []):
                if c.lower() in cookie_blob:
                    self._mark(waf)
                    return waf
            for b in sig.get("body", []):
                if b.lower() in body_snippet:
                    self._mark(waf)
                    return waf
        return None

    def _mark(self, waf: str) -> None:
        with self._lock:
            self.detected.add(waf)


# ---------------------------------------------------------------------------
# WAF bypass — path / encoding / method tricks
# ---------------------------------------------------------------------------

class WAFBypass:
    """Generates payload variants for a 403'd path and tests each one."""

    @staticmethod
    def path_variants(path: str) -> List[Tuple[str, str]]:
        """Return [(label, transformed_path), ...] applying classic path-bypass tricks."""
        if not path.startswith("/"):
            path = "/" + path
        clean = path.rstrip("/")
        seg = clean.lstrip("/")
        out: List[Tuple[str, str]] = []
        # Variants that work against many WAFs.
        out.append(("double-slash", f"//{seg}"))
        out.append(("dot-slash",     f"/./{seg}"))
        out.append(("trailing-semi", f"/{seg}..;/"))
        out.append(("encoded-slash", f"/%2f{seg}"))
        out.append(("trailing-space-encoded", f"/{seg}%20"))
        out.append(("trailing-tab-encoded",   f"/{seg}%09"))
        out.append(("trailing-cr-encoded",    f"/{seg}%0d"))
        out.append(("trailing-lf-encoded",    f"/{seg}%0a"))
        out.append(("backslash-traversal",    f"/{seg}\\../"))
        out.append(("null-byte-html",         f"/{seg}%00.html"))
        out.append(("fragment",               f"/{seg}#fragment"))
        out.append(("semicolon-js",           f"/{seg};.js"))
        out.append(("semicolon-css",          f"/{seg};.css"))
        out.append(("upper-case",             "/" + seg.upper() if seg else "/"))
        out.append(("uri-encoded",            "/" + quote(seg, safe="")))
        out.append(("double-encoded",         "/" + quote(quote(seg, safe=""), safe="")))
        # Cache-buster
        sep = "&" if "?" in clean else "?"
        out.append(("cache-buster", f"{clean}{sep}cb={random.randint(10**6, 10**9)}"))
        return out

    @staticmethod
    def methods_to_try() -> List[str]:
        """Alternate verbs sometimes accepted where GET is filtered."""
        return ["POST", "PUT", "PATCH", "OPTIONS", "HEAD"]


# ---------------------------------------------------------------------------
# Scope checker
# ---------------------------------------------------------------------------

class ScopeChecker:
    """Decides whether a URL belongs to the authorised target scope."""

    def __init__(self, target_url: str, extra_scopes: Iterable[str] = (),
                 excludes: Iterable[str] = ()):
        self.target_url = target_url
        parsed = urlparse(target_url)
        self.target_host = (parsed.hostname or "").lower()
        self.target_root = self._registrable(self.target_host)
        # additional scope entries (each may be exact or wildcard like *.foo.com)
        self.extra_hosts: Set[str] = set()
        self.extra_roots: Set[str] = set()
        for s in extra_scopes:
            s = s.strip().lower().lstrip("*").lstrip(".")
            if not s:
                continue
            self.extra_hosts.add(s)
            self.extra_roots.add(self._registrable(s))
        self.excludes: List[str] = [e.strip() for e in excludes if e.strip()]

    @staticmethod
    def _registrable(host: str) -> str:
        """Return a "good-enough" registrable suffix (last two labels). Not a public-suffix-list lookup."""
        if not host:
            return ""
        parts = host.split(".")
        if len(parts) <= 2:
            return host
        return ".".join(parts[-2:])

    def in_scope(self, url: str) -> bool:
        try:
            host = (urlparse(url).hostname or "").lower()
        except Exception:
            return False
        if not host:
            return False
        # Match target's registrable + any subdomain of it.
        if self.target_root and (host == self.target_root or host.endswith("." + self.target_root)):
            return True
        for h in self.extra_hosts:
            if host == h or host.endswith("." + h):
                return True
        for r in self.extra_roots:
            if r and (host == r or host.endswith("." + r)):
                return True
        return False

    def is_excluded(self, url: str) -> bool:
        try:
            path = urlparse(url).path or "/"
        except Exception:
            return False
        return any(path.startswith(e) for e in self.excludes)


# ---------------------------------------------------------------------------
# JS Analyzer
# ---------------------------------------------------------------------------

class JSAnalyzer:
    """Extracts endpoints, parameters, secrets, and interesting markers from JS source."""

    @staticmethod
    def _line_of(text: str, idx: int) -> int:
        return text.count("\n", 0, idx) + 1

    @staticmethod
    def _redact(value: str) -> str:
        if len(value) <= 8:
            return "***"
        return value[:4] + "..." + value[-4:]

    def extract_endpoints(self, js: str, source: str = "") -> List[EndpointInfo]:
        """Find every URL-like string in the source and emit EndpointInfo records."""
        seen: Dict[str, EndpointInfo] = {}

        def add(raw: str, method: str = "GET") -> None:
            raw = raw.strip()
            if not raw or len(raw) > 600:
                return
            # Filter junk.
            if raw.startswith(("data:", "blob:", "javascript:")):
                return
            if raw.startswith("//") and not raw.startswith("///"):
                pass  # protocol-relative — keep
            if not (raw.startswith(("/", "http://", "https://", "//"))
                    or re.match(r"^[A-Za-z][A-Za-z0-9_\-]{1,40}/[A-Za-z]", raw)):
                return
            params: List[str] = []
            try:
                qs = urlparse(raw).query
                if qs:
                    params = [k for k, _ in parse_qsl(qs, keep_blank_values=True)]
            except Exception:
                pass
            key = f"{method}:{raw}"
            if key in seen:
                # Merge new params we didn't have.
                for p in params:
                    if p not in seen[key].parameters:
                        seen[key].parameters.append(p)
                return
            seen[key] = EndpointInfo(url=raw, method=method, parameters=params)

        # Quoted URL/path strings (broadest catch).
        for m in JS_QUOTED_PATH_RE.finditer(js):
            add(m.group("u"))

        # WebSocket URLs.
        for m in JS_WS_RE.finditer(js):
            add(m.group(2))

        # Template-literal paths.
        for m in JS_TEMPLATE_PATH_RE.finditer(js):
            add(m.group(1))

        # fetch/axios call sites — try to infer the method.
        for m in JS_FETCH_RE.finditer(js):
            method = "GET"
            mm = re.search(r"method\s*:\s*['\"]([A-Z]+)['\"]", js[m.start():m.start() + 400])
            if mm:
                method = mm.group(1)
            else:
                low = m.group(0).lower()
                for verb in ("post", "put", "delete", "patch", "options", "head"):
                    if f".{verb}(" in low or f"$.{verb}(" in low:
                        method = verb.upper()
                        break
            add(m.group(1), method=method)

        # Server-side route declarations.
        for m in JS_ROUTE_RE.finditer(js):
            verb_match = re.search(r"\.(get|post|put|delete|patch|all|use|options|head)\s*\(",
                                   m.group(0).lower())
            method = verb_match.group(1).upper() if verb_match else "GET"
            if method == "ALL" or method == "USE":
                method = "ANY"
            add(m.group(1), method=method)

        # Object-literal url/path/endpoint keys.
        for m in JS_OBJECT_KEY_RE.finditer(js):
            add(m.group(1))

        # Broad API-path-fragment pass — catches /api/... embedded in template literals,
        # string concatenations and interpolated URLs that the quoted-string / leading-slash
        # template regexes above miss (the common case in webpack-minified SPA bundles).
        for m in JS_PATH_TOKEN_RE.finditer(js):
            tok = m.group(0)
            if len(tok) < 4:
                continue
            if _API_PATH_MARKER_RE.search(tok):
                add(tok)

        return list(seen.values())

    def extract_secrets(self, js: str, source: str) -> List[SecretInfo]:
        """Run the secret regex catalogue and return findings (deduplicated by value+type)."""
        out: List[SecretInfo] = []
        seen_keys: Set[Tuple[str, str]] = set()

        for label, regex, severity in SECRET_PATTERNS:
            for m in regex.finditer(js):
                value = m.group(0)
                # GENERIC_SECRET frequently fires on placeholders — skip those.
                if label == "GENERIC_SECRET" and m.lastindex:
                    captured = m.group(m.lastindex) or ""
                    if _GENERIC_SECRET_DENYLIST.match(captured):
                        continue
                    # Avoid reporting tokens that are obvious example/dummy strings.
                    if len(captured) < 16:
                        continue
                key = (label, value[:120])
                if key in seen_keys:
                    continue
                seen_keys.add(key)
                line = self._line_of(js, m.start())
                out.append(SecretInfo(
                    type=label,
                    value=value,
                    redacted=self._redact(value),
                    found_in=source,
                    line=line,
                    severity=severity,
                ))
        return out

    def extract_parameters(self, js: str) -> Set[str]:
        """Return the union of plausible parameter names referenced anywhere in the source.

        Minifier-noise names (single letters, common 2-letter runtime vars, JS keywords)
        are filtered out — they're never real API parameters and just bloat the report.
        """
        params: Set[str] = set()
        for m in JS_QUERY_PARAM_RE.finditer(js):
            params.add(m.group(1))
        for m in JS_FORMDATA_RE.finditer(js):
            params.add(m.group(1))
        for m in JS_LOCALSTORAGE_RE.finditer(js):
            params.add(m.group(1))
        # Object-literal keys near fetch / body / data sites.
        for m in re.finditer(r"(?:body|data|params|payload|query|variables)\s*:\s*\{([^{}]{0,2000})\}", js):
            for km in JS_PARAM_OBJ_KEY_RE.finditer(m.group(1)):
                params.add(km.group(1))
        return {p for p in params if not _is_noise_param(p)}

    def extract_interesting(self, js: str) -> Dict[str, List[str]]:
        """Return a dict of interest-category -> [matched snippets...]."""
        out: Dict[str, List[str]] = {}
        for label, regex in INTEREST_PATTERNS:
            matches: List[str] = []
            for m in regex.finditer(js):
                snippet = m.group(0)
                if snippet not in matches:
                    matches.append(snippet[:200])
                if len(matches) >= 50:
                    break
            if matches:
                out[label] = matches
        return out

    def extract_graphql(self, js: str) -> List[str]:
        """Return GraphQL operation names referenced in the source."""
        names: List[str] = []
        for m in JS_GRAPHQL_RE.finditer(js):
            n = m.group(1)
            if n not in names:
                names.append(n)
        return names

    def find_source_map(self, js: str) -> Optional[str]:
        """Return the //# sourceMappingURL value if one is present."""
        m = JS_SOURCEMAP_RE.search(js)
        if m:
            return m.group(1).strip()
        return None


# ---------------------------------------------------------------------------
# HTML Analyzer
# ---------------------------------------------------------------------------

class HTMLAnalyzer:
    """Pulls links, forms, scripts, comments, and data-* attributes out of HTML."""

    DATA_ATTRS = ("data-url", "data-api", "data-endpoint", "data-href",
                  "data-link", "data-action", "data-src", "ng-href",
                  "v-bind:href", ":href", "@click")

    def parse(self, html: str, page_url: str) -> Dict[str, Any]:
        """Return {links, forms, scripts, inline_scripts, comments, data_attrs, meta_redirect}."""
        try:
            soup = BeautifulSoup(html, "html.parser")
        except Exception as exc:
            logger.debug("HTML parse failed for %s: %s", page_url, exc)
            return {"links": set(), "forms": [], "scripts": set(),
                    "inline_scripts": [], "comments": [], "data_attrs": set(),
                    "meta_redirect": None}

        links: Set[str] = set()
        scripts: Set[str] = set()
        forms: List[FormInfo] = []
        inline_scripts: List[str] = []
        comments: List[str] = []
        data_attrs: Set[str] = set()
        meta_redirect: Optional[str] = None

        # Anchor/area links.
        for tag_name, attr in (("a", "href"), ("area", "href")):
            for tag in soup.find_all(tag_name):
                href = tag.get(attr)
                if href:
                    links.add(urljoin(page_url, href.strip()))

        # Scripts (external + inline).
        for tag in soup.find_all("script"):
            src = tag.get("src")
            if src:
                scripts.add(urljoin(page_url, src.strip()))
            elif tag.string:
                txt = str(tag.string)
                if txt.strip():
                    inline_scripts.append(txt)

        # Resource references — skip <img>, <video>, <audio> since they're media
        # not application surfaces. Static assets (images, stylesheets, fonts, media —
        # e.g. <link rel="stylesheet">) are explicitly filtered out: nothing interesting
        # lives on them.
        for tag_name, attr in (
            ("link", "href"), ("iframe", "src"),
            ("embed", "src"), ("object", "data"), ("source", "src"),
        ):
            for tag in soup.find_all(tag_name):
                v = tag.get(attr)
                if v:
                    full = urljoin(page_url, v.strip())
                    if not _is_noise_asset(full):
                        links.add(full)

        # Forms.
        for f in soup.find_all("form"):
            action = urljoin(page_url, (f.get("action") or page_url).strip())
            method = (f.get("method") or "GET").upper()
            inputs: List[str] = []
            for inp in f.find_all(["input", "select", "textarea", "button"]):
                name = inp.get("name")
                if name:
                    inputs.append(name)
            forms.append(FormInfo(action=action, method=method,
                                  inputs=inputs, found_in=page_url))

        # Meta refresh redirect.
        for m in soup.find_all("meta"):
            http_equiv = (m.get("http-equiv") or "").lower()
            content = m.get("content") or ""
            if http_equiv == "refresh" and "url=" in content.lower():
                try:
                    redir = content.split("=", 1)[1].strip().strip("'\"")
                    meta_redirect = urljoin(page_url, redir)
                except Exception:
                    pass

        # Comments — secrets / TODO / debug notes are sometimes here.
        for c in soup.find_all(string=lambda s: isinstance(s, Comment)):
            text = str(c).strip()
            if text and len(text) < 4000:
                comments.append(text)

        # Data attributes — Angular/Vue/React-style URL bindings.
        for tag in soup.find_all(True):
            for attr in self.DATA_ATTRS:
                v = tag.get(attr)
                if v:
                    candidate = v.strip().strip("'\"")
                    if candidate:
                        data_attrs.add(candidate)
                        if candidate.startswith(("/", "http://", "https://")):
                            links.add(urljoin(page_url, candidate))

        return {
            "links": links,
            "forms": forms,
            "scripts": scripts,
            "inline_scripts": inline_scripts,
            "comments": comments,
            "data_attrs": data_attrs,
            "meta_redirect": meta_redirect,
        }


# ---------------------------------------------------------------------------
# HTTP client wrapper (thread-local Session, retries, evasion baked in)
# ---------------------------------------------------------------------------

class HTTPClient:
    """Thin wrapper around `requests.Session` that bakes in our evasion layer."""

    def __init__(
        self,
        evader: ProtectionEvader,
        waf_detector: WAFDetector,
        timeout: float,
        custom_headers: Optional[Dict[str, str]] = None,
        max_retries: int = 3,
    ):
        self.evader = evader
        self.waf_detector = waf_detector
        self.timeout = timeout
        self.custom_headers = custom_headers or {}
        self.max_retries = max_retries
        self._tls = threading.local()

        # Stats.
        self.total = 0
        self.successful = 0
        self.failed = 0
        self.blocked = 0
        self.bypassed = 0
        self._stats_lock = threading.Lock()

    def _session(self) -> requests.Session:
        s = getattr(self._tls, "session", None)
        if s is None:
            s = requests.Session()
            s.verify = False  # bug-bounty targets often have weird cert chains
            s.max_redirects = 5
            self._tls.session = s
        return s

    def request(
        self,
        method: str,
        url: str,
        *,
        kind: str = "html",
        referer: Optional[str] = None,
        allow_redirects: bool = True,
        data: Any = None,
        json_body: Any = None,
    ) -> Optional[requests.Response]:
        """Perform a single request with rotated headers + retries on transient errors.

        Returns the final response (even on 4xx/5xx) or None when all retries fail.
        """
        host = urlparse(url).hostname or ""
        last_exc: Optional[BaseException] = None

        # Circuit-breaker: if this host has been marked aborted by a prior worker,
        # bail immediately with no delay and no log spam.
        if self.evader.is_rate_limited_hard(host):
            if self.evader.claim_abort_log(host):
                logger.error(
                    "Host %s is rate-limiting us hard — aborting all further requests "
                    "to it. Re-run with --stealth --delay 5 (or higher) to push through.",
                    host,
                )
            return None

        for attempt in range(self.max_retries):
            try:
                self.evader.wait_before_request(host)
                if self.evader.is_rate_limited_hard(host):
                    # State flipped while we were sleeping — bail without re-logging.
                    return None

                headers = self.evader.build_headers(
                    url, kind=kind, referer=referer, extra=self.custom_headers,
                )
                with self._stats_lock:
                    self.total += 1

                resp = self._session().request(
                    method=method,
                    url=url,
                    headers=headers,
                    timeout=self.timeout,
                    allow_redirects=allow_redirects,
                    data=data,
                    json=json_body,
                )

                self.evader.report_response(host, resp.status_code)
                self.waf_detector.inspect(resp)

                with self._stats_lock:
                    if 200 <= resp.status_code < 400:
                        self.successful += 1
                    elif resp.status_code in (403, 406, 429, 503) and self.waf_detector.detected:
                        self.blocked += 1
                    else:
                        self.failed += 1
                return resp

            except (requests.Timeout, requests.ConnectionError) as exc:
                last_exc = exc
                # Exponential back-off on transient errors.
                time.sleep(min(2 ** attempt, 8) + random.uniform(0, 0.5))
            except requests.RequestException as exc:
                last_exc = exc
                time.sleep(min(2 ** attempt, 8))

        with self._stats_lock:
            self.failed += 1
        logger.debug("Request failed after %d retries: %s -> %s", self.max_retries, url, last_exc)
        return None


# ---------------------------------------------------------------------------
# Crawler engine
# ---------------------------------------------------------------------------

_JS_EXTS = (".js", ".mjs", ".cjs")
_JS_PATH_MARKERS = (
    ".bundle.js", ".chunk.js", "/static/js/", "/_next/static/",
    "/_next/data/", "/webpack/", "/dist/", "/build/static/",
)
_NON_JS_EXTS = (
    ".css", ".html", ".htm", ".png", ".jpg", ".jpeg", ".gif", ".svg",
    ".webp", ".woff", ".woff2", ".ttf", ".eot", ".ico", ".mp4", ".webm",
    ".mp3", ".wav", ".pdf", ".zip", ".tar", ".gz", ".xml", ".txt",
)
_MANIFEST_RE = re.compile(
    r"(?:^|/)(?:[\w.-]*?(?:manifest|import[-_]?map|asset[-_]?manifest|"
    r"build[-_]?manifest|chunks?[-_]?map|loadable[-_]?stats|webpack[-_]?stats|"
    r"module[-_]?map|app[-_]?manifest|routes?))[\w.-]*\.json$",
    re.IGNORECASE,
)


def _looks_like_js(url: str) -> bool:
    """True if `url` plausibly points to a JS bundle worth fetching as JS source."""
    try:
        path = urlparse(url).path.lower()
    except Exception:
        return False
    if not path:
        return False
    base = path.rsplit("/", 1)[-1]
    if any(base.endswith(ext) for ext in _NON_JS_EXTS):
        return False
    if any(base.endswith(ext) for ext in _JS_EXTS):
        return True
    return any(marker in path for marker in _JS_PATH_MARKERS)


def _looks_like_manifest_json(url: str) -> bool:
    """True if URL looks like a JSON manifest worth re-analysing for nested asset paths."""
    try:
        path = urlparse(url).path
    except Exception:
        return False
    return bool(_MANIFEST_RE.search(path))


_IMAGE_EXTS = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".bmp",
    ".tiff", ".tif", ".avif", ".apng", ".heic", ".heif",
)


def _is_image_url(url: str) -> bool:
    """True if `url` ends with an image extension — these bloat the report."""
    try:
        path = urlparse(url).path.lower()
    except Exception:
        return False
    return any(path.endswith(ext) for ext in _IMAGE_EXTS)


_CSS_EXTS = (".css", ".css.map")


def _is_css_url(url: str) -> bool:
    """True if `url` points to a stylesheet — CSS carries no security-relevant surface."""
    try:
        path = urlparse(url).path.lower()
    except Exception:
        return False
    return any(path.endswith(ext) for ext in _CSS_EXTS)


_FONT_EXTS = (".woff", ".woff2", ".ttf", ".otf", ".eot")


def _is_font_url(url: str) -> bool:
    """True if `url` points to a web font — fonts carry no security-relevant surface."""
    try:
        path = urlparse(url).path.lower()
    except Exception:
        return False
    return any(path.endswith(ext) for ext in _FONT_EXTS)


_MEDIA_EXTS = (
    # video
    ".mp4", ".webm", ".mov", ".avi", ".mkv", ".m4v", ".ogv", ".flv", ".wmv", ".3gp",
    # audio
    ".mp3", ".wav", ".ogg", ".oga", ".flac", ".m4a", ".aac", ".opus", ".wma",
)


def _is_media_url(url: str) -> bool:
    """True if `url` points to an audio/video file — media carry no security-relevant surface.

    Note: documents/archives (.pdf, .zip, .tar, .gz, .xml, .txt) are deliberately NOT here —
    they can leak PII, secrets, source, or config and are worth keeping in the report.
    """
    try:
        path = urlparse(url).path.lower()
    except Exception:
        return False
    return any(path.endswith(ext) for ext in _MEDIA_EXTS)


def _is_noise_asset(url: str) -> bool:
    """True if `url` is a static asset with no attack surface worth keeping — images,
    stylesheets, fonts, and audio/video media. Nothing interesting lives on these, so we
    never record, crawl, or follow them; they would only bloat the endpoint list and the
    report."""
    return (
        _is_image_url(url)
        or _is_css_url(url)
        or _is_font_url(url)
        or _is_media_url(url)
    )


# Well-known analytics / advertising / tag-manager / consent hosts. When we're allowed to
# read an in-scope page's *cross-origin* bundles (off-site policy), these are excluded: they
# are pure third-party trackers, never the target's own API code, so fetching them just burns
# the off-site budget and floods the report with other companies' endpoints. Matched as a
# substring against the hostname.
_TRACKER_HOST_MARKERS: Tuple[str, ...] = (
    "google-analytics.com", "googletagmanager.com", "googlesyndication.com",
    "googleadservices.com", "doubleclick.net", "g.doubleclick", "gstatic.com/recaptcha",
    "connect.facebook.net", "facebook.com/tr", "fbcdn.net",
    "analytics.tiktok.com", "tr.snapchat.com", "sc-static.net", "ct.pinterest.com",
    "bat.bing.net", "bing.com", "snap.licdn.com", "licdn.com", "ads-twitter.com",
    "analytics.twitter.com", "static.ads-twitter.com",
    # HubSpot marketing/analytics stack (js.hs-*, hsforms, usemessages, hsadspixel, …)
    "hs-scripts.com", "hs-analytics.net", "hsadspixel.net", "hs-banner.com",
    "js.hubspot.com", "js-na1.hs-scripts.com", "usemessages.com", "hsforms.",
    "hscollectedforms.net", "hs-sites.com",
    # product analytics / session replay / consent
    "appcues.com", "hotjar.com", "mixpanel.com", "segment.com", "segment.io",
    "cdn.segment", "fullstory.com", "mouseflow.com", "clarity.ms", "amplitude.com",
    "quantserve.com", "scorecardresearch.com", "criteo.", "taboola.com", "outbrain.com",
    "pardot.com", "marketo.net", "mktoresp.com", "cookielaw.org", "onetrust.com",
    "cookiebot.com", "newrelic.com", "nr-data.net", "browser-intake", "datadoghq",
)


def _is_tracker_host(url: str) -> bool:
    """True if `url`'s host is a well-known third-party analytics/ad/consent tracker."""
    try:
        host = (urlparse(url).hostname or "").lower()
    except Exception:
        return False
    if not host:
        return False
    hostpath = host + (urlparse(url).path or "").lower()
    return any(marker in host or marker in hostpath for marker in _TRACKER_HOST_MARKERS)


# Pseudo-URLs that show up in HTML/JS but aren't endpoints — XML namespaces,
# DTDs, schema identifiers. They get caught by the broad URL regex but they're
# never resources to fetch.
_NS_PSEUDO_URL_PREFIXES = (
    "http://www.w3.org/", "https://www.w3.org/",
    "http://www.w3.org/1999/xhtml", "http://www.w3.org/2000/svg",
    "http://www.w3.org/1999/xlink", "http://www.w3.org/XML/",
    "http://schemas.xmlsoap.org/", "http://schemas.microsoft.com/",
    "http://schemas.openxmlformats.org/", "http://www.openxmlformats.org/",
    "http://purl.org/", "http://xmlns.com/", "http://ns.adobe.com/",
    "http://www.opengis.net/", "http://www.iana.org/",
    "urn:", "tag:",
)


def _is_namespace_pseudo_url(url: str) -> bool:
    """True if `url` is an XML namespace / schema identifier, not a real endpoint."""
    if not url:
        return False
    low = url.lower()
    return any(low.startswith(prefix.lower()) for prefix in _NS_PSEUDO_URL_PREFIXES)


# React Suspense / Next.js streaming markers: $, /$, $?, $!, $L1, /$2 etc.
_REACT_STREAM_MARKER_RE = re.compile(r"^[/$!?]+[0-9A-Za-z]{0,6}$")


def _is_noise_comment(text: str) -> bool:
    """True if an HTML comment is framework runtime noise, not human content."""
    s = (text or "").strip()
    if not s:
        return True
    # React/Next streaming markers (the user's $, /$, $?, $! cases).
    if _REACT_STREAM_MARKER_RE.match(s):
        return True
    # Need at least 3 alphanumeric chars to be plausibly meaningful.
    alnum = sum(1 for ch in s if ch.isalnum())
    if alnum < 3:
        return True
    return False


class Crawler:
    """Level-by-level breadth-first crawler with concurrent fetching per level."""

    def __init__(
        self,
        target: str,
        depth: int,
        threads: int,
        scope: ScopeChecker,
        client: HTTPClient,
        html_parser: HTMLAnalyzer,
        js_analyzer: JSAnalyzer,
        evader: ProtectionEvader,
        waf_detector: WAFDetector,
        js_only: bool = False,
        verbose: bool = False,
        analyze_offsite: bool = True,
        offsite_cap: int = 80,
        breadth_cap: int = 1000,
    ):
        self.target = target
        self.depth = depth
        self.threads = threads
        self.scope = scope
        self.client = client
        self.html_parser = html_parser
        self.js_analyzer = js_analyzer
        self.evader = evader
        self.waf_detector = waf_detector
        self.js_only = js_only
        self.verbose = verbose
        # Off-site asset policy: an in-scope page's JS is part of its attack surface even
        # when a CDN (cdn.*, *.cloudfront.net, *.akamaized.net, a design-system host, …)
        # serves it. When enabled we fetch+analyse those cross-origin JS/JSON bundles for
        # endpoints/secrets, bounded by `offsite_cap`, but never enqueue off-site HTML into
        # the BFS. Endpoints extracted are still scope-classified afterwards.
        self.analyze_offsite = analyze_offsite
        self.offsite_cap = offsite_cap
        # Upper bound on how many URLs one BFS level may hand to the next. A broad site can
        # emit tens of thousands of links at depth 2-3; without a cap the next level's wall
        # clock explodes. Trimmed after the shuffle so the kept slice stays a random sample.
        self.breadth_cap = breadth_cap
        self._offsite_asset_count = 0
        self.offsite_assets: List[str] = []

        # Discovered state.
        self.visited_pages: Set[str] = set()
        self.visited_js: Set[str] = set()
        self.endpoints: Dict[str, EndpointInfo] = {}
        self.secrets: List[SecretInfo] = []
        self.js_files: List[JSFileInfo] = []
        self.forms: List[FormInfo] = []
        self.html_comments: List[Dict[str, str]] = []
        self._html_comments_seen: Set[Tuple[str, str]] = set()
        self.parameters: Dict[str, ParameterInfo] = {}
        self.out_of_scope: Set[str] = set()
        self.source_maps: List[SourceMapInfo] = []
        self.interesting: Dict[str, List[Dict[str, str]]] = {}
        self.graphql_ops: Set[str] = set()

        self._lock = threading.Lock()

    # ---------- normalisation / dedup ----------

    @staticmethod
    def _normalise(url: str) -> str:
        try:
            sp = urlsplit(url)
            scheme = sp.scheme.lower() or "https"
            host = (sp.hostname or "").lower()
            if not host:
                return url
            port = f":{sp.port}" if sp.port and not (
                (scheme == "http" and sp.port == 80) or (scheme == "https" and sp.port == 443)
            ) else ""
            netloc = host + port
            path = sp.path or "/"
            return urlunsplit((scheme, netloc, path, sp.query, ""))
        except Exception:
            return url

    @staticmethod
    def _origin(url: str) -> str:
        """Return scheme://host[:port] for `url` (empty string on garbage)."""
        try:
            sp = urlsplit(url)
            if not sp.hostname:
                return ""
            return f"{sp.scheme or 'https'}://{sp.netloc}"
        except Exception:
            return ""

    # ---------- off-site asset policy ----------

    def _can_fetch_asset(self, url: str, referer: Optional[str]) -> bool:
        """True if we may fetch `url` as a code asset (JS/JSON) for endpoint/secret analysis.

        In-scope assets: always. Cross-origin assets: only when off-site analysis is enabled,
        the referring page/bundle is itself in-scope, and we're under the off-site cap. This
        lets us read a CDN-hosted bundle that an in-scope page loads (its real attack surface)
        without wandering the whole internet.
        """
        if self.scope.is_excluded(url):
            return False
        if self.scope.in_scope(url):
            return True
        if not self.analyze_offsite:
            return False
        # Don't spend the off-site budget on third-party analytics/ad/consent trackers —
        # they never host the target's API.
        if _is_tracker_host(url):
            return False
        if not (referer and self.scope.in_scope(referer)):
            return False
        with self._lock:
            return self._offsite_asset_count < self.offsite_cap

    def _claim_offsite_slot(self, url: str) -> bool:
        """Atomically reserve one off-site-asset slot; False if the cap is already hit."""
        norm = self._normalise(url)
        with self._lock:
            if self._offsite_asset_count >= self.offsite_cap:
                return False
            self._offsite_asset_count += 1
            self.offsite_assets.append(norm)
            return True

    def _resolve_ep(self, raw: str, js_url: str, referer: Optional[str]) -> str:
        """Resolve an extracted endpoint to an absolute URL.

        A root-relative "/path" reached from a *cross-origin* bundle is an SPA same-origin
        call against the page that loaded the bundle — NOT against the CDN that served it —
        so it resolves against the referring in-scope page origin. Absolute and same-origin
        references resolve normally.
        """
        raw = (raw or "").strip()
        if not raw:
            return raw
        if raw.startswith(("http://", "https://", "//")):
            return urljoin(js_url, raw)
        if raw.startswith("/"):
            js_off = not self.scope.in_scope(js_url)
            if js_off and referer and self.scope.in_scope(referer):
                base = self._origin(referer)
                if base:
                    return urljoin(base + "/", raw.lstrip("/"))
            return urljoin(js_url, raw)
        # Bare relative fragment ("api/v2/x") — resolve against the JS file's directory.
        return urljoin(js_url, raw)

    # ---------- recording helpers ----------

    def _record_endpoint(self, ep: EndpointInfo) -> None:
        # Static assets (images, stylesheets, fonts, media) are not interesting from a
        # security standpoint and just bloat the report — never record them as endpoints.
        if _is_noise_asset(ep.url):
            return
        # XML namespace identifiers / DTD URIs aren't real endpoints — drop them.
        if _is_namespace_pseudo_url(ep.url):
            return
        # Out-of-scope absolute URLs (third-party trackers, partner sites, etc.)
        # belong in `out_of_scope_urls`, not in the endpoints list.
        if not self.scope.in_scope(ep.url):
            with self._lock:
                self.out_of_scope.add(ep.url)
            return
        if self.scope.is_excluded(ep.url):
            return
        key = f"{ep.method}:{ep.url}"
        with self._lock:
            existing = self.endpoints.get(key)
            if existing:
                for p in ep.parameters:
                    if p not in existing.parameters:
                        existing.parameters.append(p)
            else:
                self.endpoints[key] = ep
            for p in ep.parameters:
                if p not in self.parameters:
                    self.parameters[p] = ParameterInfo(name=p, type="query_param")

    def _record_param(self, name: str, where: str, kind: str = "param") -> None:
        with self._lock:
            if name not in self.parameters:
                self.parameters[name] = ParameterInfo(name=name, type=kind)

    def _record_secrets(self, secs: List[SecretInfo]) -> None:
        with self._lock:
            seen = {(s.type, s.value) for s in self.secrets}
            for s in secs:
                if (s.type, s.value) not in seen:
                    self.secrets.append(s)
                    seen.add((s.type, s.value))

    def _record_interesting(self, items: Dict[str, List[str]], source: str) -> None:
        with self._lock:
            for cat, vals in items.items():
                bucket = self.interesting.setdefault(cat, [])
                for v in vals:
                    if not any(b["snippet"] == v and b["source"] == source for b in bucket):
                        bucket.append({"snippet": v, "source": source})

    # ---------- recursive asset following ----------

    def _follow_assets(self, urls: Iterable[str], referer: str) -> None:
        """For each URL: if it's a JS bundle, fetch+analyse via fetch_js; if a manifest
        JSON, fetch+analyse via fetch_page. Both paths recurse, so chunk graphs of any
        depth are walked. Dedup is enforced by the visited_js / visited_pages sets.
        """
        if not urls:
            return
        # De-dupe within this batch first to avoid redundant lock churn.
        seen_in_batch: Set[str] = set()
        for raw in urls:
            if not raw or not isinstance(raw, str):
                continue
            try:
                full = urljoin(referer, raw)
            except Exception:
                continue
            if not full.startswith(("http://", "https://")):
                continue
            norm = self._normalise(full)
            if norm in seen_in_batch:
                continue
            seen_in_batch.add(norm)
            if self.scope.is_excluded(norm):
                continue

            if _looks_like_js(norm):
                # In-scope JS always; cross-origin JS only via the off-site policy (cap +
                # in-scope referer). fetch_js re-checks and claims the slot atomically.
                if not self._can_fetch_asset(norm, referer):
                    if not self.scope.in_scope(norm):
                        with self._lock:
                            self.out_of_scope.add(norm)
                    continue
                with self._lock:
                    if norm in self.visited_js:
                        continue
                self.fetch_js(norm, referer=referer)
            elif _looks_like_manifest_json(norm) and self.scope.in_scope(norm):
                with self._lock:
                    if norm in self.visited_pages:
                        continue
                # fetch_page's JSON branch handles manifests and calls _follow_assets again.
                self.fetch_page(norm, referer=referer)
            elif not self.scope.in_scope(norm):
                with self._lock:
                    self.out_of_scope.add(norm)

    # ---------- fetch / analyse JS ----------

    def fetch_js(self, js_url: str, referer: Optional[str] = None) -> None:
        """Fetch a single JS file, run all extractors, and record findings."""
        norm = self._normalise(js_url)
        host = (urlparse(norm).hostname or "").lower()
        if self.evader.is_rate_limited_hard(host):
            return
        with self._lock:
            if norm in self.visited_js:
                return
            self.visited_js.add(norm)

        if self.scope.is_excluded(norm):
            return
        offsite = not self.scope.in_scope(norm)
        if offsite:
            # A CDN-hosted bundle loaded by an in-scope page is analysable code, but bounded:
            # require the referrer to be in-scope and claim a slot from the off-site cap.
            if not self._can_fetch_asset(norm, referer) or not self._claim_offsite_slot(norm):
                with self._lock:
                    self.out_of_scope.add(norm)
                return

        if self.verbose:
            logger.debug("JS%s %s", " (off-site)" if offsite else "", norm)

        resp = self.client.request("GET", norm, kind="script", referer=referer)
        if resp is None or resp.status_code >= 400:
            return

        try:
            text = resp.text
        except Exception:
            return
        if not text:
            return

        size = len(resp.content) if resp.content else 0

        eps = self.js_analyzer.extract_endpoints(text, norm)
        for ep in eps:
            # Root-relative paths from a cross-origin bundle are SPA calls against the page
            # that loaded it, not the CDN that served it — resolve accordingly (_resolve_ep).
            try:
                ep.url = self._resolve_ep(ep.url, norm, referer)
            except Exception:
                pass
            self._record_endpoint(ep)

        secs = self.js_analyzer.extract_secrets(text, norm)
        self._record_secrets(secs)

        for p in self.js_analyzer.extract_parameters(text):
            self._record_param(p, norm, kind="js_extracted")

        interest = self.js_analyzer.extract_interesting(text)
        self._record_interesting(interest, norm)

        for op in self.js_analyzer.extract_graphql(text):
            with self._lock:
                self.graphql_ops.add(op)

        # Recursively fetch any JS chunks / nested manifests this bundle references. Propagate
        # the original page referer (not this JS URL) so a CDN bundle's sibling chunks stay
        # reachable and relative paths keep resolving against the in-scope page origin.
        self._follow_assets((ep.url for ep in eps), referer=referer or norm)

        smap = self.js_analyzer.find_source_map(text)
        smap_url = ""
        if smap:
            try:
                smap_url = urljoin(norm, smap)
            except Exception:
                smap_url = smap
            self._check_source_map(smap_url, referer=norm)

        with self._lock:
            self.js_files.append(JSFileInfo(
                url=norm,
                size_bytes=size,
                endpoints_found=len(eps),
                secrets_found=len(secs),
                source_map_available=bool(smap),
                source_map_url=smap_url,
            ))

    def _check_source_map(self, smap_url: str, referer: Optional[str]) -> None:
        """If a sourceMappingURL is reachable and yields original sources, flag it."""
        if not self.scope.in_scope(smap_url):
            return
        resp = self.client.request("GET", smap_url, kind="json", referer=referer)
        if resp is None or resp.status_code >= 400:
            with self._lock:
                self.source_maps.append(SourceMapInfo(
                    url=smap_url, contains_original_source=False,
                    note="referenced but not accessible",
                ))
            return
        try:
            data = resp.json()
            has_src = bool(data.get("sourcesContent")) or bool(data.get("sources"))
        except Exception:
            has_src = False
        with self._lock:
            self.source_maps.append(SourceMapInfo(
                url=smap_url,
                contains_original_source=has_src,
                note="CRITICAL: Full original source code exposed!" if has_src
                     else "source map fetched but no original source",
            ))

    # ---------- fetch / analyse HTML ----------

    def fetch_page(self, url: str, referer: Optional[str] = None) -> Set[str]:
        """Fetch + parse one HTML page; returns the set of in-scope links to enqueue next."""
        norm = self._normalise(url)
        host = (urlparse(norm).hostname or "").lower()
        if self.evader.is_rate_limited_hard(host):
            return set()
        with self._lock:
            if norm in self.visited_pages:
                return set()
            self.visited_pages.add(norm)

        if not self.scope.in_scope(norm):
            with self._lock:
                self.out_of_scope.add(norm)
            return set()
        if self.scope.is_excluded(norm):
            return set()

        if self.verbose:
            logger.info("GET %s", norm)
        else:
            logger.debug("GET %s", norm)

        resp = self.client.request("GET", norm, kind="html", referer=referer)
        if resp is None:
            return set()

        # Look for JSON / API responses crawled from /api/ etc.
        ct = (resp.headers.get("Content-Type") or "").lower()
        # Some servers serve JSON manifests with content-type text/plain or
        # application/octet-stream; treat URLs that look like manifests as JSON too.
        is_manifest_url = _looks_like_manifest_json(norm)
        if ("json" in ct or is_manifest_url) and resp.text:
            # Treat JSON responses as endpoints — re-analyse for nested URLs.
            eps = self.js_analyzer.extract_endpoints(resp.text, norm)
            for ep in eps:
                try:
                    ep.url = urljoin(norm, ep.url)
                except Exception:
                    pass
                self._record_endpoint(ep)
            secs = self.js_analyzer.extract_secrets(resp.text, norm)
            self._record_secrets(secs)
            # Recursively fetch any JS bundles or nested manifests referenced here.
            # This is the case for build-tool import maps like /admin-import-map.json
            # whose values are paths to JS chunks (/static/js/main.<hash>.bundle.js).
            self._follow_assets((ep.url for ep in eps), referer=norm)
            return set()

        if "html" not in ct and "xml" not in ct:
            return set()

        try:
            html = resp.text
        except Exception:
            return set()

        parsed = self.html_parser.parse(html, norm)

        # Forms.
        with self._lock:
            for f in parsed["forms"]:
                self.forms.append(f)
                for inp in f.inputs:
                    if inp not in self.parameters:
                        self.parameters[inp] = ParameterInfo(name=inp, type="form_field")

        # Comments — filter framework runtime markers (React Suspense $, /$, $?, etc.)
        # and dedupe by (comment, source) so the same hint isn't recorded N times.
        with self._lock:
            for c in parsed["comments"]:
                if _is_noise_comment(c):
                    continue
                trimmed = c.strip()[:1000]
                key = (trimmed, norm)
                if key in self._html_comments_seen:
                    continue
                self._html_comments_seen.add(key)
                self.html_comments.append({"comment": trimmed, "source": norm})

        # Inline scripts.
        for inline in parsed["inline_scripts"]:
            eps = self.js_analyzer.extract_endpoints(inline, f"{norm} (inline)")
            for ep in eps:
                try:
                    ep.url = urljoin(norm, ep.url)
                except Exception:
                    pass
                self._record_endpoint(ep)
            self._record_secrets(self.js_analyzer.extract_secrets(inline, f"{norm} (inline)"))
            for p in self.js_analyzer.extract_parameters(inline):
                self._record_param(p, f"{norm} (inline)", kind="js_extracted")
            self._record_interesting(
                self.js_analyzer.extract_interesting(inline), f"{norm} (inline)",
            )
            # Recursively fetch any JS bundles referenced by inline scripts.
            self._follow_assets((ep.url for ep in eps), referer=norm)

        # External JS (<script src>). In-scope always; cross-origin bundles (CDN-hosted app
        # code, e.g. cdn.zeroheight.com) go through the off-site policy so we analyse the same
        # code the browser actually loads instead of discarding it as out-of-scope.
        scripts = list(parsed["scripts"])
        for src in scripts:
            n_src = self._normalise(src)
            if n_src in self.visited_js:
                continue
            if self._can_fetch_asset(n_src, norm):
                self.fetch_js(src, referer=norm)
            elif not self.scope.in_scope(src):
                with self._lock:
                    self.out_of_scope.add(n_src)

        # Data-attribute / extracted URLs.
        for da in parsed["data_attrs"]:
            if da.startswith(("/", "http://", "https://")):
                full = urljoin(norm, da)
                if self.scope.in_scope(full):
                    self._record_endpoint(EndpointInfo(url=full, method="GET"))
        # Follow JS bundles / manifests referenced via data-* attrs.
        self._follow_assets(parsed["data_attrs"], referer=norm)

        # Build the next-level link set.
        next_urls: Set[str] = set()
        for link in parsed["links"]:
            if not link or link.startswith(("javascript:", "mailto:", "tel:", "data:")):
                continue
            try:
                full = urljoin(norm, link)
                # Strip fragments — they don't change the resource.
                full = full.split("#", 1)[0]
            except Exception:
                continue
            # Drop static assets (images, stylesheets, fonts, media) — not app surfaces.
            if _is_noise_asset(full):
                continue
            if not self.scope.in_scope(full):
                with self._lock:
                    self.out_of_scope.add(full)
                continue
            if self.scope.is_excluded(full):
                continue
            n = self._normalise(full)
            # JS bundles and manifest JSONs go through their own pipelines —
            # they would otherwise be skipped by the HTML content-type check.
            if _looks_like_js(n):
                with self._lock:
                    already = n in self.visited_js
                if not already:
                    self.fetch_js(n, referer=norm)
                continue
            if _looks_like_manifest_json(n):
                with self._lock:
                    already = n in self.visited_pages
                if not already:
                    # Manifests still go through fetch_page (JSON branch handles them
                    # and recurses into JS chunks), but skip BFS enqueue.
                    self.fetch_page(n, referer=norm)
                continue
            with self._lock:
                if n in self.visited_pages:
                    continue
            next_urls.add(n)

        if parsed["meta_redirect"]:
            redir = urljoin(norm, parsed["meta_redirect"])
            if self.scope.in_scope(redir):
                next_urls.add(self._normalise(redir))

        return next_urls

    # ---------- main crawl loop ----------

    def crawl(self) -> None:
        """Run BFS up to `self.depth` levels using a thread pool per level."""
        if self.js_only:
            self._run_js_only()
            return

        target_host = (urlparse(self.target).hostname or "").lower()
        current: Set[str] = {self._normalise(self.target)}
        for level in range(self.depth + 1):
            if not current:
                break
            if self.evader.is_rate_limited_hard(target_host):
                logger.warning("Aborting crawl at depth %d — target is rate-limiting us.", level)
                break
            logger.info("Depth %d/%d — %d URL(s) to fetch", level, self.depth, len(current))
            with ThreadPoolExecutor(max_workers=self.threads) as pool:
                futures = {pool.submit(self.fetch_page, u): u for u in current}
                next_level: Set[str] = set()
                for fut in as_completed(futures):
                    try:
                        new = fut.result() or set()
                    except Exception as exc:  # never crash the crawl on one URL
                        logger.warning("Worker error on %s: %s", futures[fut], exc)
                        new = set()
                    next_level |= new
            if self.evader.is_rate_limited_hard(target_host):
                logger.warning("Target marked as rate-limited — stopping further BFS levels.")
                break
            # Randomise order so we don't crawl alphabetically.
            next_level_list = list(next_level)
            random.shuffle(next_level_list)
            # Trim to a sane upper bound to avoid runaway breadth.
            if self.breadth_cap > 0 and len(next_level_list) > self.breadth_cap:
                logger.warning("Trimming next-level URLs from %d to %d",
                               len(next_level_list), self.breadth_cap)
                next_level_list = next_level_list[:self.breadth_cap]
            current = set(next_level_list)

    def _run_js_only(self) -> None:
        """Fetch the target page once, analyse all JS files it references, then stop."""
        logger.info("JS-only mode: fetching target then analysing only JS files")
        target = self._normalise(self.target)
        target_host = (urlparse(target).hostname or "").lower()
        resp = self.client.request("GET", target, kind="html")
        if resp is None:
            if self.evader.is_rate_limited_hard(target_host):
                logger.error("Target is rate-limiting us — aborting JS-only scan.")
            else:
                logger.error("Could not fetch target")
            return
        try:
            html = resp.text
        except Exception:
            return
        parsed = self.html_parser.parse(html, target)

        # Inline scripts.
        for inline in parsed["inline_scripts"]:
            eps = self.js_analyzer.extract_endpoints(inline, f"{target} (inline)")
            for ep in eps:
                try:
                    ep.url = urljoin(target, ep.url)
                except Exception:
                    pass
                self._record_endpoint(ep)
            self._record_secrets(self.js_analyzer.extract_secrets(inline, f"{target} (inline)"))
            for p in self.js_analyzer.extract_parameters(inline):
                self._record_param(p, f"{target} (inline)", kind="js_extracted")

        # External scripts in parallel — include cross-origin CDN bundles via the off-site
        # policy (fetch_js re-checks the cap + in-scope-referer per asset before fetching).
        scripts = [s for s in parsed["scripts"]
                   if self._can_fetch_asset(self._normalise(s), target)]
        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futures = [pool.submit(self.fetch_js, s, target) for s in scripts]
            for _ in as_completed(futures):
                pass


# ---------------------------------------------------------------------------
# Smart path discovery (with WAF bypass on 403)
# ---------------------------------------------------------------------------

class SmartPathDiscovery:
    """Probes well-known sensitive paths and applies bypass tricks to 403s."""

    def __init__(
        self,
        target: str,
        client: HTTPClient,
        scope: ScopeChecker,
        evader: ProtectionEvader,
        waf_detector: WAFDetector,
        threads: int,
        verbose: bool = False,
    ):
        self.target = target
        self.client = client
        self.scope = scope
        self.evader = evader
        self.waf_detector = waf_detector
        self.threads = threads
        self.verbose = verbose

        self.interesting_paths: List[PathInfo] = []
        self.waf_blocked_paths: List[WAFBlockedPath] = []
        self._lock = threading.Lock()

        # Soft-404 baselines: fingerprints of "what unknown paths look like on this target".
        # If a probe response matches any baseline, it's treated as a false positive.
        self.baselines: List[Dict[str, Any]] = []
        self.soft_404_filtered = 0  # how many probes we suppressed
        self.baseline_is_200 = False  # True iff the target serves 2xx for unknown paths

    # ---------- soft-404 / catch-all detection ----------

    BASELINE_PROBES = 2  # Number of random nonsense paths to fingerprint at start.

    @staticmethod
    def _hash_body(body: bytes) -> str:
        """SHA1 of the first 4 KiB of the body — stable enough for soft-404 comparison."""
        return hashlib.sha1(body[:4096]).hexdigest() if body else ""

    @staticmethod
    def _extract_title(body: bytes) -> str:
        try:
            m = re.search(rb"<title[^>]*>([^<]{0,200})</title>", body, re.IGNORECASE)
            return m.group(1).decode("utf-8", errors="ignore").strip() if m else ""
        except Exception:
            return ""

    def _establish_baseline(self) -> None:
        """Probe a couple of guaranteed-non-existent paths so we know what soft-404s look like.

        Many SPAs and catch-all routes return 200 with `index.html` for any path. Without a
        baseline we'd flag every smart-path probe as "interesting". We fingerprint the response
        (status, content-type, body length, sha1, title) and later filter probes that match.
        """
        target_host = (urlparse(self.target).hostname or "").lower()
        if self.evader.is_rate_limited_hard(target_host):
            return

        for _ in range(self.BASELINE_PROBES):
            token = "".join(random.choices(string.ascii_lowercase + string.digits, k=18))
            url = self.target.rstrip("/") + f"/__bh_probe_{token}_doesnotexist"
            resp = self.client.request("GET", url, kind="html")
            if not resp:
                continue
            ct = (resp.headers.get("Content-Type") or "").split(";")[0].strip().lower()
            body = resp.content or b""
            self.baselines.append({
                "status": resp.status_code,
                "content_type": ct,
                "length": len(body),
                "hash": self._hash_body(body),
                "title": self._extract_title(body) if "html" in ct else "",
            })

        if not self.baselines:
            return
        statuses = sorted({b["status"] for b in self.baselines})
        if any(200 <= s < 400 for s in statuses):
            self.baseline_is_200 = True
            logger.info(
                "Soft-404 mode active: target returns %s for unknown paths "
                "(probe responses matching this fingerprint will be filtered).",
                statuses,
            )
        else:
            logger.debug("Baseline (unknown paths) returns %s — proper 404 handling.", statuses)

    def _is_soft_404(self, resp: requests.Response, path: str) -> bool:
        """Return True if `resp` is almost certainly a catch-all soft 404 (false positive)."""
        body = resp.content or b""
        ct = (resp.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        body_len = len(body)
        body_hash = self._hash_body(body)

        # Fingerprint comparison against captured baselines.
        for b in self.baselines:
            if resp.status_code != b["status"]:
                continue
            if ct != b["content_type"]:
                continue
            # Strong signal — exact body hash match.
            if body_hash and body_hash == b["hash"]:
                return True
            base_len = b["length"]
            if base_len > 0:
                diff = abs(body_len - base_len)
                ratio = diff / base_len
                if diff <= 64 or ratio <= 0.05:
                    if "html" in ct:
                        title = self._extract_title(body)
                        if title and title == b.get("title", ""):
                            return True
                    else:
                        return True

        # Path-specific content-type sanity: if the path strongly implies a non-HTML
        # type but we got HTML back, it's an SPA catch-all. This catches the case
        # where the baseline wasn't established (e.g. fetch failed).
        low = path.lower()
        is_html_resp = "html" in ct
        if is_html_resp:
            if low.endswith((".json", ".xml", ".yaml", ".yml", ".env", ".config",
                             ".ini", ".sql", ".bak", ".gz", ".zip", ".tar")):
                return True
            if low.endswith(("/.git/config", "/.git/head", "/.git/index",
                             "/.htaccess", "/.htpasswd", "/.ds_store",
                             "/robots.txt", "/security.txt", "/crossdomain.xml",
                             "/sitemap.xml")):
                return True
        # Body-shape sanity for paths whose response body should clearly be JSON/XML.
        if low.endswith(".json") and body and not body.lstrip().startswith((b"{", b"[")):
            return True
        if low.endswith(".xml") and body and not body.lstrip().startswith((b"<?xml", b"<")):
            return True

        return False

    def _try_bypass(self, base: str, path: str, original_status: int) -> Tuple[bool, str, List[str]]:
        """Try every bypass variant; return (success, success_label, attempted_labels).

        A "success" must be a 2xx/3xx that isn't itself a soft-404 catch-all — otherwise
        every variant of every blocked path would trivially "succeed" against an SPA.
        """
        attempted: List[str] = []
        # Path manipulations.
        for label, variant in WAFBypass.path_variants(path):
            attempted.append(f"path:{label}")
            url = base.rstrip("/") + variant
            resp = self.client.request("GET", url, kind="html")
            if resp and 200 <= resp.status_code < 400 and not self._is_soft_404(resp, path):
                self.evader.bypass_methods_used.add("path-encoding bypass")
                return True, f"{variant} -> {resp.status_code}", attempted
        # Method switch.
        for method in WAFBypass.methods_to_try():
            attempted.append(f"method:{method}")
            resp = self.client.request(method, base.rstrip("/") + path, kind="html")
            if resp and 200 <= resp.status_code < 400 and not self._is_soft_404(resp, path):
                self.evader.bypass_methods_used.add("method-switch bypass")
                return True, f"{method} -> {resp.status_code}", attempted
        return False, "", attempted

    def _probe_one(self, path: str) -> None:
        url = self.target.rstrip("/") + path
        if not self.scope.in_scope(url):
            return
        host = (urlparse(url).hostname or "").lower()
        if self.evader.is_rate_limited_hard(host):
            return  # circuit-broken; don't even queue requests
        resp = self.client.request("GET", url, kind="html")
        if not resp:
            return
        status = resp.status_code

        if status == 403:
            waf_name = self.waf_detector.inspect(resp) or "unknown"
            success, result, attempted = self._try_bypass(self.target, path, status)
            with self._lock:
                self.waf_blocked_paths.append(WAFBlockedPath(
                    path=path, status=status, waf=waf_name,
                    bypass_attempts=attempted, bypass_successful=success,
                ))
                if success:
                    self.interesting_paths.append(PathInfo(
                        path=path, status_code=status,
                        bypass_attempted=True, bypass_result=result,
                        note="403 bypassed!",
                    ))
        elif 200 <= status < 400:
            # Filter SPA catch-all / soft-404 responses before flagging.
            if self._is_soft_404(resp, path):
                with self._lock:
                    self.soft_404_filtered += 1
                if self.verbose:
                    logger.debug("Filtered soft-404: %s -> %d", path, status)
                return
            note = ""
            low = path.lower()
            if any(k in low for k in ("/.env", "/.git", "/admin", "/dashboard", "actuator",
                                       "swagger", "graphql", "phpinfo", "wp-admin",
                                       "console", "backup", "dump.sql", "/.svn", "/.DS_Store",
                                       "package.json", "/.well-known/security")):
                note = "Sensitive path is accessible — investigate."
            with self._lock:
                self.interesting_paths.append(PathInfo(
                    path=path, status_code=status,
                    bypass_attempted=False, note=note,
                ))
        elif status in (401, 405):
            with self._lock:
                self.interesting_paths.append(PathInfo(
                    path=path, status_code=status, note="auth-required / method-only",
                ))

    def run(self) -> None:
        """Probe every path in `SMART_PATHS` concurrently. Bails fast if target is hard-blocked."""
        target_host = (urlparse(self.target).hostname or "").lower()
        if self.evader.is_rate_limited_hard(target_host):
            logger.warning("Skipping smart-path discovery — target is rate-limiting us.")
            return
        # Fingerprint soft-404 / SPA catch-all responses BEFORE the real probes.
        self._establish_baseline()
        if self.evader.is_rate_limited_hard(target_host):
            logger.warning("Aborting smart-path discovery — rate-limited during baseline.")
            return
        logger.info("Smart-path discovery: probing %d paths", len(SMART_PATHS))
        # Randomise order so we don't probe alphabetically.
        paths = SMART_PATHS[:]
        random.shuffle(paths)
        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futures = [pool.submit(self._probe_one, p) for p in paths]
            for _ in as_completed(futures):
                pass
        if self.soft_404_filtered:
            logger.info("Soft-404 filter suppressed %d false-positive probe(s).",
                        self.soft_404_filtered)


# ---------------------------------------------------------------------------
# Report generator
# ---------------------------------------------------------------------------

class ReportGenerator:
    """Builds the structured JSON report and prints a colourised terminal summary."""

    SEVERITY_COLOUR = {
        "CRITICAL": Fore.RED + Style.BRIGHT,
        "HIGH": Fore.YELLOW + Style.BRIGHT,
        "MEDIUM": Fore.YELLOW,
        "LOW": Fore.CYAN,
        "INFO": Fore.GREEN,
    }

    def __init__(
        self,
        target: str,
        crawler: Crawler,
        path_discovery: SmartPathDiscovery,
        client: HTTPClient,
        evader: ProtectionEvader,
        waf_detector: WAFDetector,
        started_at: float,
        show_out_of_scope: bool = False,
    ):
        self.target = target
        self.crawler = crawler
        self.path_discovery = path_discovery
        self.client = client
        self.evader = evader
        self.waf_detector = waf_detector
        self.started_at = started_at
        self.show_out_of_scope = show_out_of_scope

    @staticmethod
    def _fmt_duration(seconds: float) -> str:
        m, s = divmod(int(seconds), 60)
        h, m = divmod(m, 60)
        if h:
            return f"{h}h {m}m {s}s"
        if m:
            return f"{m}m {s}s"
        return f"{s}s"

    def build(self) -> Dict[str, Any]:
        """Return the report as a JSON-serialisable dict."""
        elapsed = time.time() - self.started_at
        endpoints = list(self.crawler.endpoints.values())

        report: Dict[str, Any] = {
            "target": self.target,
            "scan_date": datetime.now().astimezone().isoformat(timespec="seconds"),
            "scan_duration": self._fmt_duration(elapsed),
            "protection_detected": sorted(self.waf_detector.detected),
            "bypass_methods_used": sorted(self.evader.bypass_methods_used),
            "stats": {
                "total_requests": self.client.total,
                "successful": self.client.successful,
                "failed": self.client.failed,
                "blocked_by_waf": self.client.blocked,
                "bypassed": sum(1 for p in self.path_discovery.waf_blocked_paths if p.bypass_successful),
                "pages_crawled": len(self.crawler.visited_pages),
                "js_files_analyzed": len(self.crawler.js_files),
                "offsite_js_analyzed": len(self.crawler.offsite_assets),
                "unique_endpoints_found": len(endpoints),
                "secrets_found": len(self.crawler.secrets),
                "parameters_found": len(self.crawler.parameters),
                "forms_found": len(self.crawler.forms),
                "interesting_paths": len(self.path_discovery.interesting_paths),
                "waf_blocked_paths": len(self.path_discovery.waf_blocked_paths),
                "soft_404_filtered": self.path_discovery.soft_404_filtered,
                "soft_404_baseline_active": self.path_discovery.baseline_is_200,
                "out_of_scope_urls": len(self.crawler.out_of_scope),
                "graphql_operations": len(self.crawler.graphql_ops),
                "html_comments": len(self.crawler.html_comments),
                "source_maps_referenced": len(self.crawler.source_maps),
            },
            "endpoints": [asdict(e) for e in endpoints],
            "secrets": [asdict(s) for s in self.crawler.secrets],
            "parameters": [asdict(p) for p in self.crawler.parameters.values()],
            "forms": [asdict(f) for f in self.crawler.forms],
            "interesting_paths": [asdict(p) for p in self.path_discovery.interesting_paths],
            "waf_blocked_paths": [asdict(p) for p in self.path_discovery.waf_blocked_paths],
            "html_comments": self.crawler.html_comments[:500],
            "source_maps": [asdict(s) for s in self.crawler.source_maps],
            "interesting_findings": self.crawler.interesting,
            "graphql_operations": sorted(self.crawler.graphql_ops),
            "offsite_assets_analyzed": self.crawler.offsite_assets[:200],
        }
        if self.show_out_of_scope:
            report["out_of_scope_urls"] = sorted(self.crawler.out_of_scope)[:1000]
        return report

    def write_json(self, report: Dict[str, Any], path: str) -> None:
        """Write the report to disk, creating parent dirs if needed."""
        parent = os.path.dirname(os.path.abspath(path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, ensure_ascii=False)

    # ---------- terminal summary ----------

    @staticmethod
    def _line(char: str = "=", n: int = 78) -> str:
        return char * n

    def print_summary(self, report: Dict[str, Any], output_path: str) -> None:
        """Pretty-print the high-signal findings to the terminal."""
        bold = Style.BRIGHT
        reset = Style.RESET_ALL
        s = report["stats"]

        print()
        print(Fore.CYAN + bold + self._line() + reset)
        print(Fore.CYAN + bold + f" BUG-HUNTER REPORT — {report['target']}" + reset)
        print(Fore.CYAN + bold + self._line() + reset)
        print(f"  Scan date     : {report['scan_date']}")
        print(f"  Duration      : {report['scan_duration']}")
        print(f"  WAFs detected : "
              + (Fore.YELLOW + ", ".join(report['protection_detected']) + reset
                 if report['protection_detected'] else Fore.GREEN + "none detected" + reset))
        bypass_str = ", ".join(report["bypass_methods_used"]) or "n/a"
        print(f"  Bypass methods: {bypass_str}")

        # ---- stats ----
        print()
        print(Fore.CYAN + bold + " Stats" + reset)
        print(self._line("-"))
        print(f"  Total requests : {s['total_requests']}  "
              f"({Fore.GREEN}{s['successful']} ok{reset}, "
              f"{Fore.YELLOW}{s['failed']} failed{reset}, "
              f"{Fore.RED}{s['blocked_by_waf']} blocked{reset})")
        print(f"  Pages crawled  : {s['pages_crawled']}")
        print(f"  JS analysed    : {s['js_files_analyzed']}")
        if s.get('offsite_js_analyzed'):
            print(f"  Off-site JS    : {Fore.YELLOW}{s['offsite_js_analyzed']}{reset} "
                  f"(cross-origin/CDN bundles analysed)")
        print(f"  Endpoints      : {s['unique_endpoints_found']}")
        print(f"  Parameters     : {s['parameters_found']}")
        print(f"  Forms          : {s['forms_found']}")
        print(f"  Out-of-scope   : {s['out_of_scope_urls']}")

        # ---- secrets ----
        if report["secrets"]:
            print()
            print(Fore.RED + bold + f" SECRETS FOUND ({len(report['secrets'])})" + reset)
            print(self._line("-"))
            for sec in report["secrets"][:25]:
                colour = self.SEVERITY_COLOUR.get(sec["severity"], "")
                print(f"  {colour}[{sec['severity']:8}] {sec['type']:22}{reset} "
                      f"{Fore.WHITE}{sec['redacted']}{reset}")
                print(f"           in {sec['found_in']}:{sec['line']}")

        # ---- bypassed paths ----
        bypassed = [p for p in report["interesting_paths"] if p.get("bypass_attempted") and "bypass" in (p.get("note") or "").lower()]
        if bypassed:
            print()
            print(Fore.YELLOW + bold + f" 403 BYPASS SUCCESSES ({len(bypassed)})" + reset)
            print(self._line("-"))
            for p in bypassed:
                print(f"  {Fore.YELLOW}{p['path']}{reset}  ->  {p['bypass_result']}")

        # ---- interesting paths ----
        if report["interesting_paths"]:
            sensitive = [p for p in report["interesting_paths"]
                         if 200 <= p["status_code"] < 400 and (p.get("note") or "").lower().startswith("sensitive")]
            if sensitive:
                print()
                print(Fore.RED + bold + f" SENSITIVE PATHS ACCESSIBLE ({len(sensitive)})" + reset)
                print(self._line("-"))
                for p in sensitive[:25]:
                    print(f"  {Fore.RED}{p['status_code']}{reset}  {p['path']}")

        # ---- source maps ----
        critical_maps = [m for m in report["source_maps"] if m.get("contains_original_source")]
        if critical_maps:
            print()
            print(Fore.RED + bold + f" SOURCE MAPS WITH ORIGINAL SOURCE ({len(critical_maps)})" + reset)
            print(self._line("-"))
            for m in critical_maps[:10]:
                print(f"  {Fore.RED}{m['url']}{reset}")

        # ---- top endpoints ----
        if report["endpoints"]:
            print()
            print(Fore.GREEN + bold + f" TOP ENDPOINTS ({min(15, len(report['endpoints']))} of {len(report['endpoints'])})" + reset)
            print(self._line("-"))
            for ep in report["endpoints"][:15]:
                params = ",".join(ep["parameters"][:6])
                params_part = f"  ?{params}" if params else ""
                print(f"  {ep['method']:6}  {ep['url']}{params_part}")

        # ---- next steps ----
        print()
        print(Fore.CYAN + bold + " Suggested next steps" + reset)
        print(self._line("-"))
        steps: List[str] = []
        if any(s["severity"] == "CRITICAL" for s in report["secrets"]):
            steps.append("Rotate exposed credentials immediately and report to the program.")
        if critical_maps:
            steps.append("Review .map files — original source may reveal further bugs.")
        if any(p.get("bypass_successful") for p in report["waf_blocked_paths"]):
            steps.append("Replicate the WAF bypass manually and document the path/payload.")
        if sensitive := [p for p in report["interesting_paths"]
                         if 200 <= p["status_code"] < 400
                         and "sensitive" in (p.get("note") or "").lower()]:
            steps.append("Manually visit each sensitive path; verify auth and data exposure.")
        if report["stats"]["graphql_operations"]:
            steps.append("Probe GraphQL with introspection / batched queries for IDOR.")
        if not steps:
            steps.append("Review the full JSON report for follow-up leads.")
        for i, st in enumerate(steps, 1):
            print(f"  {i}. {st}")

        print()
        print(Fore.CYAN + bold + f" Full JSON report -> {output_path}" + reset)
        print(Fore.CYAN + bold + self._line() + reset)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _default_output(target: str) -> str:
    """Build a default report filename of the form ./report_<domain>_<ts>.json."""
    domain = (urlparse(target).hostname or "target").replace(".", "_")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"./report_{domain}_{ts}.json"


def _parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="bug_hunter_crawler",
        description="Production-grade bug-bounty reconnaissance crawler.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--target", help="Base URL to start crawling")
    p.add_argument("--targets-file", "-l", default=None,
                   help="File with one URL per line. Lines starting with # are comments. "
                        "All targets are scanned and merged into a SINGLE consolidated report.")
    p.add_argument("--depth", type=int, default=5, help="Max crawl depth (default: 5)")
    p.add_argument("--output", default=None,
                   help="Output JSON path. With --targets-file this is the path of the single "
                        "consolidated report (default: ./report_combined_<ts>.json). "
                        "Without --targets-file, default is ./report_<domain>_<ts>.json.")
    p.add_argument("--timeout", type=float, default=10.0,
                   help="Per-request timeout in seconds (default: 10)")
    p.add_argument("--threads", type=int, default=10,
                   help="Number of concurrent threads (default: 10)")
    p.add_argument("--headers", default=None,
                   help='Custom headers as a JSON string, e.g. \'{"Cookie": "session=abc"}\'')
    p.add_argument("--scope", default="",
                   help="Additional in-scope hosts, comma-separated (e.g. api.x.com,admin.x.com)")
    p.add_argument("--exclude", default="",
                   help="Path prefixes to exclude, comma-separated (e.g. /logout,/delete)")
    p.add_argument("--js-only", action="store_true",
                   help="Only analyse JS files, skip HTML crawling")
    p.add_argument("--no-smart-paths", "--no-bruteforce", dest="no_smart_paths",
                   action="store_true",
                   help="Disable Smart-path discovery — the built-in brute-force probe of "
                        "common config/admin/debug/backup/leak paths (SMART_PATHS). Only the "
                        "link crawl + JS analysis run. Use on fragile targets or to avoid "
                        "hammering a host with wordlist requests.")
    p.add_argument("--verbose", action="store_true", help="Show detailed output while running")
    p.add_argument("--stealth", action="store_true",
                   help="Maximum stealth mode (slow crawl + extra evasion)")
    p.add_argument("--delay", type=float, default=0.5,
                   help="Base delay between requests in seconds (default: 0.5)")
    p.add_argument("--show-out-of-scope", action="store_true",
                   help="Include the out_of_scope_urls list in the JSON report (off by default)")
    p.add_argument("--no-offsite-js", action="store_true",
                   help="Do NOT fetch cross-origin (CDN-hosted) JS bundles referenced by "
                        "in-scope pages. By default such bundles ARE analysed for endpoints / "
                        "secrets (bounded by --offsite-cap) — that's where modern SPA API "
                        "routes live (e.g. app code served from cdn.* / *.cloudfront.net).")
    p.add_argument("--offsite-cap", type=int, default=80,
                   help="Max cross-origin JS/JSON assets to fetch for code analysis (default: 80)")
    p.add_argument("--breadth-cap", type=int, default=1000,
                   help="Max URLs carried from one crawl depth to the next (default: 1000). "
                        "Lower it to keep wide sites fast; 0 disables the cap entirely.")
    return p.parse_args(argv)


def _load_targets_file(path: str) -> List[str]:
    """Read targets from a text file. One URL per line; blank lines and `#` comments ignored."""
    expanded = os.path.expanduser(path)
    if not os.path.isfile(expanded):
        raise FileNotFoundError(f"Targets file not found: {expanded}")
    out: List[str] = []
    with open(expanded, "r", encoding="utf-8", errors="ignore") as fh:
        for raw in fh:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            # Allow optional leading "- " from yaml-style lists
            if line.startswith("- "):
                line = line[2:].strip()
            out.append(line)
    return out


def _normalise_target(raw: str) -> Optional[str]:
    """Normalise a single target string: add scheme if missing, validate hostname. Returns None on garbage."""
    target = raw.strip().rstrip("/")
    if not target:
        return None
    if not re.match(r"^https?://", target, re.IGNORECASE):
        target = "https://" + target
    if not urlparse(target).hostname:
        return None
    return target


def _default_combined_output() -> str:
    """Default filename for the consolidated multi-target report."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"./report_combined_{ts}.json"


def _aggregate_stats(reports: List[Dict[str, Any]]) -> Dict[str, int]:
    """Sum per-target stat counters into a single combined stats dict."""
    keys = (
        "total_requests", "successful", "failed", "blocked_by_waf", "bypassed",
        "pages_crawled", "js_files_analyzed", "offsite_js_analyzed",
        "unique_endpoints_found",
        "secrets_found", "parameters_found", "forms_found",
        "interesting_paths", "waf_blocked_paths", "soft_404_filtered",
        "out_of_scope_urls", "graphql_operations", "html_comments",
        "source_maps_referenced",
    )
    out: Dict[str, int] = {k: 0 for k in keys}
    for r in reports:
        st = r.get("stats", {})
        for k in keys:
            v = st.get(k, 0)
            if isinstance(v, (int, float)):
                out[k] += int(v)
    return out


def _run_one_target(
    target: str,
    args: argparse.Namespace,
    output_path: str,
    *,
    write_json: bool = True,
) -> Tuple[int, Optional[Dict[str, Any]]]:
    """Run the full pipeline (crawl + smart-path discovery + report) for a single target.

    Returns (return_code, report_dict). When `write_json=False` the JSON file is NOT written —
    the caller is responsible for combining `report_dict` into a consolidated report.
    """
    # Custom headers.
    custom_headers: Dict[str, str] = {}
    if args.headers:
        try:
            custom_headers = json.loads(args.headers)
            if not isinstance(custom_headers, dict):
                raise ValueError("headers must be a JSON object")
        except Exception as exc:
            logger.error("Failed to parse --headers JSON: %s", exc)
            return 2, None

    # Scope.
    extra_scopes = [s for s in (args.scope.split(",") if args.scope else []) if s.strip()]
    excludes = [s for s in (args.exclude.split(",") if args.exclude else []) if s.strip()]
    scope = ScopeChecker(target, extra_scopes, excludes)

    # Stealth mode tweaks.
    base_delay = args.delay
    threads = args.threads
    if args.stealth:
        base_delay = max(args.delay, 1.5)
        threads = min(args.threads, 4)
        logger.info("Stealth mode ON — delay >= %.1fs, threads <= %d", base_delay, threads)

    # Build the pipeline (fresh state per target — counters, dedup sets, sessions).
    evader = ProtectionEvader(stealth=args.stealth, base_delay=base_delay)
    waf_detector = WAFDetector()
    client = HTTPClient(evader, waf_detector,
                        timeout=args.timeout, custom_headers=custom_headers)
    html_parser = HTMLAnalyzer()
    js_analyzer = JSAnalyzer()

    crawler = Crawler(
        target=target, depth=args.depth, threads=threads,
        scope=scope, client=client, html_parser=html_parser,
        js_analyzer=js_analyzer, evader=evader, waf_detector=waf_detector,
        js_only=args.js_only, verbose=args.verbose,
        analyze_offsite=not args.no_offsite_js, offsite_cap=args.offsite_cap,
        breadth_cap=args.breadth_cap,
    )
    path_discovery = SmartPathDiscovery(
        target=target, client=client, scope=scope, evader=evader,
        waf_detector=waf_detector, threads=threads, verbose=args.verbose,
    )

    started = time.time()
    logger.info("Starting bug-hunter crawl on %s (depth=%d, threads=%d)",
                target, args.depth, threads)
    try:
        crawler.crawl()
        if not args.js_only and not args.no_smart_paths:
            path_discovery.run()
        elif args.no_smart_paths and not args.js_only:
            logger.info("Smart-path discovery disabled (--no-smart-paths).")
    except KeyboardInterrupt:
        logger.warning("Interrupted — writing partial report.")
        # Re-raise to let main() decide whether to continue with remaining targets.
        raise

    rg = ReportGenerator(
        target=target, crawler=crawler, path_discovery=path_discovery,
        client=client, evader=evader, waf_detector=waf_detector,
        started_at=started, show_out_of_scope=args.show_out_of_scope,
    )
    report = rg.build()
    if write_json:
        try:
            rg.write_json(report, output_path)
        except Exception as exc:
            logger.error("Failed to write JSON report for %s: %s", target, exc)
            return 1, report
    rg.print_summary(report, output_path)
    return 0, report


def main(argv: Optional[List[str]] = None) -> int:
    args = _parse_args(argv)
    _setup_logger(args.verbose)

    # Resolve target list: --targets-file takes precedence; otherwise --target.
    if not args.target and not args.targets_file:
        logger.error("Provide either --target <url> or --targets-file <path>.")
        return 2

    raw_targets: List[str] = []
    if args.targets_file:
        try:
            raw_targets.extend(_load_targets_file(args.targets_file))
        except Exception as exc:
            logger.error("Failed to read --targets-file: %s", exc)
            return 2
    if args.target:
        raw_targets.append(args.target)

    if not raw_targets:
        logger.error("No targets to scan (file empty?).")
        return 2

    # Normalise + dedupe while preserving order.
    targets: List[str] = []
    seen: Set[str] = set()
    for raw in raw_targets:
        norm = _normalise_target(raw)
        if not norm:
            logger.warning("Skipping invalid target: %r", raw)
            continue
        if norm in seen:
            continue
        seen.add(norm)
        targets.append(norm)

    if not targets:
        logger.error("No valid targets after normalisation.")
        return 2

    # When --targets-file is in play, ALL targets are merged into one consolidated
    # report file. Without it, each target keeps its own report (and there's only
    # one anyway, since --target is a single URL).
    consolidated_mode = bool(args.targets_file)

    if consolidated_mode:
        consolidated_path = (
            os.path.expanduser(args.output) if args.output else _default_combined_output()
        )
        logger.info("Multi-target mode: %d target(s) -> consolidated report at %s",
                    len(targets), consolidated_path)
    else:
        consolidated_path = ""

    overall_rc = 0
    per_target_reports: List[Dict[str, Any]] = []
    batch_started = time.time()

    for idx, target in enumerate(targets, 1):
        if consolidated_mode:
            logger.info("=" * 60)
            logger.info("[%d/%d] Target: %s", idx, len(targets), target)
            logger.info("=" * 60)
        if consolidated_mode:
            # Pass the consolidated path purely so the per-target summary mentions
            # where the final file will land. The JSON itself is not written yet.
            out_path = consolidated_path
            write_json = False
        else:
            out_path = (os.path.expanduser(args.output) if args.output
                        else _default_output(target))
            write_json = True

        try:
            rc, report = _run_one_target(target, args, out_path, write_json=write_json)
        except KeyboardInterrupt:
            logger.warning("Aborted by user — stopping remaining targets.")
            if consolidated_mode and per_target_reports:
                _write_consolidated(consolidated_path, per_target_reports, batch_started,
                                    show_out_of_scope=args.show_out_of_scope)
            return 130
        except Exception as exc:
            logger.exception("Unhandled error scanning %s: %s", target, exc)
            rc, report = 1, None
        if rc != 0:
            overall_rc = rc
        if report is not None:
            per_target_reports.append(report)

    # If we ran with --targets-file, emit one consolidated JSON.
    if consolidated_mode:
        try:
            _write_consolidated(consolidated_path, per_target_reports, batch_started,
                                show_out_of_scope=args.show_out_of_scope)
        except Exception as exc:
            logger.error("Failed to write consolidated report: %s", exc)
            return 1
        logger.info("Consolidated report written: %s  (%d target(s))",
                    consolidated_path, len(per_target_reports))

    return overall_rc


def _write_consolidated(
    path: str,
    reports: List[Dict[str, Any]],
    batch_started: float,
    *,
    show_out_of_scope: bool,
) -> None:
    """Combine per-target reports into a single JSON file at `path`."""
    elapsed = time.time() - batch_started
    m, s = divmod(int(elapsed), 60)
    h, m = divmod(m, 60)
    if h:
        duration = f"{h}h {m}m {s}s"
    elif m:
        duration = f"{m}m {s}s"
    else:
        duration = f"{s}s"

    # Strip the (potentially huge) out_of_scope list from per-target sections unless
    # the user explicitly opted in via --show-out-of-scope.
    cleaned_targets: List[Dict[str, Any]] = []
    for r in reports:
        rr = dict(r)
        if not show_out_of_scope:
            rr.pop("out_of_scope_urls", None)
        cleaned_targets.append(rr)

    consolidated = {
        "scan_date": datetime.now().astimezone().isoformat(timespec="seconds"),
        "scan_duration": duration,
        "targets_scanned": len(cleaned_targets),
        "targets_list": [r.get("target", "") for r in cleaned_targets],
        "aggregated_stats": _aggregate_stats(cleaned_targets),
        "targets": cleaned_targets,
    }
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(consolidated, fh, indent=2, ensure_ascii=False)


if __name__ == "__main__":
    sys.exit(main())
