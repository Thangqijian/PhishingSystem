"""
PhishGuard - Heuristic Detection Engine
========================================
Layer 2 detection after the ML model.
Covers:
  - URL unshortening and redirect-chain following
  - Malicious download detection
  - Rule-based phishing checks
"""

import math
import re
import urllib.error
import urllib.parse
import urllib.request


SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "rb.gy", "short.link", "cutt.ly", "tiny.cc",
    "shorte.st", "adf.ly", "bc.vc", "clk.sh", "buff.ly",
    "dlvr.it", "j.mp", "lnkd.in", "mcaf.ee", "po.st",
    "qr.ae", "snipurl.com", "su.pr", "x.co", "youtu.be",
    "fb.me", "wp.me", "tr.im", "v.gd", "twurl.nl",
    "cli.gs", "ff.im", "budurl.com", "ping.fm", "post.ly",
    "just.as", "bkite.com", "snipr.com", "fic.kr", "loopt.us",
    "doiop.com", "twitthis.com", "ht.ly", "rubyurl.com",
    "om.ly", "to.ly", "twit.ac", "url4.eu", "redir.ec",
    "go2.me", "clk.im",
}

MALICIOUS_EXTENSIONS = [
    ".exe", ".bat", ".cmd", ".msi", ".vbs", ".ps1",
    ".scr", ".jar", ".dll", ".pif", ".com", ".hta",
    ".wsf", ".cpl", ".reg", ".iso", ".img", ".apk",
]

SUSPICIOUS_EXTENSIONS = [
    ".zip", ".rar", ".7z", ".tar", ".gz",
    ".dmg", ".pkg", ".deb", ".rpm",
]

SUSPICIOUS_WORDS = [
    "login", "signin", "sign-in", "verify", "verification",
    "update", "secure", "security", "account", "banking",
    "confirm", "password", "credential", "support", "alert",
    "suspended", "validate", "authorize", "submit", "wallet",
    "recover", "unlock", "urgent", "limited", "expire",
    "click", "free", "winner", "prize", "claim", "bonus",
    "invoice", "payment", "billing", "refund", "cancel",
]

BRAND_NAMES = [
    "paypal", "apple", "microsoft", "google", "amazon",
    "facebook", "netflix", "instagram", "twitter", "linkedin",
    "dropbox", "spotify", "chase", "wellsfargo", "citibank",
    "bankofamerica", "hsbc", "maybank", "cimb", "rhb",
    "publicbank", "dhl", "fedex", "ups", "usps",
    "steam", "ebay", "alibaba", "lazada", "shopee",
]

REDIRECT_PARAMS = [
    "redirect", "url=", "link=", "goto=", "redir",
    "return=", "returnurl", "next=", "target=", "dest=",
    "destination=", "forward=", "location=", "continue=",
    "redirect_uri", "callback=", "out=", "view=",
]

POP_AD_TERMS = [
    "propellerads", "proppop", "prop_pop", "popunder",
    "pop-under", "popads", "adsterra", "clickadu", "onclicka",
]

PAID_AD_MEDIUMS = {"cpc", "cpm", "cpv", "pop", "paid", "push"}

MAX_REDIRECT_HOPS = 8
TIMEOUT_SECONDS = 4


def is_shortener(url):
    try:
        host = urllib.parse.urlparse(url).netloc.lower().replace("www.", "")
        return host in SHORTENER_DOMAINS
    except Exception:
        return False


def follow_redirects(url):
    chain = [url]
    was_shortened = is_shortener(url)
    timed_out = False
    current = url

    for _ in range(MAX_REDIRECT_HOPS):
        try:
            req = urllib.request.Request(
                current,
                headers={"User-Agent": "Mozilla/5.0 Chrome/120.0.0.0"},
                method="HEAD",
            )

            class NoRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, req, fp, code, msg, headers, newurl):
                    return None

            opener = urllib.request.build_opener(NoRedirect())
            opener.open(req, timeout=TIMEOUT_SECONDS)
            break
        except urllib.error.HTTPError as error:
            if error.code not in (301, 302, 303, 307, 308):
                break

            next_url = error.headers.get("Location", "")
            if not next_url or next_url == current:
                break
            if next_url.startswith("/"):
                next_url = urllib.parse.urljoin(current, next_url)
            if next_url.startswith("//"):
                scheme = urllib.parse.urlparse(current).scheme
                next_url = scheme + ":" + next_url
            if is_shortener(next_url):
                was_shortened = True
            chain.append(next_url)
            current = next_url
        except urllib.error.URLError:
            timed_out = True
            break
        except Exception:
            break

    try:
        original_host = urllib.parse.urlparse(url).netloc.lower()
        final_host = urllib.parse.urlparse(chain[-1]).netloc.lower()
        cross_domain = original_host != final_host
    except Exception:
        cross_domain = False

    return {
        "resolved_url": chain[-1],
        "was_shortened": was_shortened,
        "redirect_chain": chain,
        "redirect_count": len(chain) - 1,
        "cross_domain": cross_domain,
        "timed_out": timed_out,
    }


def check_download(url, filename=None):
    try:
        path = urllib.parse.urlparse(url).path.lower().rstrip("/")
    except Exception:
        path = url.lower()

    candidates = [path]
    if filename:
        candidates.append(str(filename).lower().strip())

    for extension in MALICIOUS_EXTENSIONS:
        if any(candidate.endswith(extension) for candidate in candidates):
            return {
                "is_malicious": True,
                "is_suspicious": False,
                "extension": extension,
                "severity": "HIGH",
                "message": (
                    f"Dangerous file type: {extension} - "
                    "this file can execute code on your computer"
                ),
            }

    for extension in SUSPICIOUS_EXTENSIONS:
        if any(candidate.endswith(extension) for candidate in candidates):
            return {
                "is_malicious": False,
                "is_suspicious": True,
                "extension": extension,
                "severity": "MEDIUM",
                "message": (
                    f"Compressed archive: {extension} - "
                    "may contain hidden malicious files"
                ),
            }

    return {
        "is_malicious": False,
        "is_suspicious": False,
        "extension": None,
        "severity": None,
        "message": None,
    }


def shannon_entropy(value):
    if not value:
        return 0.0

    frequencies = {}
    for character in value:
        frequencies[character] = frequencies.get(character, 0) + 1

    total = len(value)
    return -sum(
        (count / total) * math.log2(count / total)
        for count in frequencies.values()
    )


def run_rules(url):
    flags = []
    rule_scores = {}

    try:
        parsed = urllib.parse.urlparse(url)
        scheme = parsed.scheme.lower()
        netloc = parsed.netloc.lower()
        path = parsed.path
        hostname = netloc.split(":")[0] if ":" in netloc else netloc
        parts = hostname.split(".")
        url_low = url.lower()
        query = urllib.parse.parse_qs(parsed.query)
    except Exception:
        return {
            "flags": ["Could not parse URL"],
            "rule_scores": {},
            "heuristic_risk": 0.5,
        }

    if re.compile(r"^(\d{1,3}\.){3}\d{1,3}$").match(hostname):
        flags.append("IP address used instead of domain - common phishing tactic")
        rule_scores["ip_address"] = 0.9

    if scheme == "http":
        flags.append("No HTTPS - connection is not secure")
        rule_scores["no_https"] = 0.1

    if "@" in netloc:
        flags.append("@ symbol in URL - browser ignores everything before @")
        rule_scores["at_symbol"] = 0.8

    found_words = [word for word in SUSPICIOUS_WORDS if word in url_low]
    if len(found_words) >= 2:
        flags.append(
            f"Multiple suspicious keywords: {', '.join(found_words[:4])}"
        )
        rule_scores["suspicious_keywords"] = min(
            0.2 * len(found_words),
            0.8,
        )
    elif len(found_words) == 1:
        flags.append(f"Suspicious keyword detected: {found_words[0]}")
        rule_scores["suspicious_keywords"] = 0.2

    found_brands = [brand for brand in BRAND_NAMES if brand in url_low]
    if found_brands:
        real_domain = ".".join(parts[-2:]) if len(parts) >= 2 else hostname
        is_real = any(brand in real_domain for brand in found_brands)
        if not is_real:
            flags.append(
                f"Brand '{found_brands[0]}' in URL but domain is "
                f"'{real_domain}' - possible impersonation"
            )
            rule_scores["brand_impersonation"] = 0.85

    subdomains = parts[:-2] if len(parts) > 2 else []
    if len(subdomains) >= 4:
        flags.append(
            f"Excessive subdomains ({len(subdomains)}) - hides real domain"
        )
        rule_scores["excessive_subdomains"] = 0.6
    elif len(subdomains) == 3:
        flags.append(f"Multiple subdomains ({len(subdomains)}) detected")
        rule_scores["excessive_subdomains"] = 0.3

    url_length = len(url)
    if url_length > 300:
        flags.append(f"Extremely long URL ({url_length} chars)")
        rule_scores["long_url"] = 0.3
    elif url_length > 200:
        flags.append(f"Very long URL ({url_length} chars)")
        rule_scores["long_url"] = 0.15
    elif url_length > 120:
        flags.append(f"Long URL ({url_length} chars)")
        rule_scores["long_url"] = 0.05

    query_names = {name.lower() for name in query.keys()}
    decoded_query = urllib.parse.unquote_plus(parsed.query).lower()
    found_ad_terms = [
        term
        for term in POP_AD_TERMS
        if term in url_low or term in decoded_query
    ]
    tracking_params = {
        "clickid", "click_id", "subid", "zoneid", "offer",
        "campaign", "utm_source", "utm_medium", "utm_campaign",
        "utm_term", "utm_content",
    }
    tracking_hits = query_names.intersection(tracking_params)
    utm_medium = (query.get("utm_medium", [""])[0] or "").lower()
    paid_medium = utm_medium in PAID_AD_MEDIUMS

    if found_ad_terms and (paid_medium or len(tracking_hits) >= 4):
        flags.append(
            "Pop-up advertising campaign indicators detected - "
            "often used by deceptive redirects"
        )
        rule_scores["ad_popup_campaign"] = 0.9

        if paid_medium and len(tracking_hits) >= 4:
            rule_scores["paid_click_tracking"] = 0.7

        has_click_offer = (
            {"clickid", "offer"}.issubset(query_names)
            or {"click_id", "offer"}.issubset(query_names)
        )
        if has_click_offer:
            rule_scores["popup_affiliate_tracking"] = 0.7

    domain = ".".join(parts[-2:]) if len(parts) >= 2 else hostname
    if domain.count("-") >= 3:
        flags.append("Many dashes in domain - e.g. paypal-secure-login.com")
        rule_scores["domain_dashes"] = 0.5

    found_redirects = [
        parameter for parameter in REDIRECT_PARAMS if parameter in url_low
    ]
    if found_redirects:
        flags.append(
            f"Redirect parameter '{found_redirects[0]}' - "
            "may redirect to different destination"
        )
        rule_scores["redirect_param"] = 0.6

    if re.search(r":\d+", netloc):
        port = netloc.split(":")[-1]
        flags.append(f"Non-standard port (:{port}) detected")
        rule_scores["non_standard_port"] = 0.5

    entropy = shannon_entropy(url)
    if entropy > 5.8:
        flags.append(
            f"High URL randomness (entropy={entropy:.2f}) - possibly obfuscated"
        )
        rule_scores["high_entropy"] = 0.25
    elif entropy > 5.2:
        flags.append(f"Moderately high entropy ({entropy:.2f})")
        rule_scores["high_entropy"] = 0.10

    if url.count(".") >= 6:
        flags.append(
            f"Too many dots ({url.count('.')}) - used to confuse users"
        )
        rule_scores["too_many_dots"] = 0.4

    if "//" in path:
        flags.append("Double slash in path - used to bypass filters")
        rule_scores["double_slash"] = 0.4

    if "%" in hostname or "=" in hostname:
        flags.append("Encoded characters in domain - hides real destination")
        rule_scores["encoded_domain"] = 0.7

    heuristic_risk = (
        min(sum(rule_scores.values()) / 3.0, 1.0)
        if rule_scores
        else 0.0
    )

    return {
        "flags": flags,
        "rule_scores": rule_scores,
        "heuristic_risk": round(heuristic_risk, 4),
    }


def get_redirect_flags(redirect_info):
    flags = []
    risk_boost = 0.0

    if redirect_info["was_shortened"]:
        flags.append("URL shortener detected - hides the real destination")
        risk_boost += 0.25

    if redirect_info["redirect_count"] >= 6:
        flags.append(
            f"Long redirect chain ({redirect_info['redirect_count']} hops) - "
            "used to evade detection"
        )
        risk_boost += 0.25
    elif redirect_info["redirect_count"] >= 4:
        flags.append(
            f"Multiple redirects ({redirect_info['redirect_count']} hops)"
        )
        risk_boost += 0.10

    if (
        redirect_info["cross_domain"]
        and redirect_info["redirect_count"] >= 2
    ):
        risk_boost += 0.1

    if redirect_info["timed_out"]:
        flags.append(
            "Could not fully resolve redirects - destination unknown"
        )
        risk_boost += 0.1

    return {
        "flags": flags,
        "risk_boost": min(risk_boost, 0.6),
    }


def run_full_heuristic_analysis(original_url, filename=None):
    """
    Run redirect, download, and rule-based analysis for one URL.
    """
    redirect_info = follow_redirects(original_url)
    resolved_url = redirect_info["resolved_url"]
    download_info = check_download(resolved_url, filename)
    heuristic = run_rules(resolved_url)

    print("RULE SCORES:", heuristic["rule_scores"])
    print("FLAGS:", heuristic["flags"])
    print("HEURISTIC RISK:", heuristic["heuristic_risk"])
    print("RESOLVED URL:", resolved_url)

    redirect_flags = get_redirect_flags(redirect_info)
    all_flags = redirect_flags["flags"] + heuristic["flags"]

    if download_info["is_malicious"]:
        all_flags.insert(
            0,
            f"DANGEROUS DOWNLOAD: {download_info['message']}",
        )
    elif download_info["is_suspicious"]:
        all_flags.insert(
            0,
            f"Suspicious download: {download_info['message']}",
        )

    boost = redirect_flags["risk_boost"]
    if download_info["is_malicious"]:
        boost += 0.5
    elif download_info["is_suspicious"]:
        boost += 0.2

    final_risk = min(heuristic["heuristic_risk"] + boost, 1.0)

    return {
        "original_url": original_url,
        "resolved_url": resolved_url,
        "was_shortened": redirect_info["was_shortened"],
        "redirect_count": redirect_info["redirect_count"],
        "redirect_chain": redirect_info["redirect_chain"],
        "cross_domain": redirect_info["cross_domain"],
        "flags": all_flags,
        "download": download_info,
        "heuristic_risk": round(final_risk, 4),
        "rule_scores": heuristic["rule_scores"],
    }
