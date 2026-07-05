import re
import math
import urllib.parse

FEATURE_COLS = [
    "url_len", "dom_len", "is_ip", "tld_len", "subdom_cnt",
    "letter_cnt", "digit_cnt", "special_cnt", "eq_cnt", "qm_cnt",
    "amp_cnt", "dot_cnt", "dash_cnt", "under_cnt",
    "letter_ratio", "digit_ratio", "spec_ratio",
    "is_https", "slash_cnt", "entropy", "path_len", "query_len",
]


def shannon_entropy(s):
    if not s:
        return 0.0
    freq  = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


def extract_features(url):
    """
    Extract all 22 features from a URL string.
    Returns dict with exact same column names as Dataset.csv.
    """
    url = url.strip()

    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return {col: 0.0 for col in FEATURE_COLS}

    scheme   = parsed.scheme.lower()
    netloc   = parsed.netloc.lower()
    path     = parsed.path
    query    = parsed.query
    hostname = netloc.split(":")[0] if ":" in netloc else netloc
    parts    = hostname.split(".")
    domain   = ".".join(parts[-2:]) if len(parts) >= 2 else hostname
    tld      = parts[-1]            if len(parts) >= 1 else ""
    subdoms  = parts[:-2]           if len(parts) > 2  else []

    url_len   = float(len(url))
    dom_len   = float(len(domain))
    tld_len   = float(len(tld))
    path_len  = float(len(path))
    query_len = float(len(query))
    subdom_cnt= float(len(subdoms))

    ip_pattern = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
    is_ip = 1.0 if ip_pattern.match(hostname) else 0.0

    letter_cnt  = float(sum(c.isalpha() for c in url))
    digit_cnt   = float(sum(c.isdigit() for c in url))
    special_cnt = float(sum(
        not c.isalnum() and c not in (".", "-", "_", "/", ":", "?", "&", "=")
        for c in url
    ))

    eq_cnt    = float(url.count("="))
    qm_cnt    = float(url.count("?"))
    amp_cnt   = float(url.count("&"))
    dot_cnt   = float(url.count("."))
    dash_cnt  = float(url.count("-"))
    under_cnt = float(url.count("_"))
    slash_cnt = float(url.count("/"))

    total        = len(url) if len(url) > 0 else 1
    letter_ratio = letter_cnt  / total
    digit_ratio  = digit_cnt   / total
    spec_ratio   = special_cnt / total

    is_https = 1.0 if scheme == "https" else 0.0
    entropy  = shannon_entropy(url)

    return {
        "url_len"     : url_len,
        "dom_len"     : dom_len,
        "is_ip"       : is_ip,
        "tld_len"     : tld_len,
        "subdom_cnt"  : subdom_cnt,
        "letter_cnt"  : letter_cnt,
        "digit_cnt"   : digit_cnt,
        "special_cnt" : special_cnt,
        "eq_cnt"      : eq_cnt,
        "qm_cnt"      : qm_cnt,
        "amp_cnt"     : amp_cnt,
        "dot_cnt"     : dot_cnt,
        "dash_cnt"    : dash_cnt,
        "under_cnt"   : under_cnt,
        "letter_ratio": letter_ratio,
        "digit_ratio" : digit_ratio,
        "spec_ratio"  : spec_ratio,
        "is_https"    : is_https,
        "slash_cnt"   : slash_cnt,
        "entropy"     : entropy,
        "path_len"    : path_len,
        "query_len"   : query_len,
    }


def features_to_list(features_dict):
    """Convert feature dict to ordered list matching training column order."""
    return [features_dict.get(col, 0.0) for col in FEATURE_COLS]
