"""
URL Feature Extractor for Phishing Detection
Extracts 71 features matching the clean model schema.

Perubahan dari versi sebelumnya:
  - Dihapus: google_index (data leakage, 86.5% accuracy sendirian)
  - Dihapus: page_rank, domain_age, domain_registration_length,
             whois_registered_domain, web_traffic, dns_record,
             statistical_report  (semua selalu 0 di inference → tidak berguna)
  - Dihapus: nb_or, ratio_nullHyperlinks, ratio_intRedirection,
             ratio_intErrors, submit_email, sfh  (zero-variance di seluruh dataset)
  - Dihapus: longest_words_raw (corr=0.969 dengan longest_word_path → redundan)
  - Dihapus: nb_eq (corr=0.906 dengan nb_and → redundan)
  - Ditambahkan: extract_html_features() untuk mengisi fitur konten HTML
    saat halaman bisa di-fetch (opsional, default 0 jika tidak di-fetch)
"""

import re
import math
import urllib.parse
import ipaddress
from collections import Counter


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_features(url: str, html_content: str | None = None) -> dict:
    """
    Extract 71 features from a URL string.

    Parameters
    ----------
    url          : raw URL string
    html_content : optional raw HTML string of the page; when provided,
                   HTML-based features are computed instead of defaulting to 0.

    Returns
    -------
    dict of feature_name → numeric value
    """
    features = {}

    # ── Parse URL ──────────────────────────────────────────────────────────
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        parsed = urllib.parse.urlparse("http://invalid.com")

    hostname  = parsed.hostname or ""
    path      = parsed.path     or ""
    query     = parsed.query    or ""
    scheme    = parsed.scheme   or ""
    parts     = hostname.split(".")
    domain    = parts[-2] if len(parts) >= 2 else hostname
    subdomain = ".".join(parts[:-2]) if len(parts) > 2 else ""

    # ── Length features ────────────────────────────────────────────────────
    features["length_url"]      = len(url)
    features["length_hostname"] = len(hostname)

    # ── IP address check ───────────────────────────────────────────────────
    try:
        ipaddress.ip_address(hostname)
        features["ip"] = 1
    except ValueError:
        features["ip"] = 0

    # ── Character count features ───────────────────────────────────────────
    features["nb_dots"]       = url.count(".")
    features["nb_hyphens"]    = url.count("-")
    features["nb_at"]         = url.count("@")
    features["nb_qm"]         = url.count("?")
    features["nb_and"]        = url.count("&")
    # nb_or  REMOVED — zero-variance in entire dataset
    # nb_eq  REMOVED — multicollinear with nb_and (corr=0.906)
    features["nb_underscore"] = url.count("_")
    features["nb_tilde"]      = url.count("~")
    features["nb_percent"]    = url.count("%")
    features["nb_slash"]      = url.count("/")
    features["nb_star"]       = url.count("*")
    features["nb_colon"]      = url.count(":")
    features["nb_comma"]      = url.count(",")
    features["nb_semicolumn"] = url.count(";")
    features["nb_dollar"]     = url.count("$")
    features["nb_space"]      = url.count(" ") + url.count("%20")

    # ── www / com counts ───────────────────────────────────────────────────
    features["nb_www"]    = url.lower().count("www")
    features["nb_com"]    = url.lower().count(".com")
    features["nb_dslash"] = url.count("//")

    # ── Token checks ───────────────────────────────────────────────────────
    features["http_in_path"] = 1 if "http" in path.lower() else 0
    features["https_token"]  = 1 if scheme == "https" else 0

    # ── Digit ratio ────────────────────────────────────────────────────────
    features["ratio_digits_url"]  = sum(c.isdigit() for c in url) / max(len(url), 1)
    features["ratio_digits_host"] = sum(c.isdigit() for c in hostname) / max(len(hostname), 1)

    # ── Punycode ───────────────────────────────────────────────────────────
    features["punycode"] = 1 if "xn--" in hostname.lower() else 0

    # ── Non-standard port ──────────────────────────────────────────────────
    features["port"] = 1 if parsed.port and parsed.port not in (80, 443) else 0

    # ── TLD in path / subdomain ────────────────────────────────────────────
    common_tlds = [".com", ".net", ".org", ".info", ".biz", ".gov", ".edu"]
    features["tld_in_path"]      = int(any(t in path.lower() for t in common_tlds))
    features["tld_in_subdomain"] = int(any(t.strip(".") in subdomain.lower() for t in common_tlds))

    # ── Abnormal subdomain ─────────────────────────────────────────────────
    features["abnormal_subdomain"] = 1 if re.search(r"(^|\.)(w{2,3}\d|mail\d)", hostname.lower()) else 0

    # ── Subdomain count ────────────────────────────────────────────────────
    features["nb_subdomains"] = max(len(parts) - 2, 0)

    # ── Prefix/suffix hyphen in domain ─────────────────────────────────────
    features["prefix_suffix"] = 1 if "-" in domain else 0

    # ── Random domain heuristic (Shannon entropy) ──────────────────────────
    features["random_domain"] = 1 if _entropy(domain) > 3.5 else 0

    # ── URL shortening service ─────────────────────────────────────────────
    _shorteners = {
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
        "is.gd", "buff.ly", "adf.ly", "tiny.cc", "short.link", "rb.gy",
    }
    features["shortening_service"] = int(any(s in hostname.lower() for s in _shorteners))

    # ── Suspicious file extension in path ──────────────────────────────────
    _susp_exts = {".exe", ".php", ".asp", ".aspx", ".jsp", ".cgi"}
    features["path_extension"] = int(any(path.lower().endswith(e) for e in _susp_exts))

    # ── Redirections ───────────────────────────────────────────────────────
    features["nb_redirection"]          = path.count("//")
    features["nb_external_redirection"] = max(
        url.count("http://") + url.count("https://") - 1, 0
    )

    # ── Word-based features ────────────────────────────────────────────────
    tokens     = [t for t in re.split(r"[\W_]+", url)  if t]
    word_lens  = [len(t) for t in tokens] or [0]

    features["length_words_raw"]  = len(tokens)
    features["char_repeat"]       = max(Counter(url).values()) if url else 0
    features["shortest_words_raw"] = min(word_lens)
    # longest_words_raw REMOVED — corr=0.969 with longest_word_path
    features["avg_words_raw"]     = sum(word_lens) / max(len(word_lens), 1)

    host_tokens = [t for t in re.split(r"[\W_]+", hostname) if t]
    host_lens   = [len(t) for t in host_tokens] or [0]
    features["shortest_word_host"] = min(host_lens)
    features["longest_word_host"]  = max(host_lens)
    features["avg_word_host"]      = sum(host_lens) / max(len(host_lens), 1)

    path_tokens = [t for t in re.split(r"[\W_]+", path) if t]
    path_lens   = [len(t) for t in path_tokens] or [0]
    features["shortest_word_path"] = min(path_lens)
    features["longest_word_path"]  = max(path_lens)
    features["avg_word_path"]      = sum(path_lens) / max(len(path_lens), 1)

    # ── Phishing hints ─────────────────────────────────────────────────────
    _phish_kw = {
        "secure", "account", "update", "login", "verify", "bank",
        "confirm", "password", "paypal", "ebay", "apple", "google",
        "signin", "validation", "support", "access",
    }
    features["phish_hints"] = sum(kw in url.lower() for kw in _phish_kw)

    # ── Brand in domain / subdomain / path ─────────────────────────────────
    _brands = {
        "paypal", "apple", "google", "microsoft", "amazon", "facebook",
        "netflix", "ebay", "instagram", "twitter", "linkedin", "dropbox",
    }
    features["domain_in_brand"]    = int(domain.lower() in _brands)
    features["brand_in_subdomain"] = int(any(b in subdomain.lower() for b in _brands))
    features["brand_in_path"]      = int(any(b in path.lower() for b in _brands))

    # ── Suspicious TLD ─────────────────────────────────────────────────────
    _susp_tlds = {
        ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click",
        ".link", ".work", ".loan", ".racing", ".date", ".cricket",
    }
    tld = ("." + parts[-1]) if parts else ""
    features["suspecious_tld"] = int(tld.lower() in _susp_tlds)

    # ── HTML / content-based features ─────────────────────────────────────
    # These are populated from dataset (nb_hyperlinks mean=87, etc.).
    # Pass html_content to compute them; otherwise they stay 0.
    # NOTE: keeping them at 0 for URL-only inference is valid — the model
    #       was trained on the full dataset where these are populated,
    #       so URL-only predictions will be slightly less accurate but
    #       still functional. Use extract_html_features() when possible.
    html_feats = _extract_html_features(html_content) if html_content else _html_defaults()
    features.update(html_feats)

    # ── Removed features (kept as comments for traceability) ──────────────
    # google_index            → DATA LEAKAGE (removed)
    # page_rank               → external lookup, always 0 at inference (removed)
    # domain_age              → external lookup, always 0 at inference (removed)
    # domain_registration_length → external lookup, always 0 (removed)
    # whois_registered_domain → external lookup, always 0 (removed)
    # web_traffic             → external lookup, always 0 (removed)
    # dns_record              → external lookup, always 0 (removed)
    # statistical_report      → always 0, no implementation (removed)
    # nb_or                   → zero-variance in dataset (removed)
    # ratio_nullHyperlinks    → zero-variance in dataset (removed)
    # ratio_intRedirection    → zero-variance in dataset (removed)
    # ratio_intErrors         → zero-variance in dataset (removed)
    # submit_email            → zero-variance in dataset (removed)
    # sfh                     → zero-variance in dataset (removed)
    # nb_eq                   → multicollinear with nb_and corr=0.906 (removed)
    # longest_words_raw       → multicollinear with longest_word_path corr=0.969 (removed)

    return features


# ---------------------------------------------------------------------------
# HTML feature extraction
# ---------------------------------------------------------------------------

def _html_defaults() -> dict:
    """Return zero-default values for all HTML-based features."""
    return {
        "nb_hyperlinks":        0,
        "ratio_intHyperlinks":  0.0,
        "ratio_extHyperlinks":  0.0,
        "nb_extCSS":            0,
        "ratio_extRedirection": 0.0,
        "ratio_extErrors":      0,
        "login_form":           0,
        "external_favicon":     0,
        "links_in_tags":        0.0,
        "ratio_intMedia":       0.0,
        "ratio_extMedia":       0.0,
        "iframe":               0,
        "popup_window":         0,
        "safe_anchor":          0.0,
        "onmouseover":          0,
        "right_clic":           0,
        "empty_title":          0,
        "domain_in_title":      0,
        "domain_with_copyright": 0,
    }


def _extract_html_features(html: str, base_domain: str = "") -> dict:
    """
    Extract content-based features from raw HTML.

    Parameters
    ----------
    html        : raw HTML string
    base_domain : the domain of the URL being analysed (used to classify
                  internal vs external links). Falls back to empty string.
    """
    f = _html_defaults()
    if not html:
        return f

    html_lower = html.lower()

    # ── Hyperlinks ─────────────────────────────────────────────────────────
    all_hrefs   = re.findall(r'href\s*=\s*["\']([^"\']*)["\']', html_lower)
    total_links = len(all_hrefs)
    f["nb_hyperlinks"] = total_links

    if total_links > 0:
        int_links = sum(1 for h in all_hrefs
                        if not h.startswith("http") or (base_domain and base_domain in h))
        ext_links = total_links - int_links
        f["ratio_intHyperlinks"] = int_links / total_links
        f["ratio_extHyperlinks"] = ext_links / total_links

    # ── External CSS ───────────────────────────────────────────────────────
    ext_css = re.findall(r'<link[^>]+rel\s*=\s*["\']stylesheet["\'][^>]*href\s*=\s*["\']https?://[^"\']*["\']', html_lower)
    f["nb_extCSS"] = len(ext_css)

    # ── External redirections in anchors ───────────────────────────────────
    ext_redirect = [h for h in all_hrefs if h.startswith("http") and base_domain and base_domain not in h]
    f["ratio_extRedirection"] = len(ext_redirect) / max(total_links, 1)

    # ── Login form ─────────────────────────────────────────────────────────
    has_form       = bool(re.search(r"<form", html_lower))
    has_pwd_field  = bool(re.search(r'type\s*=\s*["\']password["\']', html_lower))
    f["login_form"] = int(has_form and has_pwd_field)

    # ── External favicon ───────────────────────────────────────────────────
    favicon_match = re.search(r'<link[^>]+rel\s*=\s*["\'][^"\']*icon[^"\']*["\'][^>]*href\s*=\s*["\']([^"\']*)["\']', html_lower)
    if favicon_match:
        favicon_href = favicon_match.group(1)
        f["external_favicon"] = int(
            favicon_href.startswith("http") and (not base_domain or base_domain not in favicon_href)
        )

    # ── Links in <script> / <link> tags (ratio over total links) ──────────
    script_src  = re.findall(r'<script[^>]+src\s*=\s*["\']([^"\']*)["\']', html_lower)
    link_hrefs  = re.findall(r'<link[^>]+href\s*=\s*["\']([^"\']*)["\']', html_lower)
    tag_links   = len(script_src) + len(link_hrefs)
    f["links_in_tags"] = tag_links / max(total_links, 1)

    # ── Media (img / video / audio) ────────────────────────────────────────
    media_srcs = re.findall(r'(?:src|data-src)\s*=\s*["\']([^"\']*)["\']', html_lower)
    total_media = len(media_srcs)
    if total_media > 0:
        int_media = sum(1 for s in media_srcs if not s.startswith("http") or (base_domain and base_domain in s))
        f["ratio_intMedia"] = int_media / total_media
        f["ratio_extMedia"] = (total_media - int_media) / total_media

    # ── Suspicious JS patterns ─────────────────────────────────────────────
    f["iframe"]        = int(bool(re.search(r"<iframe", html_lower)))
    f["popup_window"]  = int(bool(re.search(r"window\.open\s*\(", html_lower)))
    f["onmouseover"]   = int(bool(re.search(r"onmouseover\s*=", html_lower)))
    f["right_clic"]    = int(bool(re.search(r"event\.button\s*==\s*2|contextmenu", html_lower)))

    # ── Safe anchor (ratio of # anchors) ──────────────────────────────────
    null_hrefs = [h for h in all_hrefs if h in ("#", "", "javascript:void(0)", "javascript:;")]
    f["safe_anchor"] = len(null_hrefs) / max(total_links, 1)

    # ── Title features ─────────────────────────────────────────────────────
    title_match = re.search(r"<title[^>]*>(.*?)</title>", html_lower)
    title = title_match.group(1).strip() if title_match else ""
    f["empty_title"]          = int(not title)
    f["domain_in_title"]      = int(bool(base_domain and base_domain in title))
    f["domain_with_copyright"] = int(bool(base_domain and re.search(r"©|&copy;|copyright", html_lower) and base_domain in html_lower))

    # ── External error resources (404/broken external links heuristic) ─────
    # Count external hrefs that look like error paths
    error_patterns = re.findall(r'href\s*=\s*["\']https?://[^"\']*(?:404|error|notfound)[^"\']*["\']', html_lower)
    f["ratio_extErrors"] = len(error_patterns) / max(total_links, 1)

    return f


# ---------------------------------------------------------------------------
# Risk factor helpers (unchanged from v1)
# ---------------------------------------------------------------------------

def get_url_risk_factors(url: str) -> list[str]:
    """Return human-readable risk factors found in a URL."""
    factors = []
    parsed    = urllib.parse.urlparse(url)
    hostname  = parsed.hostname or ""
    path      = parsed.path     or ""
    parts     = hostname.split(".")
    tld       = ("." + parts[-1]) if parts else ""

    if "@" in url:
        factors.append("⚠️ Mengandung simbol '@' yang mencurigakan")
    if url.count("//") > 1:
        factors.append("⚠️ Memiliki double-slash berlebih di path")
    if "xn--" in hostname:
        factors.append("⚠️ Menggunakan karakter Punycode (homograph attack)")
    if any(s in hostname for s in {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly"}):
        factors.append("⚠️ Menggunakan URL shortener yang menyembunyikan tujuan asli")
    try:
        ipaddress.ip_address(hostname)
        factors.append("⚠️ Menggunakan alamat IP langsung (bukan domain)")
    except ValueError:
        pass
    if len(url) > 75:
        factors.append(f"⚠️ URL sangat panjang ({len(url)} karakter)")

    phish_kw = {"secure", "account", "update", "login", "verify", "confirm", "password"}
    found = [kw for kw in phish_kw if kw in url.lower()]
    if found:
        factors.append(f"⚠️ Mengandung kata sensitif: {', '.join(found)}")

    brands = {"paypal", "apple", "google", "microsoft", "amazon", "facebook", "netflix"}
    base_domain = parts[-2] if len(parts) >= 2 else hostname
    brand_hits = [b for b in brands if b in url.lower() and b != base_domain.lower()]
    if brand_hits:
        factors.append(f"⚠️ Menyamar sebagai brand: {', '.join(brand_hits)}")

    _susp_tlds = {".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click"}
    if tld in _susp_tlds:
        factors.append(f"⚠️ TLD mencurigakan: {tld}")
    if "-" in hostname:
        factors.append("⚠️ Domain mengandung tanda hubung (tanda phishing)")
    if len(parts) > 3:
        factors.append(f"⚠️ Subdomain terlalu banyak ({len(parts) - 2} level)")
    if "http://" in path or "https://" in path:
        factors.append("⚠️ URL menyembunyikan URL lain di dalam path")

    return factors


def get_url_safe_reasons(url: str) -> list[str]:
    """Return reasons why a URL appears safe."""
    reasons  = []
    parsed   = urllib.parse.urlparse(url)
    hostname = parsed.hostname or ""
    scheme   = parsed.scheme   or ""
    parts    = hostname.split(".")

    if scheme == "https":
        reasons.append("✅ Menggunakan HTTPS (koneksi terenkripsi)")
    if len(parts) == 2:
        reasons.append("✅ Struktur domain sederhana dan bersih")
    if not any(c in url for c in "@#$%^&*()"):
        reasons.append("✅ Tidak mengandung karakter mencurigakan")
    if len(url) <= 75:
        reasons.append("✅ Panjang URL normal dan wajar")

    known_safe = {
        "google.com", "youtube.com", "facebook.com", "wikipedia.org",
        "twitter.com", "instagram.com", "linkedin.com", "github.com",
        "microsoft.com", "apple.com", "amazon.com", "netflix.com",
        "bca.co.id", "mandiri.co.id", "bni.co.id", "bri.co.id",
    }
    for sd in known_safe:
        if hostname.lower().endswith(sd):
            reasons.append(f"✅ Domain terkenal dan terpercaya: {sd}")
            break

    phish_kw = {"login", "verify", "confirm", "update", "account", "secure"}
    if not any(kw in url.lower() for kw in phish_kw):
        reasons.append("✅ Tidak mengandung kata-kata mencurigakan")

    if not reasons:
        reasons.append("✅ URL terlihat aman berdasarkan analisis")

    return reasons


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _entropy(s: str) -> float:
    """Shannon entropy of a string."""
    if not s:
        return 0.0
    cnt   = Counter(s)
    total = len(s)
    return -sum((c / total) * math.log2(c / total) for c in cnt.values())