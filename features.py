import re
import math
import ipaddress
from urllib.parse import urlparse, unquote


class URLFeatureExtractor:
    """
    URL-only feature extractor for phishing detection.

    Important:
    The same FEATURE_NAMES are used during training and prediction.
    """

    def __init__(self):
        self.phishing_keywords = {
            "login", "signin", "sign-in", "verify", "verification",
            "account", "secure", "security", "update", "confirm",
            "confirmation", "password", "passwd", "credential",
            "reset", "recover", "recovery", "bank", "billing",
            "payment", "invoice", "wallet", "support", "unlock",
            "suspended", "suspend", "urgent", "alert", "notice",
            "authenticate", "authentication", "authorize",
            "authorization", "mfa", "2fa", "otp", "gift", "reward",
            "prize", "winner", "free", "bonus", "claim"
        }

        # A suspicious TLD is only a signal, NOT an automatic phishing verdict.
        self.suspicious_tlds = {
            "tk", "ml", "ga", "cf", "gq", "xyz", "top",
            "work", "click", "country", "stream", "download",
            "win", "zip", "mov", "pw", "icu", "cam", "buzz"
        }

        self.shorteners = {
            "bit.ly", "tinyurl.com", "t.co", "is.gd", "ow.ly",
            "cutt.ly", "shorturl.at", "rebrand.ly", "rb.gy",
            "lnkd.in", "goo.gl", "buff.ly", "s.id"
        }

        self.brand_names = {
            "paypal", "google", "youtube", "youtu", "microsoft",
            "apple", "amazon", "netflix", "facebook", "instagram",
            "linkedin", "github", "binance", "coinbase", "icici",
            "hdfc", "sbi", "axis", "phonepe", "paytm"
        }

        self.feature_names = [
            "url_length",
            "hostname_length",
            "path_length",
            "query_length",
            "fragment_length",
            "num_dots",
            "num_hyphens",
            "num_underscores",
            "num_slashes",
            "num_digits",
            "digit_ratio",
            "special_char_ratio",
            "num_subdomains",
            "has_https",
            "has_http",
            "has_at_symbol",
            "has_ip",
            "has_port",
            "has_punycode",
            "has_encoded_chars",
            "num_encoded_chars",
            "has_double_slash_path",
            "has_userinfo",
            "has_suspicious_tld",
            "has_shortener",
            "num_phishing_keywords",
            "has_brand_name",
            "brand_in_subdomain",
            "brand_in_path",
            "hostname_entropy",
            "path_entropy",
            "has_long_subdomain",
            "has_many_subdomains",
            "has_suspicious_port",
            "has_numeric_hostname",
            "hostname_digit_ratio",
            "path_digit_ratio",
            "query_has_password_like",
            "query_has_redirect_like",
            "has_fragment"
        ]

    def extract_features(self, url):
        if not isinstance(url, str):
            raise TypeError("URL must be a string")

        url = url.strip()

        if not url:
            raise ValueError("URL cannot be empty")

        parse_url = url
        if not parse_url.lower().startswith(("http://", "https://")):
            parse_url = "https://" + parse_url

        parsed = urlparse(parse_url)

        hostname = (parsed.hostname or "").lower().rstrip(".")
        path = parsed.path or ""
        query = parsed.query or ""
        fragment = parsed.fragment or ""
        full_lower = parse_url.lower()

        url_length = len(parse_url)
        hostname_length = len(hostname)

        digits = sum(c.isdigit() for c in parse_url)
        special_chars = sum(not c.isalnum() for c in parse_url)

        digit_ratio = digits / max(url_length, 1)
        special_char_ratio = special_chars / max(url_length, 1)

        # IP address
        has_ip = 0
        try:
            ipaddress.ip_address(hostname)
            has_ip = 1
        except ValueError:
            pass

        # TLD
        tld = hostname.rsplit(".", 1)[-1] if "." in hostname else ""

        has_suspicious_tld = int(tld in self.suspicious_tlds)

        # Subdomains
        parts = hostname.split(".") if hostname else []
        num_subdomains = max(len(parts) - 2, 0)

        has_long_subdomain = int(
            any(len(part) > 25 for part in parts[:-2])
        )

        has_many_subdomains = int(num_subdomains >= 3)

        # Keyword detection
        words = set(re.findall(r"[a-z0-9]+", full_lower))

        num_phishing_keywords = sum(
            1 for word in self.phishing_keywords if word in words
        )

        # Brand signals
        has_brand_name = int(
            any(re.search(rf"(?<![a-z]){re.escape(brand)}(?![a-z])", full_lower)
                for brand in self.brand_names)
        )

        first_label = parts[0] if parts else ""

        brand_in_subdomain = int(
            any(brand in first_label for brand in self.brand_names)
        )

        brand_in_path = int(
            any(brand in path.lower() for brand in self.brand_names)
        )

        # URL shortener
        has_shortener = int(
            hostname in self.shorteners
            or any(hostname.endswith("." + domain) for domain in self.shorteners)
        )

        # Encoding / obfuscation
        encoded_matches = re.findall(r"%[0-9a-fA-F]{2}", parse_url)

        has_encoded_chars = int(bool(encoded_matches))
        num_encoded_chars = len(encoded_matches)

        has_punycode = int("xn--" in hostname)

        # Port
        try:
            port = parsed.port
        except ValueError:
            port = None

        has_port = int(port is not None)
        has_suspicious_port = int(
            port is not None and port not in {80, 443}
        )

        # @ and userinfo
        has_at_symbol = int("@" in parse_url)
        has_userinfo = int(parsed.username is not None)

        # Path tricks
        has_double_slash_path = int("//" in path)

        # Entropy
        hostname_entropy = self._entropy(hostname)
        path_entropy = self._entropy(path)

        # Numeric hostname
        hostname_digits = sum(c.isdigit() for c in hostname)
        has_numeric_hostname = int(hostname_digits >= 3)
        hostname_digit_ratio = hostname_digits / max(len(hostname), 1)

        path_digits = sum(c.isdigit() for c in path)
        path_digit_ratio = path_digits / max(len(path), 1)

        query_lower = unquote(query).lower()

        query_has_password_like = int(
            any(x in query_lower for x in [
                "password", "passwd", "pass=", "pwd=", "credential", "otp"
            ])
        )

        query_has_redirect_like = int(
            any(x in query_lower for x in [
                "redirect=", "url=", "next=", "return=", "returnurl=",
                "continue=", "dest=", "destination="
            ])
        )

        has_fragment = int(bool(fragment))

        return {
            "url_length": url_length,
            "hostname_length": hostname_length,
            "path_length": len(path),
            "query_length": len(query),
            "fragment_length": len(fragment),

            "num_dots": parse_url.count("."),
            "num_hyphens": parse_url.count("-"),
            "num_underscores": parse_url.count("_"),
            "num_slashes": parse_url.count("/"),
            "num_digits": digits,

            "digit_ratio": digit_ratio,
            "special_char_ratio": special_char_ratio,

            "num_subdomains": num_subdomains,

            "has_https": int(parsed.scheme == "https"),
            "has_http": int(parsed.scheme == "http"),

            "has_at_symbol": has_at_symbol,
            "has_ip": has_ip,
            "has_port": has_port,

            "has_punycode": has_punycode,
            "has_encoded_chars": has_encoded_chars,
            "num_encoded_chars": num_encoded_chars,

            "has_double_slash_path": has_double_slash_path,
            "has_userinfo": has_userinfo,

            "has_suspicious_tld": has_suspicious_tld,
            "has_shortener": has_shortener,

            "num_phishing_keywords": num_phishing_keywords,

            "has_brand_name": has_brand_name,
            "brand_in_subdomain": brand_in_subdomain,
            "brand_in_path": brand_in_path,

            "hostname_entropy": hostname_entropy,
            "path_entropy": path_entropy,

            "has_long_subdomain": has_long_subdomain,
            "has_many_subdomains": has_many_subdomains,

            "has_suspicious_port": has_suspicious_port,

            "has_numeric_hostname": has_numeric_hostname,
            "hostname_digit_ratio": hostname_digit_ratio,
            "path_digit_ratio": path_digit_ratio,

            "query_has_password_like": query_has_password_like,
            "query_has_redirect_like": query_has_redirect_like,
            "has_fragment": has_fragment,

            # Compatibility aliases used by the existing UI.
            "has_IP_in_url": has_ip,
            "uses_url_shortener": has_shortener,
            "has_redirect": query_has_redirect_like,
        }

    def extract_features_batch(self, urls):
        return [self.extract_features(url) for url in urls]

    @staticmethod
    def _entropy(value):
        if not value:
            return 0.0

        counts = {}

        for char in value:
            counts[char] = counts.get(char, 0) + 1

        length = len(value)
        entropy = 0.0

        for count in counts.values():
            probability = count / length
            entropy -= probability * math.log2(probability)

        return entropy
