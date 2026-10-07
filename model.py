import os
import re
import joblib
import pandas as pd
from urllib.parse import urlparse

from features import URLFeatureExtractor


class PhishingDetector:
    """
    PhishGuard hybrid URL detector.

    Decision layers:
      1. Known/trusted domains -> LEGITIMATE
      2. Official namespace checks -> LEGITIMATE
      3. ML model -> LEGITIMATE / SUSPICIOUS / PHISHING

    IMPORTANT:
    A trusted domain does not mean every page on that domain is harmless.
    The trusted list is intended to reduce false positives during demos.
    Look-alike domains are never accepted just because they contain a trusted
    brand name.
    """

    MODEL_VERSION = 5

    # Large list of commonly used, well-known domains.
    # Matching is exact-root or real subdomain only.
    TRUSTED_DOMAINS = {
        # Search / web
        "google.com", "google.co.in", "google.co.uk", "google.de", "google.fr", "google.ca", "google.com.au", "google.co.jp",
        "googleusercontent.com", "gstatic.com", "googleapis.com", "googlevideo.com", "googlesyndication.com", "googleadservices.com",
        "youtube.com", "youtu.be", "ytimg.com", "bing.com", "duckduckgo.com", "yahoo.com", "yandex.com", "yandex.ru",
        "baidu.com", "wikipedia.org", "wikimedia.org", "archive.org", "webcache.googleusercontent.com", "gov.com", "phishtank.org", "phishtank.net", "phishtank.com", "talosintelligence.com", "cisco.com",

        # Microsoft / Windows / enterprise cloud
        "microsoft.com", "microsoftonline.com", "live.com", "outlook.com", "office.com", "office365.com", "windows.com",
        "azure.com", "azurewebsites.net", "sharepoint.com", "sharepointonline.com", "onedrive.com", "visualstudio.com",
        "xbox.com", "bing.com", "msn.com", "microsoft365.com", "powerbi.com", "dynamics.com", "teams.microsoft.com",

        # Apple
        "apple.com", "icloud.com", "itunes.com", "appleid.apple.com",

        # Amazon / AWS
        "amazon.com", "amazon.in", "amazon.co.uk", "amazon.de", "amazon.ca", "amazon.com.au", "amazon.co.jp",
        "amazonaws.com", "aws.amazon.com", "awsstatic.com", "cloudfront.net", "primevideo.com",

        # Meta / social / communication
        "facebook.com", "instagram.com", "threads.net", "messenger.com", "whatsapp.com", "whatsapp.net", "meta.com",
        "linkedin.com", "licdn.com", "x.com", "twitter.com", "tiktok.com", "snapchat.com", "pinterest.com",
        "reddit.com", "redditmedia.com", "tumblr.com", "telegram.org", "telegram.me", "discord.com", "discordapp.com",
        "mastodon.social", "medium.com", "quora.com",

        # Developer / technology / open source
        "github.com", "githubusercontent.com", "githubassets.com", "gitlab.com", "bitbucket.org", "stackoverflow.com",
        "stackexchange.com", "superuser.com", "serverfault.com", "npmjs.com", "npmjs.org", "pypi.org", "python.org",
        "pythonhosted.org", "docker.com", "docker.io", "kubernetes.io", "apache.org", "mozilla.org", "firefox.com",
        "chromium.org", "ubuntu.com", "debian.org", "redhat.com", "canonical.com", "linux.org", "kernel.org",
        "gnu.org", "rust-lang.org", "golang.org", "nodejs.org", "react.dev", "vuejs.org", "angular.dev", "flutter.dev",
        "dart.dev", "java.com", "oracle.com", "javatpoint.com", "tutorialspoint.com", "geeksforgeeks.org",
        "freecodecamp.org", "w3.org", "w3schools.com", "developer.mozilla.org", "dev.to", "codepen.io", "jsfiddle.net",

        # Cloud / productivity / collaboration
        "dropbox.com", "box.com", "notion.so", "notion.com", "slack.com", "zoom.us", "atlassian.com", "trello.com",
        "asana.com", "monday.com", "canva.com", "figma.com", "miro.com", "grammarly.com", "evernote.com", "airtable.com",
        "clickup.com", "basecamp.com", "todoist.com", "docusign.com", "adobe.com", "acrobat.com", "salesforce.com",
        "hubspot.com", "mailchimp.com", "zapier.com", "calendly.com", "typeform.com", "surveyMonkey.com",

        # AI / software platforms
        "openai.com", "chatgpt.com", "anthropic.com", "claude.ai", "huggingface.co", "perplexity.ai", "gemini.google.com",
        "deepmind.google", "ai.google", "vercel.com", "netlify.com", "heroku.com", "render.com", "railway.app",
        "digitalocean.com", "linode.com", "akamai.com", "cloudflare.com", "cloudflareaccess.com", "fastly.com",
        "databricks.com", "snowflake.com", "mongodb.com", "redis.io", "elastic.co", "postman.com", "insomnia.rest",

        # Streaming / entertainment / gaming
        "netflix.com", "spotify.com", "soundcloud.com", "twitch.tv", "disneyplus.com", "disney.com", "hulu.com",
        "garena.com", "intl.garena.com", "mobile.garena.com", "ff.garena.com", "support.garena.com", "help.garena.com", "account.garena.com",
        "pubg.com", "pubgmobile.com", "battlegrounds.pubg.com", "krafton.com", "playbattlegrounds.com",
        "imdb.com", "rottentomatoes.com", "steampowered.com", "epicgames.com", "playstation.com", "xbox.com",
        "nintendo.com", "ea.com", "ubisoft.com", "rockstargames.com", "roblox.com", "minecraft.net", "ign.com",
        "fandom.com", "crunchyroll.com", "primevideo.com",

        # Payments / finance / crypto
        "paypal.com", "paypal.me", "stripe.com", "squareup.com", "wise.com", "visa.com", "mastercard.com",
        "americanexpress.com", "discover.com", "revolut.com", "binance.com", "coinbase.com", "kraken.com", "gemini.com",
        "coindesk.com", "coinmarketcap.com", "metamask.io", "blockchain.com", "robinhood.com", "fidelity.com",
        "schwab.com", "vanguard.com", "jpmorgan.com", "chase.com", "bankofamerica.com", "wellsfargo.com",

        # India payments / banks / financial services
        "phonepe.com", "paytm.com", "razorpay.com", "cashfree.com", "payu.in", "billdesk.com", "npci.org.in",
        "upi.npci.org.in", "sbi.co.in", "onlinesbi.sbi", "hdfcbank.com", "icicibank.com", "axisbank.com",
        "kotak.com", "kotakbank.com", "indusind.com", "indusindbank.com", "bankofbaroda.in", "bankofbaroda.com",
        "pnbindia.in", "canarabank.com", "unionbankofindia.co.in", "idfcfirstbank.com", "yesbank.in",
        "federalbank.co.in", "idbibank.in", "rblbank.com", "aubank.in", "bandhanbank.com", "bobworld.com",
        "licindia.in", "licindia.com", "irdai.gov.in", "sebi.gov.in", "amfiindia.com", "bseindia.com", "nseindia.com",

        # Shopping / travel / food / services
        "flipkart.com", "myntra.com", "ajio.com", "meesho.com", "snapdeal.com", "ebay.com", "etsy.com", "walmart.com",
        "target.com", "bestbuy.com", "costco.com", "homedepot.com", "ikea.com", "decathlon.in", "decathlon.com",
        "booking.com", "airbnb.com", "makemytrip.com", "goibibo.com", "irctc.co.in", "irctc.gov.in", "uber.com",
        "ola.com", "swiggy.com", "zomato.com", "dominos.com", "kfc.com", "mcdonalds.com", "starbucks.com",
        "tripadvisor.com", "expedia.com", "agoda.com", "cleartrip.com", "easemytrip.com",

        # News / media / reference
        "bbc.com", "bbc.co.uk", "cnn.com", "reuters.com", "apnews.com", "nytimes.com", "theguardian.com",
        "washingtonpost.com", "timesofindia.indiatimes.com", "hindustantimes.com", "ndtv.com", "indiatoday.in",
        "thehindu.com", "indianexpress.com", "economictimes.indiatimes.com", "moneycontrol.com", "livemint.com",
        "news18.com", "timesnownews.com", "firstpost.com", "scroll.in", "deccanherald.com", "deccanchronicle.com",

        # Business / enterprise / hardware
        "ibm.com", "oracle.com", "sap.com", "autodesk.com", "intel.com", "amd.com", "nvidia.com", "dell.com",
        "hp.com", "lenovo.com", "samsung.com", "sony.com", "cisco.com", "vmware.com", "servicenow.com", "twilio.com",
        "okta.com", "auth0.com", "datadog.com", "newrelic.com", "zoom.com", "lenovo.com", "acer.com", "asus.com",
        "lg.com", "panasonic.com", "philips.com", "siemens.com", "bosch.com", "3m.com", "tesla.com",

        # Education / research / course portals
        "shiksha.com", "collegedunia.com", "collegedekho.com", "careers360.com", "getmyuni.com", "universitydunia.com",
        "javatpoint.com", "tutorialspoint.com", "geeksforgeeks.org", "coursera.org", "udemy.com", "edx.org",
        "khanacademy.org", "freecodecamp.org", "codecademy.com", "udacity.com", "simplilearn.com", "upgrad.com",
        "mit.edu", "stanford.edu", "harvard.edu", "berkeley.edu", "cmu.edu", "cornell.edu", "princeton.edu",
        "yale.edu", "ox.ac.uk", "cam.ac.uk", "ed.ac.uk", "imperial.ac.uk", "iitb.ac.in", "iitd.ac.in", "iitm.ac.in",
        "iitk.ac.in", "iitr.ac.in", "iisc.ac.in", "nptel.ac.in", "swayam.gov.in", "ugc.gov.in", "aicte-india.org",
        "aicte.gov.in", "ernet.in", "ignou.ac.in", "du.ac.in", "jnu.ac.in", "amu.ac.in", "bhu.ac.in", "annauniv.edu",
        "osmania.ac.in", "universityofcalicut.info", "kuvempu.ac.in",

        # Indian government / public services
        "india.gov.in", "mygov.in", "uidai.gov.in", "incometax.gov.in", "gst.gov.in", "epfindia.gov.in", "esic.gov.in",
        "passportindia.gov.in", "parivahan.gov.in", "digilocker.gov.in", "umang.gov.in", "cowin.gov.in", "pib.gov.in",
        "nic.in", "gov.in", "dce.karnataka.gov.in", "kar.nic.in", "karnataka.gov.in", "karnataka.gov.in",
        "services.india.gov.in", "data.gov.in", "myscheme.gov.in", "ncs.gov.in", "mca.gov.in", "eci.gov.in",
        "supremecourtofindia.nic.in", "doj.gov.in", "legislative.gov.in", "mea.gov.in", "mohfw.gov.in", "education.gov.in",
        "mha.gov.in", "mod.gov.in", "defence.gov.in", "railway.gov.in", "isro.gov.in", "drdo.gov.in", "rbi.org.in",
        "nabard.org", "irdai.gov.in", "trai.gov.in", "dot.gov.in", "morth.nic.in", "mparivahan.gov.in",

        # Major Indian state / local government domains frequently encountered
        "maharashtra.gov.in", "kerala.gov.in", "tn.gov.in", "telangana.gov.in", "ap.gov.in", "andhra-pradesh.gov.in",
        "odisha.gov.in", "westbengal.gov.in", "gujarat.gov.in", "rajasthan.gov.in", "mp.gov.in", "up.gov.in",
        "bihar.gov.in", "jharkhand.gov.in", "chhattisgarh.gov.in", "goa.gov.in", "haryana.gov.in", "punjab.gov.in",
        "himachal.gov.in", "uttarakhand.gov.in", "assam.gov.in", "manipur.gov.in", "meghalaya.gov.in", "mizoram.gov.in",
        "nagaland.gov.in", "tripura.gov.in", "sikkim.gov.in", "arunachalpradesh.gov.in", "ladakh.gov.in", "jammu.gov.in",

        # Common legitimate utilities / documentation / testing
        "example.com", "example.org", "example.net", "neverssl.com", "httpforever.com", "iana.org", "internic.net",
        "letsencrypt.org", "eff.org", "owasp.org", "haveibeenpwned.com", "urlscan.io",
    }

    # Official namespaces. These are deliberately restricted to namespaces
    # where registration is controlled or institutionally restricted.
    TRUSTED_SUFFIXES = (
        ".gov.in",
        ".nic.in",
        ".mil.in",
        ".ac.in",
        ".edu.in",
        ".res.in",
        ".gov.uk",
        ".ac.uk",
        ".edu.au",
        ".gov.au",
        ".gc.ca",
        ".gouv.fr",
        ".go.jp",
        ".gov.sg",
        ".gov.nz",
        ".gov.za",
    )

    # Never use a brand substring as a trust rule.
    # e.g. youtube.com.evil.com must NOT be trusted.

    def __init__(self, model_path="phishing_model.pkl"):
        print("Loading PhishGuard model...")

        if not os.path.exists(model_path):
            raise FileNotFoundError(
                f"Model not found: {model_path}. Run train_model.py first."
            )

        model_data = joblib.load(model_path)
        self.model = model_data["model"]
        self.model_name = model_data.get("model_name", "ML Classifier")
        self.feature_extractor = URLFeatureExtractor()

        saved_features = model_data.get("feature_names")
        self.feature_names = saved_features or self.feature_extractor.feature_names

        print(f"Model loaded: {self.model_name}")

    @staticmethod
    def _hostname(url):
        value = url.strip()
        if not re.match(r"^https?://", value, re.I):
            value = "https://" + value
        try:
            return (urlparse(value).hostname or "").lower().rstrip(".")
        except Exception:
            return ""

    @staticmethod
    def _is_https(url):
        return url.strip().lower().startswith("https://")

    @classmethod
    def _is_trusted_domain(cls, hostname):
        if not hostname:
            return False

        # Exact trusted root or an actual subdomain.
        for domain in cls.TRUSTED_DOMAINS:
            if hostname == domain or hostname.endswith("." + domain):
                return True

        # Controlled/restricted official namespaces.
        for suffix in cls.TRUSTED_SUFFIXES:
            if hostname.endswith(suffix):
                return True

        return False

    @classmethod
    def _looks_like_ip(cls, hostname):
        return bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", hostname or ""))

    def _trusted_result(self, url, features, hostname, reason):
        https = self._is_https(url)
        security_status = "SECURE" if https else "NOT SECURE"
        security_message = (
            "HTTPS encryption detected"
            if https
            else "HTTP connection is not encrypted"
        )

        return {
            "url": url,
            "prediction": "Legitimate",
            "status": "LEGITIMATE",
            "is_phishing": False,
            "confidence": 99.0,
            "phishing_probability": 1.0,
            "legitimate_probability": 99.0,
            "probability": {"phishing": 0.01, "legitimate": 0.99},
            "model": "Hybrid ML + Domain Verification",
            "model_used": "Trusted Domain Verification",
            "decision_source": "trusted_domain",
            "trusted_domain": hostname,
            "trusted_reason": reason,
            "security": {
                "status": security_status,
                "https": https,
                "message": security_message,
            },
            "features": features,
            "explanation": [
                f"Trusted domain verified: {hostname}",
                reason,
                security_message,
            ],
        }

    def _ml_result(self, url, features):
        X = pd.DataFrame([features])[self.feature_names]
        probabilities = self.model.predict_proba(X)[0]
        prediction = int(self.model.predict(X)[0])

        class_probabilities = {
            int(cls): float(prob)
            for cls, prob in zip(self.model.classes_, probabilities)
        }

        phishing_probability = class_probabilities.get(0, 0.0) * 100
        legitimate_probability = class_probabilities.get(1, 0.0) * 100

        # Three-level result. A moderate ML score is not called confirmed
        # phishing; this reduces false positives during demonstrations.
        if phishing_probability >= 80:
            status = "PHISHING"
            prediction_name = "Phishing"
            is_phishing = True
            confidence = phishing_probability
        elif phishing_probability >= 30:
            status = "SUSPICIOUS"
            prediction_name = "Suspicious"
            is_phishing = False
            confidence = max(phishing_probability, legitimate_probability)
        else:
            status = "LEGITIMATE"
            prediction_name = "Legitimate"
            is_phishing = False
            confidence = legitimate_probability

        https = self._is_https(url)
        security_status = "SECURE" if https else "NOT SECURE"
        security_message = (
            "HTTPS encryption detected"
            if https
            else "HTTP connection is not encrypted"
        )

        return {
            "url": url,
            "prediction": prediction_name,
            "status": status,
            "is_phishing": is_phishing,
            "confidence": confidence,
            "phishing_probability": phishing_probability,
            "legitimate_probability": legitimate_probability,
            "probability": {
                "phishing": phishing_probability / 100,
                "legitimate": legitimate_probability / 100,
            },
            "model": self.model_name,
            "model_used": self.model_name,
            "decision_source": "machine_learning",
            "security": {
                "status": security_status,
                "https": https,
                "message": security_message,
            },
            "features": features,
        }

    def predict(self, url):
        features = self.feature_extractor.extract_features(url)
        hostname = self._hostname(url)

        # Domain verification happens before the ML model so common legitimate
        # domains do not get falsely rejected because of their URL structure.
        if self._is_trusted_domain(hostname):
            if any(
                hostname == d or hostname.endswith("." + d)
                for d in self.TRUSTED_DOMAINS
            ):
                reason = "Domain is in the PhishGuard trusted-domain list"
            else:
                reason = "Domain uses a controlled/restricted official namespace"

            return self._trusted_result(url, features, hostname, reason)

        return self._ml_result(url, features)

    def explain_prediction(self, url):
        result = self.predict(url)
        features = result["features"]
        explanations = list(result.get("explanation", []))

        if features.get("has_https", 0):
            if not any("HTTPS" in x for x in explanations):
                explanations.append("HTTPS encryption detected")
        else:
            if not any("HTTP" in x for x in explanations):
                explanations.append("HTTP connection is not encrypted")

        checks = [
            ("has_ip", "IP address used instead of a normal domain"),
            ("has_suspicious_tld", "Suspicious TLD detected"),
            ("has_shortener", "URL shortening service detected"),
            ("has_at_symbol", "@ symbol detected in URL"),
            ("has_suspicious_port", "Non-standard port detected"),
            ("has_punycode", "Punycode domain detected"),
            ("has_encoded_chars", "Encoded characters detected"),
            ("brand_in_subdomain", "Brand name appears in the first hostname label"),
            ("query_has_password_like", "Password/OTP-like query parameter detected"),
            ("query_has_redirect_like", "Redirect-like query parameter detected"),
            ("has_many_subdomains", "Many subdomains detected"),
            ("has_long_subdomain", "Unusually long subdomain detected"),
        ]

        for key, message in checks:
            if features.get(key, 0):
                explanations.append(message)

        keyword_count = int(features.get("num_phishing_keywords", 0))
        if keyword_count:
            explanations.append(f"{keyword_count} suspicious keyword(s) detected")

        if features.get("url_length", 0) > 120:
            explanations.append("URL is unusually long")

        if features.get("hostname_entropy", 0) > 4.0:
            explanations.append("Hostname has high character randomness")

        if not explanations:
            explanations.append("No major suspicious URL features detected")

        result["explanation"] = explanations
        return result

    def predict_batch(self, urls):
        return [self.predict(url) for url in urls]
