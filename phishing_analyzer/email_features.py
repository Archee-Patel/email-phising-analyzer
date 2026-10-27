import re
from collections import Counter
from email.message import Message
from email.utils import getaddresses, parseaddr
from html.parser import HTMLParser
from typing import Dict, Iterable, List, Tuple
from urllib.parse import unquote, urlsplit


FeatureGroups = Dict[str, Dict[str, object]]

URL_PATTERN = re.compile(r"""(?i)\b(?:https?://|www\.)[^\s<>"']+""")
WORD_PATTERN = re.compile(r"[a-z]{3,}")
PHISHING_WORDS = {
    "account", "action", "alert", "bank", "billing", "blocked", "confirm",
    "credentials", "expired", "immediately", "invoice", "login", "password",
    "payment", "secure", "suspended", "update", "urgent", "verify",
}
SHORTENING_HOSTS = {
    "bit.ly", "goo.gl", "is.gd", "ow.ly", "rb.gy", "t.co", "tiny.cc",
    "tinyurl.com",
}


class _HTMLTextParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.text: List[str] = []
        self.links: List[Tuple[str, str]] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, str]]) -> None:
        if tag.lower() == "a":
            attributes = dict(attrs)
            href = attributes.get("href", "")
            if href:
                self.links.append((href, ""))

    def handle_data(self, data: str) -> None:
        self.text.append(data)
        if self.links and not self.links[-1][1]:
            href, _ = self.links[-1]
            self.links[-1] = (href, data)


def _decode_part(part: Message) -> str:
    payload = part.get_payload(decode=True)
    if payload is None:
        raw = part.get_payload()
        return raw if isinstance(raw, str) else ""
    charset = part.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except LookupError:
        return payload.decode("utf-8", errors="replace")


def _message_content(message: Message) -> Tuple[str, List[Tuple[str, str]], bool]:
    text_parts: List[str] = []
    html_parts: List[str] = []
    html_links: List[Tuple[str, str]] = []
    if message.is_multipart():
        parts: Iterable[Message] = message.walk()
    else:
        parts = [message]

    for part in parts:
        if part.get_content_maintype() == "multipart":
            continue
        content_type = part.get_content_type().lower()
        if content_type == "text/plain":
            text_parts.append(_decode_part(part))
        elif content_type == "text/html":
            parser = _HTMLTextParser()
            parser.feed(_decode_part(part))
            html_parts.extend(parser.text)
            html_links.extend(parser.links)

    body = "\n".join(text_parts + html_parts)
    return body, html_links, bool(html_parts)


def _domain(address: str) -> str:
    parsed = parseaddr(address)[1]
    if "@" not in parsed:
        return ""
    host = parsed.rsplit("@", 1)[1].strip().rstrip(".").lower()
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return host


def _header_addresses(message: Message, header: str) -> List[str]:
    return [address for _, address in getaddresses(message.get_all(header, [])) if address]


def _url_host(url: str) -> str:
    candidate = url.strip().rstrip(".,;:!?)]}")
    if candidate.lower().startswith("www."):
        candidate = "http://" + candidate
    try:
        host = urlsplit(candidate).hostname or ""
        return host.rstrip(".").lower()
    except ValueError:
        return ""


def _url_scheme_and_netloc(url: str) -> Tuple[str, str]:
    candidate = "http://" + url if url.lower().startswith("www.") else url
    try:
        parsed = urlsplit(candidate)
        return parsed.scheme.lower(), parsed.netloc
    except ValueError:
        return "", ""


def extract_feature_groups(message: Message) -> FeatureGroups:
    """Extract interpretable header, link, and wording features from an email."""
    sender_addresses = _header_addresses(message, "From")
    reply_addresses = _header_addresses(message, "Reply-To")
    return_path_addresses = _header_addresses(message, "Return-Path")
    sender_domain = _domain(sender_addresses[0]) if sender_addresses else ""
    reply_domain = _domain(reply_addresses[0]) if reply_addresses else ""
    return_path_domain = (
        _domain(return_path_addresses[0]) if return_path_addresses else ""
    )

    authentication = " ".join(message.get_all("Authentication-Results", []))
    authentication_lower = authentication.lower()
    headers: Dict[str, object] = {
        "has_reply_to": int(bool(reply_addresses)),
        "sender_reply_to_domain_mismatch": int(
            bool(sender_domain and reply_domain and sender_domain != reply_domain)
        ),
        "has_return_path": int(bool(return_path_addresses)),
        "sender_return_path_domain_mismatch": int(
            bool(sender_domain and return_path_domain and sender_domain != return_path_domain)
        ),
        "has_authentication_results": int(bool(authentication)),
        "spf_pass": int(bool(re.search(r"\bspf\s*=\s*pass\b", authentication_lower))),
        "dkim_pass": int(bool(re.search(r"\bdkim\s*=\s*pass\b", authentication_lower))),
        "dmarc_pass": int(bool(re.search(r"\bdmarc\s*=\s*pass\b", authentication_lower))),
        "from_domain": sender_domain or "missing",
        "reply_to_domain": reply_domain or "missing",
        "subject_length": len(str(message.get("Subject", ""))),
        "sender_display_name_present": int(
            bool(parseaddr(message.get("From", ""))[0].strip())
        ),
    }

    body, html_links, has_html = _message_content(message)
    visible_urls = URL_PATTERN.findall(body)
    all_urls = [(url, "") for url in visible_urls] + html_links
    hosts = [_url_host(url) for url, _ in all_urls]
    hosts = [host for host in hosts if host]
    ip_hosts = sum(
        bool(re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host)) for host in hosts
    )
    link_features: Dict[str, object] = {
        "url_count": len(all_urls),
        "unique_url_domains": len(set(hosts)),
        "url_domain_is_ip": int(ip_hosts > 0),
        "shortened_url_count": sum(host in SHORTENING_HOSTS for host in hosts),
        "url_uses_https_only": int(
            bool(all_urls)
            and all(_url_scheme_and_netloc(url)[0] == "https" for url, _ in all_urls)
        ),
        "url_sender_domain_mismatch_count": sum(
            bool(sender_domain and host and host != sender_domain
                 and not host.endswith("." + sender_domain))
            for host in hosts
        ),
        "punycode_url_count": sum("xn--" in host for host in hosts),
        "url_with_userinfo_count": sum(
            "@" in _url_scheme_and_netloc(url)[1] for url, _ in all_urls
        ),
        "percent_encoded_url_count": sum("%" in unquote(url) or "%" in url for url, _ in all_urls),
        "html_body_present": int(has_html),
    }

    words = [word.lower() for word in WORD_PATTERN.findall(body)]
    counts = Counter(words)
    wording: Dict[str, object] = {
        "body_word_count": len(words),
        "urgent_or_account_word_count": sum(
            count for word, count in counts.items() if word in PHISHING_WORDS
        ),
        "exclamation_count": body.count("!"),
        "question_count": body.count("?"),
        "uppercase_ratio": (
            sum(character.isupper() for character in body) / max(len(body), 1)
        ),
        "credential_or_account_language": int(
            any(word in counts for word in {"password", "login", "account", "verify"})
        ),
    }
    return {"headers": headers, "links": link_features, "wording": wording}


def flatten_features(groups: FeatureGroups, selected_groups: List[str]) -> Dict[str, object]:
    return {
        "{}__{}".format(group, name): value
        for group in selected_groups
        for name, value in groups[group].items()
    }


def explain_features(groups: FeatureGroups) -> List[str]:
    headers = groups["headers"]
    links = groups["links"]
    wording = groups["wording"]
    reasons: List[str] = []
    if headers["sender_reply_to_domain_mismatch"]:
        reasons.append("Sender domain does not match the Reply-To domain.")
    if headers["sender_return_path_domain_mismatch"]:
        reasons.append("Sender domain does not match the Return-Path domain.")
    if headers["has_authentication_results"] and not any(
        headers[key] for key in ("spf_pass", "dkim_pass", "dmarc_pass")
    ):
        reasons.append("Authentication-Results contains no SPF, DKIM, or DMARC pass.")
    if links["url_domain_is_ip"]:
        reasons.append("A link uses an IP address instead of a domain name.")
    if links["shortened_url_count"]:
        reasons.append("The message contains a shortened link.")
    if links["punycode_url_count"]:
        reasons.append("A link contains a punycode domain.")
    if links["url_with_userinfo_count"]:
        reasons.append("A link contains user information before its host.")
    if links["url_sender_domain_mismatch_count"]:
        reasons.append("At least one link domain differs from the sender domain.")
    if wording["urgent_or_account_word_count"] >= 2:
        reasons.append("The wording uses multiple urgency or account-related terms.")
    if wording["credential_or_account_language"]:
        reasons.append("The wording refers to account access or verification.")
    if not reasons:
        reasons.append("No configured high-signal indicators were detected.")
    return reasons
