from __future__ import annotations

import json
import os
import socket
import ssl
import unicodedata
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from html import escape
from ipaddress import IPv4Address, IPv6Address, ip_address, is_link_local, is_loopback, is_multicast, is_private, is_reserved
from typing import Any, Iterable
from urllib.parse import parse_qsl, urljoin, urlparse, urlunparse

try:
    import idna
except ModuleNotFoundError:  # pragma: no cover
    idna = None

try:
    import publicsuffixlist
except ModuleNotFoundError:  # pragma: no cover
    publicsuffixlist = None

try:
    import httpx
except ModuleNotFoundError:  # pragma: no cover
    httpx = None

try:
    import typer
    from rich.console import Console
    from rich.table import Table
except ModuleNotFoundError:  # pragma: no cover
    typer = None
    Console = None
    Table = None

try:
    import dns.exception
    import dns.resolver
except ModuleNotFoundError:  # pragma: no cover
    dns = None


KEYWORD_SIGNAL = [
    "verify",
    "login",
    "secure",
    "account",
    "update",
    "confirm",
    "bank",
    "password",
    "alert",
    "invoice",
    "payment",
    "support",
    "security",
    "billing",
]
KNOWN_SUFFIXES = {"co.uk", "com.au", "org.uk", "gov.uk", "ac.uk", "co.jp", "com.cn", "com.tr"}


class PhishLensError(RuntimeError):
    """Base exception for PhishLens errors."""


class URLValidationError(PhishLensError):
    """Raised when a URL has invalid structure."""


class AnalysisUnavailableError(PhishLensError):
    """Raised when a module is unavailable or cannot complete safely."""


@dataclass
class Rule:
    rule_id: str
    name: str
    description: str
    severity: str
    evidence: str
    score: int
    recommendation: str
    confidence: str = "medium"


@dataclass
class Finding:
    rule_id: str
    name: str
    severity: str
    description: str
    evidence: str
    score: int
    recommendation: str
    confidence: str = "medium"
    evidence_type: str = "heuristic"


@dataclass
class URLAnalysis:
    url: str
    normalized_url: str
    scheme: str
    hostname: str
    registrable_domain: str
    is_ip_address: bool
    is_suspicious: bool
    score: int
    classification: str
    findings: list[Finding] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class DomainInfo:
    hostname: str
    registrable_domain: str
    subdomains: list[str]
    tld: str
    suspicious: bool
    notes: list[str] = field(default_factory=list)


@dataclass
class DNSResult:
    hostname: str
    records: dict[str, list[str]] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    state: str = "unavailable"


@dataclass
class TLSResult:
    hostname: str
    valid: bool
    state: str
    issuer: str | None = None
    subject: str | None = None
    sans: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    certificate_expired: bool = False


@dataclass
class RedirectResult:
    initial_url: str
    redirects: list[str]
    loop_detected: bool
    cross_domain: bool
    state: str
    errors: list[str] = field(default_factory=list)


DEFAULT_RULES: list[Rule] = [
    Rule("R001", "Confirmed malicious reputation", "A trusted reputation source has identified the URL as malicious.", "critical", "Threat intelligence source flagged the URL.", 40, "Treat as strongly suspicious and avoid clicking.", "high"),
    Rule("R002", "Unicode homograph indicators", "Unicode characters visually resemble ASCII characters and may be used in homograph attacks.", "high", "Mixed-script or confusable Unicode in the hostname or path.", 25, "Inspect the hostname carefully and validate the destination using a safe method.", "high"),
    Rule("R003", "Strong brand impersonation indicators", "The host structure resembles a well-known brand but with deceptive placement or padding.", "high", "Suspicious subdomains or path patterns mimic a trusted brand.", 25, "Verify the actual domain against the brand's official URL before proceeding.", "medium"),
    Rule("R004", "Direct IP address URL", "The destination is directly an IP address. This often appears in phishing or malware infrastructure.", "medium", "Host resolves to a literal IP address rather than a hostname.", 15, "Prefer a trusted hostname and validate the IP against official service records.", "medium"),
    Rule("R005", "Cross-domain redirect", "A redirect jumps to a different registrable domain, which may indicate credential theft or malicious landing pages.", "medium", "Redirect target differs from the original registrable domain.", 15, "Review the redirect chain and confirm the final destination is expected.", "medium"),
    Rule("R006", "Recently registered domain", "A very new domain may be used for short-lived phishing campaigns.", "medium", "Registration age is extremely recent or unknown but suspicious.", 10, "Validate the domain's age and registration details before trusting the site.", "medium"),
    Rule("R007", "Suspicious credential-related URL structures", "The URL encodes credentials or login semantics in a way that is frequently used in phishing.", "medium", "Embedded credentials, login-related paths, or deceptive account triggers found in the URL.", 10, "Do not enter credentials into a URL that appears modified or deceptive.", "medium"),
    Rule("R008", "Excessive URL length", "The URL is unusually long, which often indicates obfuscation or tracking parameters.", "low", "Length exceeds operational thresholds for typical web destinations.", 5, "Review the destination and avoid submitting confidential data to excessively long links.", "medium"),
]


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _normalize_hostname(hostname: str) -> str:
    return hostname.strip().rstrip(".").lower()


def decode_idna_hostname(hostname: str) -> str:
    host = _normalize_hostname(hostname)
    if not host or (host.startswith("[") and host.endswith("]")):
        return host
    if idna is not None:
        try:
            if host.startswith("xn--"):
                return idna.decode(host.encode("ascii"))
            if any(ord(ch) > 127 for ch in host):
                return idna.decode(host.encode("utf-8"), uts46=True)
        except Exception:
            pass
    if host.startswith("xn--"):
        try:
            return host.encode("ascii").decode("idna")
        except UnicodeError:
            return host
    return host


def normalize_url(raw_url: str) -> str:
    candidate = raw_url.strip()
    if not candidate:
        raise URLValidationError("The URL is empty.")
    parsed = urlparse(candidate)
    if not parsed.scheme or not parsed.netloc:
        if "//" in candidate and not parsed.scheme:
            candidate = "https://" + candidate.lstrip("/")
            parsed = urlparse(candidate)
        else:
            raise URLValidationError("URL parsing failed. Ensure the URL includes a scheme and hostname.")
    if parsed.scheme.lower() not in {"http", "https"}:
        raise URLValidationError("PhishLens supports HTTP and HTTPS URLs only.")
    hostname = (parsed.hostname or "").lower()
    if not hostname:
        raise URLValidationError("The URL does not include a valid hostname.")
    host = decode_idna_hostname(hostname)
    netloc = host
    if parsed.username or parsed.password:
        user = parsed.username or ""
        password = parsed.password or ""
        netloc = f"{user}:{password}@{host}" if password else f"{user}@{host}" if user else host
    if parsed.port is not None and parsed.port not in {80, 443}:
        netloc = f"{netloc}:{parsed.port}"
    return urlunparse((parsed.scheme.lower(), netloc, parsed.path or "/", "", parsed.query, parsed.fragment))


def _psl_lookup(hostname: str) -> str:
    if publicsuffixlist is None:
        return ""
    try:
        psl = publicsuffixlist.PublicSuffixList()
    except Exception:
        return ""
    for attr in ("get_public_suffix", "publicsuffix", "suffix", "get_sld", "get_registrable_domain"):
        method = getattr(psl, attr, None)
        if method is None:
            continue
        try:
            value = method(hostname)
            if isinstance(value, str) and value.strip():
                return value.strip().lower()
        except Exception:
            continue
    return ""


def extract_registrable_domain(hostname: str) -> str:
    host = decode_idna_hostname(hostname).strip().lower().rstrip(".")
    if not host or host.startswith("[") and host.endswith("]"):
        return host
    try:
        return str(ip_address(host))
    except ValueError:
        pass
    psl_value = _psl_lookup(host)
    if psl_value:
        return psl_value
    labels = host.split(".")
    if len(labels) < 2:
        return host
    if len(labels) == 2:
        return host
    for suffix in sorted(KNOWN_SUFFIXES, key=len, reverse=True):
        if host.endswith("." + suffix):
            return host.rsplit(".", 2)[-2] + "." + suffix
    return ".".join(labels[-2:])


def has_unicode_confusable(value: str) -> bool:
    for ch in value:
        if ord(ch) <= 127:
            continue
        if unicodedata.normalize("NFKC", ch).isascii() and unicodedata.normalize("NFKC", ch) != ch:
            return True
        if any(candidate.isascii() and candidate != ch for candidate in unicodedata.normalize("NFKD", ch)):
            return True
    return False


def detect_mixed_script(domain: str) -> bool:
    if not domain:
        return False
    latin = 0
    non_latin = 0
    for ch in domain.lower():
        if ord(ch) <= 127:
            continue
        name = unicodedata.name(ch, "")
        if "LATIN" in name:
            latin += 1
        elif any(token in name for token in ["CJK", "HIRAGANA", "KATAKANA", "ARABIC", "CYRILLIC", "GREEK", "DEVANAGARI", "ARMENIAN"]):
            non_latin += 1
        else:
            latin += 1
    return non_latin > 0 and latin > 0


def is_suspicious_domain(hostname: str) -> bool:
    host = hostname.lower().rstrip(".")
    if not host:
        return False
    if any(keyword in host for keyword in KEYWORD_SIGNAL):
        return True
    return host.count("-") > 2 or host.count(".") > 5


def analyze_domain(hostname: str) -> DomainInfo:
    host = _normalize_hostname(hostname)
    labels = [label for label in host.split(".") if label]
    registrable = extract_registrable_domain(host)
    subdomains = labels[:-2] if len(labels) >= 2 else []
    tld = labels[-1] if labels else ""
    notes: list[str] = []
    suspicious = False
    if len(labels) > 4:
        suspicious = True
        notes.append("The hostname has a deep subdomain structure.")
    if len(host) > 63:
        suspicious = True
        notes.append("The hostname length exceeds the ordinary maximum for a single label.")
    if any(label.startswith("xn--") for label in labels):
        notes.append("The hostname uses punycode and may hide Unicode content.")
    if detect_mixed_script(host):
        suspicious = True
        notes.append("The hostname combines multiple scripts and may be part of a homograph attack.")
    if is_suspicious_domain(host):
        suspicious = True
        notes.append("The hostname contains high-risk login or account semantics.")
    return DomainInfo(hostname=host, registrable_domain=registrable, subdomains=subdomains, tld=tld, suspicious=suspicious, notes=notes)


def score_rule_hits(findings: Iterable[Finding]) -> tuple[int, str, list[Finding]]:
    deduped: dict[str, Finding] = {}
    for finding in findings:
        current = deduped.get(finding.rule_id)
        if current is None or finding.score > current.score:
            deduped[finding.rule_id] = finding
    total = min(sum(item.score for item in deduped.values()), 100)
    if total < 20:
        classification = "LOW"
    elif total < 50:
        classification = "MEDIUM"
    elif total < 80:
        classification = "HIGH"
    else:
        classification = "CRITICAL"
    return total, classification, list(deduped.values())


class ScoringEngine:
    def __init__(self, rules: list[Rule] | None = None) -> None:
        self.rules = rules or DEFAULT_RULES
        self.rule_map = {rule.rule_id: rule for rule in self.rules}

    def evaluate(self, evidence: list[dict[str, Any]]) -> tuple[int, str, list[Finding]]:
        findings: list[Finding] = []
        for item in evidence:
            rule = self.rule_map.get(str(item.get("rule_id", "")).upper())
            if not rule:
                continue
            findings.append(
                Finding(
                    rule_id=rule.rule_id,
                    name=rule.name,
                    severity=rule.severity,
                    description=item.get("description", rule.description),
                    evidence=item.get("evidence", rule.evidence),
                    score=int(item.get("score", rule.score)),
                    recommendation=item.get("recommendation", rule.recommendation),
                    confidence=item.get("confidence", rule.confidence),
                    evidence_type=str(item.get("evidence_type", "heuristic")).lower(),
                )
            )
        return score_rule_hits(findings)


def detect_suspicious_keywords(value: str) -> list[str]:
    lowered = value.lower()
    return [keyword for keyword in KEYWORD_SIGNAL if keyword in lowered]


class URLAnalyzer:
    def __init__(self) -> None:
        self.scoring_engine = ScoringEngine(DEFAULT_RULES)

    def analyze(self, raw_url: str) -> URLAnalysis:
        url = normalize_url(raw_url)
        parsed = urlparse(url)
        scheme = parsed.scheme.lower()
        hostname = (parsed.hostname or "").lower()
        if not hostname:
            raise URLValidationError("The URL does not include a valid hostname.")
        registrable = extract_registrable_domain(hostname)
        try:
            ip_obj = ip_address(hostname)
            is_ip = True
        except ValueError:
            ip_obj = None
            is_ip = False

        evidence: list[dict[str, Any]] = []
        if is_ip:
            evidence.append({"rule_id": "R004", "description": "The URL targets a literal IP address rather than a hostname.", "evidence": f"Host resolves to {hostname}.", "score": 15, "recommendation": "Validate the IP address against an official and expected service before interacting with it.", "confidence": "medium", "evidence_type": "heuristic"})
            if isinstance(ip_obj, (IPv4Address, IPv6Address)) and (is_private(ip_obj) or is_loopback(ip_obj) or is_link_local(ip_obj) or is_multicast(ip_obj) or is_reserved(ip_obj)):
                evidence.append({"rule_id": "R004", "description": "The URL references a private or local network address.", "evidence": f"Resolved destination {hostname} is in a private or non-public range.", "score": 15, "recommendation": "Reject this destination because it is not a public internet endpoint.", "confidence": "high", "evidence_type": "heuristic"})
        if len(url) > 2048:
            evidence.append({"rule_id": "R008", "description": "The URL exceeds typical browser and server limits.", "evidence": f"The URL length is {len(url)} characters.", "score": 5, "recommendation": "Treat this as suspicious and verify the destination before sending credentials.", "confidence": "medium", "evidence_type": "heuristic"})
        if parsed.username or parsed.password:
            evidence.append({"rule_id": "R007", "description": "The URL embeds credentials in the network location.", "evidence": "Credentials are present before the hostname separator.", "score": 10, "recommendation": "Do not trust a URL that contains embedded usernames or passwords.", "confidence": "high", "evidence_type": "heuristic"})
        if parsed.port is not None and parsed.port not in {80, 443}:
            evidence.append({"rule_id": "R007", "description": "The URL uses a non-standard port, which may support phishing infrastructure.", "evidence": f"The URL uses port {parsed.port} instead of the usual HTTP(S) ports.", "score": 10, "recommendation": "Validate the port against the expected service before interacting with the site.", "confidence": "medium", "evidence_type": "heuristic"})
        if "@" in url:
            evidence.append({"rule_id": "R007", "description": "The URL contains an @ character before the hostname, which can hide the real destination.", "evidence": "User information appears before the hostname in the URL.", "score": 10, "recommendation": "Use care with URLs that contain @ because it can obscure the actual target.", "confidence": "medium", "evidence_type": "heuristic"})
        if hostname.startswith("xn--"):
            evidence.append({"rule_id": "R002", "description": "The hostname is encoded with punycode and may conceal a deceptive Unicode domain.", "evidence": f"The hostname begins with {hostname.split('.')[0]} and is in punycode form.", "score": 25, "recommendation": "Decode the domain and validate it against the expected brand or service.", "confidence": "high", "evidence_type": "heuristic"})
        if has_unicode_confusable(hostname):
            evidence.append({"rule_id": "R002", "description": "Unicode characters in the hostname resemble ASCII letters and may be used for visual impersonation.", "evidence": "The hostname contains non-ASCII characters that may confuse a user.", "score": 25, "recommendation": "Check whether the domain is visually consistent with the expected trusted website.", "confidence": "high", "evidence_type": "heuristic"})
        if detect_mixed_script(hostname):
            evidence.append({"rule_id": "R002", "description": "The hostname mixes scripts in ways that are often associated with homograph attacks.", "evidence": "The domain combines multiple scripts in a single hostname.", "score": 25, "recommendation": "Reject or manually verify the destination before continuing.", "confidence": "high", "evidence_type": "heuristic"})
        keywords = detect_suspicious_keywords(hostname + " " + parsed.path)
        if keywords:
            evidence.append({"rule_id": "R007", "description": "The URL contains credential or account-related terms that are commonly abused in phishing.", "evidence": f"Matched keywords: {', '.join(sorted(keywords))}.", "score": 10, "recommendation": "Exercise caution when a link uses trusted-brand or account semantics in a suspicious way.", "confidence": "medium", "evidence_type": "heuristic"})
        if "=" in parsed.query and len(parsed.query) > 200:
            evidence.append({"rule_id": "R008", "description": "The query string is unusually long and may be used to hide or obfuscate a phishing destination.", "evidence": f"Query length is {len(parsed.query)} characters.", "score": 5, "recommendation": "Review the destination and do not share confidential information with this link.", "confidence": "medium", "evidence_type": "heuristic"})
        if hostname.count(".") > 4 or hostname.count("-") > 2:
            evidence.append({"rule_id": "R003", "description": "The domain structure is unusually deep or padded, which can reduce user trust and hide brand impersonation.", "evidence": "Suspicious domain layout with multiple labels or separators.", "score": 25, "recommendation": "Check the exact trusted brand behind the subdomains before interacting with the link.", "confidence": "medium", "evidence_type": "heuristic"})
        domain_info = analyze_domain(hostname)
        if domain_info.suspicious:
            evidence.append({"rule_id": "R003", "description": "The domain structure is suspicious relative to a typical legitimate domain.", "evidence": "; ".join(domain_info.notes) if domain_info.notes else "Suspicious hostname pattern detected.", "score": 25, "recommendation": "Verify the domain against the organization's legitimate public website.", "confidence": "medium", "evidence_type": "heuristic"})
        score, classification, findings = self.scoring_engine.evaluate(evidence)
        return URLAnalysis(
            url=url,
            normalized_url=url,
            scheme=scheme,
            hostname=hostname,
            registrable_domain=registrable,
            is_ip_address=is_ip,
            is_suspicious=classification in {"MEDIUM", "HIGH", "CRITICAL"},
            score=score,
            classification=classification,
            findings=findings,
            metadata={"parsed_query": dict(parse_qsl(parsed.query, keep_blank_values=True)), "path": parsed.path, "port": parsed.port, "domain_info": asdict(domain_info), "evidence_count": len(evidence)},
        )


class DNSAnalyzer:
    def __init__(self, timeout: float = 3.0) -> None:
        self.timeout = timeout

    def _resolver(self) -> Any:
        if dns is None:
            return None
        resolver = dns.resolver.Resolver()
        resolver.timeout = self.timeout
        resolver.lifetime = self.timeout
        return resolver

    def analyze(self, hostname: str) -> DNSResult:
        if dns is None:
            return DNSResult(hostname=hostname, state="unavailable", errors=["dnspython is not installed."])
        try:
            resolver = self._resolver()
            if resolver is None:
                return DNSResult(hostname=hostname, state="unavailable", errors=["DNS resolver unavailable."])
            records: dict[str, list[str]] = {}
            for record_type in ("A", "AAAA", "MX", "NS", "TXT", "CNAME"):
                try:
                    answers = resolver.resolve(hostname, record_type, raise_on_no_answer=False)
                    if not answers:
                        continue
                    values = []
                    for answer in answers:
                        text = str(answer)
                        if record_type == "TXT" and hasattr(answer, "strings"):
                            text = ", ".join(str(part) for part in answer.strings)
                        values.append(text)
                    records[record_type] = values
                except dns.resolver.NoAnswer:
                    continue
                except dns.exception.Timeout:
                    return DNSResult(hostname=hostname, state="timeout", errors=[f"DNS timeout while resolving {record_type} records."])
                except dns.resolver.NXDOMAIN:
                    return DNSResult(hostname=hostname, state="resolution_failed", errors=["The domain does not exist."])
                except (dns.exception.DNSException, OSError) as exc:
                    return DNSResult(hostname=hostname, state="resolution_failed", errors=[f"DNS failure: {exc}."])
            txt_values = records.get("TXT", [])
            if any("SPF" in value.upper() for value in txt_values):
                records["SPF"] = ["SPF record found."]
            if any("DMARC" in value.upper() for value in txt_values):
                records["DMARC"] = ["DMARC record found."]
            return DNSResult(hostname=hostname, records=records, state="ok")
        except Exception as exc:  # pragma: no cover
            return DNSResult(hostname=hostname, state="analysis_unavailable", errors=[f"Unexpected DNS analysis error: {exc}."])


class TLSAnalyzer:
    def __init__(self, timeout: float = 5.0) -> None:
        self.timeout = timeout

    def analyze(self, hostname: str, port: int = 443) -> TLSResult:
        try:
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as tls_sock:
                    cert = tls_sock.getpeercert()
                    if not cert:
                        return TLSResult(hostname=hostname, valid=False, state="no_certificate", errors=["No certificate was presented."])
                    subject = dict(x[0] for x in cert.get("subject", []))
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    san = cert.get("subjectAltName", [])
                    sans = [value for key, value in san if key in {"DNS", "IP Address"}]
                    expiry = cert.get("notAfter")
                    expired = False
                    if expiry:
                        try:
                            expires = datetime.strptime(expiry, "%b %d %H:%M:%S %Y %Z")
                            expired = expires < datetime.now()
                        except ValueError:
                            expired = False
                    valid = not expired and bool(cert)
                    return TLSResult(hostname=hostname, valid=valid, state="ok" if valid else "certificate_invalid", issuer=str(issuer) if issuer else None, subject=str(subject) if subject else None, sans=sans, errors=[] if valid else ["Certificate validation failed or the certificate has expired."], certificate_expired=expired)
        except ssl.SSLCertVerificationError as exc:
            return TLSResult(hostname=hostname, valid=False, state="verification_failed", errors=[f"Certificate verification failed: {exc}."])
        except (socket.gaierror, TimeoutError, OSError) as exc:
            return TLSResult(hostname=hostname, valid=False, state="connection_failed", errors=[f"TLS connection failed: {exc}."])
        except Exception as exc:  # pragma: no cover
            return TLSResult(hostname=hostname, valid=False, state="analysis_unavailable", errors=[f"TLS analysis failed unexpectedly: {exc}."])


class RedirectAnalyzer:
    def __init__(self, max_redirects: int = 5, timeout: float = 4.0) -> None:
        self.max_redirects = max_redirects
        self.timeout = timeout

    @staticmethod
    def _is_safe_ip(value: str) -> bool:
        try:
            addr = ip_address(value)
        except ValueError:
            return True
        return not (is_loopback(addr) or is_private(addr) or is_link_local(addr) or is_multicast(addr) or is_reserved(addr))

    @staticmethod
    def _resolve_hostname(hostname: str) -> list[str]:
        if not hostname:
            return []
        try:
            infos = socket.getaddrinfo(hostname, 0, 0, socket.SOCK_STREAM)
        except OSError:
            return []
        result: list[str] = []
        for _, _, _, _, sockaddr in infos:
            ip = sockaddr[0] if isinstance(sockaddr, tuple) else str(sockaddr)
            if ip and ip not in result:
                result.append(ip)
        return result

    def _resolve_redirect_target(self, base_url: str, target: str) -> str:
        candidate = target.strip()
        if not candidate:
            raise ValueError("Redirect target is empty.")
        parsed_target = urlparse(candidate)
        if parsed_target.scheme and parsed_target.scheme.lower() not in {"http", "https"}:
            raise ValueError(f"Redirect scheme {parsed_target.scheme!r} is not allowed.")
        if not parsed_target.scheme and not parsed_target.netloc:
            candidate = urljoin(base_url, candidate)
        parsed = urlparse(candidate)
        if not parsed.scheme or not parsed.hostname:
            raise ValueError("Redirect target is not a valid HTTP(S) URL.")
        if parsed.scheme.lower() not in {"http", "https"}:
            raise ValueError(f"Redirect scheme {parsed.scheme!r} is not allowed.")
        if not self._is_safe_ip(parsed.hostname):
            raise ValueError("Redirect target is a private or local destination and is rejected.")
        addresses = self._resolve_hostname(parsed.hostname)
        if not addresses:
            raise ValueError("Redirect target DNS resolution failed.")
        if any(not self._is_safe_ip(ip) for ip in addresses):
            raise ValueError("Redirect target resolves to a private, local, or reserved destination.")
        return candidate

    def inspect(self, url: str) -> RedirectResult:
        if httpx is None:
            return RedirectResult(initial_url=url, redirects=[], loop_detected=False, cross_domain=False, state="unavailable", errors=["httpx is not installed."])
        redirects: list[str] = []
        seen: set[str] = set()
        current = url
        cross_domain = False
        final_state = "ok"
        errors: list[str] = []
        for _ in range(self.max_redirects):
            current_lower = current.lower()
            if current_lower in seen:
                final_state = "redirect_loop"
                break
            seen.add(current_lower)
            parsed = urlparse(current)
            if not parsed.scheme or not parsed.hostname:
                errors.append("Redirect target is not a valid HTTP(S) URL.")
                final_state = "invalid_redirect"
                break
            if parsed.scheme.lower() not in {"http", "https"}:
                errors.append(f"Redirect scheme {parsed.scheme!r} is not allowed.")
                final_state = "invalid_redirect"
                break
            if not self._is_safe_ip(parsed.hostname):
                errors.append("Redirect target is a private or local destination and is rejected.")
                final_state = "unsafe_redirect"
                break
            addresses = self._resolve_hostname(parsed.hostname)
            if not addresses:
                errors.append("DNS resolution failed before request execution.")
                final_state = "dns_resolution_failed"
                break
            if any(not self._is_safe_ip(ip) for ip in addresses):
                errors.append("Resolved redirect target is private, loopback, link-local, multicast, or reserved.")
                final_state = "unsafe_redirect"
                break
            try:
                response = httpx.get(current, follow_redirects=False, timeout=httpx.Timeout(connect=self.timeout, read=self.timeout, write=self.timeout, pool=self.timeout), headers={"User-Agent": "PhishLens/1.0"}, max_redirects=0)
            except httpx.HTTPError as exc:
                errors.append(f"Network or redirect inspection failed: {exc}")
                final_state = "network_error"
                break
            if response.is_redirect:
                target = response.headers.get("location")
                if not target:
                    errors.append("Redirect response did not include a target location.")
                    final_state = "invalid_redirect"
                    break
                try:
                    resolved = self._resolve_redirect_target(current, target)
                except ValueError as exc:
                    errors.append(str(exc))
                    final_state = "invalid_redirect"
                    break
                redirects.append(f"{current} -> {resolved}")
                candidate_p = urlparse(resolved)
                if candidate_p.netloc and candidate_p.netloc.lower() != parsed.netloc.lower():
                    cross_domain = True
                current = resolved
                continue
            if response.status_code < 300:
                break
            errors.append(f"Unexpected HTTP redirect response code: {response.status_code}")
            final_state = "invalid_redirect"
            break
        if not redirects and final_state == "ok":
            final_state = "no_redirects"
        if final_state == "redirect_loop":
            errors.append("A redirect loop was detected.")
        return RedirectResult(initial_url=url, redirects=redirects, loop_detected=final_state == "redirect_loop", cross_domain=cross_domain, state=final_state, errors=errors)


class ThreatIntelProvider:
    def __init__(self, name: str, api_key_env: str | None = None, enabled: bool = False) -> None:
        self.name = name
        self.api_key_env = api_key_env
        self.enabled = enabled

    def configured(self) -> bool:
        return self.enabled and bool(os.getenv(self.api_key_env or ""))

    def query(self, url: str) -> dict[str, Any]:
        return {"source": self.name, "status": "unavailable", "message": "This intelligence provider is not configured or is not yet implemented.", "url": url}


class IntelligenceRegistry:
    def __init__(self) -> None:
        self.providers = {"virustotal": ThreatIntelProvider("VirusTotal", "VT_API_KEY"), "safebrowsing": ThreatIntelProvider("Google Safe Browsing", "SAFEBROWSING_API_KEY"), "urlhaus": ThreatIntelProvider("URLhaus", "URLHAUS_API_KEY"), "openphish": ThreatIntelProvider("OpenPhish", "OPENPHISH_API_KEY")}

    def enabled(self) -> dict[str, ThreatIntelProvider]:
        return {name: provider for name, provider in self.providers.items() if provider.configured()}

    def query(self, url: str) -> dict[str, dict[str, Any]]:
        return {name: provider.query(url) for name, provider in self.enabled().items()}


def build_json_report(analysis: URLAnalysis, domain: DomainInfo | None = None, dns: DNSResult | None = None, tls: TLSResult | None = None, redirect: RedirectResult | None = None) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "timestamp": iso_now(),
        "project": "PhishLens",
        "analysis": {"url": analysis.url, "normalized_url": analysis.normalized_url, "scheme": analysis.scheme, "hostname": analysis.hostname, "registrable_domain": analysis.registrable_domain, "score": analysis.score, "classification": analysis.classification, "is_suspicious": analysis.is_suspicious, "findings": [asdict(f) for f in analysis.findings]},
        "domain": asdict(domain) if domain else None,
        "dns": asdict(dns) if dns else None,
        "tls": asdict(tls) if tls else None,
        "redirect": asdict(redirect) if redirect else None,
    }


def render_html_report(report: dict[str, Any]) -> str:
    findings = report["analysis"]["findings"]
    findings_html = "".join(f"<tr><td>{escape(str(f['rule_id']))}</td><td>{escape(str(f['name']))}</td><td>{escape(str(f['severity']))}</td><td>{escape(str(f['evidence']))}</td><td>{escape(str(f['recommendation']))}</td><td>{escape(str(f['score']))}</td></tr>" for f in findings)
    if not findings_html:
        findings_html = "<tr><td colspan='6'>No evidence was collected.</td></tr>"
    domain_html = ""
    if report.get("domain"):
        domain = report["domain"]
        domain_html = f"<p><strong>Registrable domain:</strong> {escape(str(domain['registrable_domain']))}<br><strong>Subdomains:</strong> {escape(', '.join(domain.get('subdomains', []))) or 'None'}<br><strong>TLD:</strong> {escape(str(domain.get('tld', '')))}</p>"
    dns_html = ""
    if report.get("dns"):
        dns = report["dns"]
        dns_html = f"<p><strong>State:</strong> {escape(str(dns.get('state', '')))}</p>"
        if dns.get("records"):
            dns_html += "<ul>" + "".join(f"<li>{escape(str(k))}: {escape(', '.join(v))}</li>" for k, v in dns["records"].items()) + "</ul>"
    tls_html = ""
    if report.get("tls"):
        tls = report["tls"]
        tls_html = f"<p><strong>State:</strong> {escape(str(tls.get('state', '')))}<br><strong>Valid:</strong> {escape(str(tls.get('valid', '')))}</p>"
    redirect_html = ""
    if report.get("redirect"):
        redirect = report["redirect"]
        redirect_html = f"<p><strong>State:</strong> {escape(str(redirect.get('state', '')))}<br><strong>Loop detected:</strong> {escape(str(redirect.get('loop_detected', '')))}</p>"
        if redirect.get("redirects"):
            redirect_html += "<ul>" + "".join(f"<li>{escape(str(item))}</li>" for item in redirect["redirects"]) + "</ul>"
    return f"""<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'><title>PhishLens Security Report</title><style>body {{ font-family: Arial, sans-serif; margin: 2rem; color: #111; }} table {{ border-collapse: collapse; width: 100%; margin-top:1rem; }} th, td {{ border: 1px solid #d0d0d0; padding: 0.5rem; text-align:left; vertical-align: top; }} th {{ background: #f4f4f4; }} .score {{ font-size: 2rem; font-weight: bold; }}</style></head><body><h1>PhishLens Security Report</h1><p><strong>URL:</strong> {escape(str(report['analysis']['url']))}</p><p><strong>Risk score:</strong> <span class='score'>{escape(str(report['analysis']['score']))}</span> / 100</p><p><strong>Classification:</strong> {escape(str(report['analysis']['classification']))}</p>{domain_html}{dns_html}{tls_html}{redirect_html}<h2>Evidence</h2><table><thead><tr><th>Rule</th><th>Name</th><th>Severity</th><th>Evidence</th><th>Recommendation</th><th>Score</th></tr></thead><tbody>{findings_html}</tbody></table><p><em>Disclaimer: this report is an explainable heuristic assessment and should not be treated as a definitive trust verdict.</em></p></body></html>"""


def render_console_report(analysis: URLAnalysis, domain: DomainInfo | None = None, dns: DNSResult | None = None, tls: TLSResult | None = None, redirect: RedirectResult | None = None) -> str:
    lines = ["PhishLens analysis", f"URL: {analysis.url}", f"Risk score: {analysis.score}/100", f"Classification: {analysis.classification}", "", "Findings:"]
    if not analysis.findings:
        lines.append("  No findings; risk signal is limited.")
    else:
        for finding in analysis.findings:
            lines.append(f"  - [{finding.rule_id}] {finding.name} ({finding.severity}) : {finding.evidence}")
            lines.append(f"      Recommendation: {finding.recommendation}")
    if domain:
        lines.extend(["", "Domain:", f"  Registrable domain: {domain.registrable_domain}", f"  Subdomains: {', '.join(domain.subdomains) if domain.subdomains else 'None'}", f"  TLD: {domain.tld}"])
    if dns:
        lines.extend(["", "DNS:", f"  State: {dns.state}"])
        for key, values in dns.records.items():
            lines.append(f"  {key}: {', '.join(values)}")
    if tls:
        lines.extend(["", "TLS:", f"  State: {tls.state}", f"  Valid: {tls.valid}"])
        if tls.subject:
            lines.append(f"  Subject: {tls.subject}")
        if tls.issuer:
            lines.append(f"  Issuer: {tls.issuer}")
    if redirect:
        lines.extend(["", "Redirects:", f"  State: {redirect.state}"])
        for item in redirect.redirects:
            lines.append(f"  - {item}")
    return "\n".join(lines)


if typer is not None:
    app = typer.Typer(add_completion=False, no_args_is_help=True, help="PhishLens: explainable phishing detection and URL threat analysis.")
    console = Console()

    @app.command("version")
    def version() -> None:
        console.print("PhishLens 1.0.0")

    @app.command("analyze")
    def analyze_command(url: str = typer.Argument(..., help="URL to inspect."), format: str = typer.Option("text", "--format", "-f", help="Output format: text, json, html."), output: str | None = typer.Option(None, "--output", "-o", help="Write the report to a file."), html: str | None = typer.Option(None, "--html", help="Write HTML output to a file."), dns: bool = typer.Option(False, "--dns", help="Collect DNS records when the resolver is available."), tls: bool = typer.Option(False, "--tls", help="Inspect the TLS certificate for the HTTPS destination."), redirects: bool = typer.Option(False, "--redirects", help="Inspect the redirect chain with safe limits.")) -> None:
        analyzer = URLAnalyzer()
        analysis = analyzer.analyze(url)
        domain = analyze_domain(analysis.hostname)
        dns_result: DNSResult | None = None
        tls_result: TLSResult | None = None
        redirect_result: RedirectResult | None = None
        if dns:
            dns_result = DNSAnalyzer().analyze(analysis.hostname)
        if tls and analysis.scheme == "https":
            tls_result = TLSAnalyzer().analyze(analysis.hostname)
        elif tls and analysis.scheme != "https":
            tls_result = TLSResult(analysis.hostname, valid=False, state="skipped", errors=["TLS analysis is only available for HTTPS URLs."])
        if redirects:
            redirect_result = RedirectAnalyzer().inspect(url)
        report = build_json_report(analysis, domain, dns_result, tls_result, redirect_result)
        if format == "json":
            rendered = json.dumps(report, indent=2, sort_keys=True)
        elif format == "html":
            rendered = render_html_report(report)
        else:
            rendered = render_console_report(analysis, domain, dns_result, tls_result, redirect_result)
        if html:
            with open(html, "w", encoding="utf-8") as handle:
                handle.write(render_html_report(report))
        if output:
            with open(output, "w", encoding="utf-8") as handle:
                handle.write(rendered)
        console.print(rendered)

    rules_app = typer.Typer(help="Inspect the built-in detection rules.")

    @rules_app.command("list")
    def list_rules() -> None:
        table = Table(title="PhishLens Detection Rules")
        table.add_column("Rule ID")
        table.add_column("Name")
        table.add_column("Severity")
        table.add_column("Score")
        for rule in DEFAULT_RULES:
            table.add_row(rule.rule_id, rule.name, rule.severity, str(rule.score))
        console.print(table)

    @rules_app.command("show")
    def show_rule(rule_id: str) -> None:
        rule = next((item for item in DEFAULT_RULES if item.rule_id == rule_id.upper()), None)
        if rule is None:
            raise typer.BadParameter(f"Rule {rule_id} was not found.")
        table = Table(title=f"Rule: {rule.rule_id}")
        table.add_column("Property")
        table.add_column("Value")
        table.add_row("Name", rule.name)
        table.add_row("Description", rule.description)
        table.add_row("Severity", rule.severity)
        table.add_row("Score", str(rule.score))
        table.add_row("Evidence", rule.evidence)
        table.add_row("Recommendation", rule.recommendation)
        table.add_row("Confidence", rule.confidence)
        console.print(table)

    app.add_typer(rules_app, name="rules")

    def main() -> None:
        app()

    if __name__ == "__main__":
        main()
else:
    def _fallback_cli() -> None:
        raise RuntimeError("The Typer CLI dependencies are not installed. Install the project dependencies to use the PhishLens CLI.")

    if __name__ == "__main__":
        _fallback_cli()


def _assert(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def run_self_tests() -> list[str]:
    results: list[str] = []
    _assert(normalize_url("  https://EXAMPLE.com/path?b=1  ") == "https://example.com/path?b=1", "normalize_url failed")
    _assert(normalize_url("http://127.0.0.1") == "http://127.0.0.1/", "IPv4 normalization failed")
    _assert(normalize_url("https://[2001:db8::1]:443/abc") == "https://[2001:db8::1]/abc", "IPv6 normalization failed")
    _assert(extract_registrable_domain("sub.example.co.uk") == "example.co.uk", "co.uk PSL extraction failed")
    _assert(extract_registrable_domain("api.example.com") == "example.com", "simple registrable domain extraction failed")
    _assert(has_unicode_confusable("paypaⅼ.com"), "Unicode confusable detection failed")
    _assert(detect_mixed_script("exämple.com"), "Mixed-script detection failed")
    _assert(not RedirectAnalyzer()._is_safe_ip("127.0.0.1"), "Private IPv4 blocked failed")
    _assert(not RedirectAnalyzer()._is_safe_ip("::1"), "Loopback IPv6 blocked failed")
    _assert(not RedirectAnalyzer()._is_safe_ip("169.254.1.1"), "Link-local IPv4 blocked failed")
    _assert(RedirectAnalyzer()._resolve_redirect_target("https://example.com/a/b", "/x").endswith("/x"), "Relative redirect resolution failed")
    _assert(RedirectAnalyzer()._resolve_redirect_target("https://example.com/a/b", "https://evil.test/x") == "https://evil.test/x", "Absolute redirect resolution failed")

    class FakeResponse:
        def __init__(self, status_code=200, headers=None, is_redirect=False):
            self.status_code = status_code
            self.headers = headers or {}
            self.is_redirect = is_redirect

    class FakeHTTPX:
        class HTTPError(RuntimeError):
            pass

        @staticmethod
        def get(url, *args, **kwargs):
            if url.endswith("/loop1"):
                return FakeResponse(302, {"location": "/loop2"}, True)
            if url.endswith("/loop2"):
                return FakeResponse(302, {"location": "/loop1"}, True)
            return FakeResponse(200)

    original_httpx = httpx
    try:
        globals()["httpx"] = FakeHTTPX
        result = RedirectAnalyzer(max_redirects=3).inspect("https://example.com/loop1")
        _assert(result.loop_detected, "Redirect loop detection failed")
    finally:
        globals()["httpx"] = original_httpx

    engine = ScoringEngine(DEFAULT_RULES)
    score_tuple = engine.evaluate([{"rule_id": "R007", "score": 10}, {"rule_id": "R007", "score": 10}])
    _assert(score_tuple[0] <= 20, "Duplicate rule findings were not deduplicated")

    low_analysis = URLAnalyzer().analyze("https://login.example.com")
    _assert(low_analysis.classification == "LOW", "Keyword-only heuristic should remain LOW")
    _assert(not low_analysis.is_suspicious, "Keyword-only heuristic should not be marked suspicious")

    report = build_json_report(URLAnalyzer().analyze("https://example.com"), analyze_domain("example.com"))
    _assert(report["analysis"]["url"].startswith("https://"), "JSON report missing URL")
    _assert("PhishLens Security Report" in render_html_report(report), "HTML report missing expected title")

    original_getaddrinfo = socket.getaddrinfo
    class FakeResolver:
        @staticmethod
        def getaddrinfo(hostname, *args, **kwargs):
            if hostname == "evil.test":
                return [(None, None, None, None, ("10.0.0.5", 0))]
            return original_getaddrinfo(hostname, *args, **kwargs)

    try:
        socket.getaddrinfo = FakeResolver.getaddrinfo
        rejected = RedirectAnalyzer()._resolve_redirect_target("https://example.com/start", "https://evil.test/x")
        _assert(False, "Private redirect target should have been rejected")
    except ValueError:
        pass
    finally:
        socket.getaddrinfo = original_getaddrinfo

    results.append("self-tests: ok")
    return results


if __name__ == "__main__":
    if len(os.sys.argv) > 1 and os.sys.argv[1] == "--self-test":
        for item in run_self_tests():
            print(item)
    elif typer is not None:
        main()
    elif typer is None:
        print("PhishLens: Typer is not installed. This file requires the CLI dependencies.")
