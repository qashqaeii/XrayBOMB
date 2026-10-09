"""DNS nameserver provider detection (DNS management ≠ CDN edge)."""

from __future__ import annotations

from typing import Optional

_DNS_PROVIDER_SIGNATURES: dict[str, list[str]] = {
    "ArvanCloud": ["arvancloud", "arvan", "neda.net", "afranet"],
    "Cloudflare": ["cloudflare.com", "ns.cloudflare.com"],
    "Google Cloud DNS": ["googledomains.com", "google.com", "googledns.com"],
    "Route53": ["awsdns", "amazonaws.com"],
    "DigitalOcean": ["digitalocean.com"],
    "Hetzner": ["hetzner.com", "first-ns", "second-ns"],
    "Namecheap": ["registrar-servers.com", "namecheap.com"],
    "GoDaddy": ["domaincontrol.com", "godaddy.com"],
    "IranServer": ["iranserver.com"],
    "Parspack": ["parspack.net", "parspack.co"],
}


def detect_dns_provider(ns_records: list[str]) -> tuple[Optional[str], float, list[str]]:
    """
    Infer who hosts DNS for the zone from NS hostnames.
    High confidence only when NS names match known patterns.
    """
    if not ns_records:
        return None, 0.0, []

    joined = " ".join(r.lower().rstrip(".") for r in ns_records)
    best: Optional[str] = None
    best_score = 0.0
    evidence: list[str] = []

    for provider, keywords in _DNS_PROVIDER_SIGNATURES.items():
        hits = [kw for kw in keywords if kw in joined]
        if not hits:
            continue
        score = 0.55 + min(0.35, 0.12 * len(hits))
        if score > best_score:
            best_score = score
            best = provider
            evidence = [f"NS match: {', '.join(hits)}"] + [f"NS: {r}" for r in ns_records[:4]]

    if best:
        evidence.insert(0, "DNS provider manages nameservers only — not proof of CDN traffic path.")
    return best, round(best_score, 2), evidence
