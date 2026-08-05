import re
import hashlib
import ipaddress
from urllib.parse import urlparse
from typing import Dict, List, Set, Any, Optional
from pydantic import BaseModel

# --- Pydantic Schemas for Structured JSON Return ---
class ExtractedIOCs(BaseModel):
    urls: List[str]
    domains: List[str]
    ips: List[str]
    emails: List[str]
    md5_hashes: List[str]
    sha1_hashes: List[str]
    sha256_hashes: List[str]
    filenames: List[str]

# --- Regular Expressions for Validating and Extracting IOCs ---
# Matches typical HTTP/HTTPS URLs
URL_PATTERN = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+')

# Matches domain names (alphanumeric, hyphens, and TLD)
DOMAIN_PATTERN = re.compile(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b', re.IGNORECASE)

# Matches email addresses
EMAIL_PATTERN = re.compile(r'\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b', re.IGNORECASE)

# Matches hashes in text
MD5_PATTERN = re.compile(r'\b[a-f0-9]{32}\b', re.IGNORECASE)
SHA1_PATTERN = re.compile(r'\b[a-f0-9]{40}\b', re.IGNORECASE)
SHA256_PATTERN = re.compile(r'\b[a-f0-9]{64}\b', re.IGNORECASE)

# Matches IPv4 / IPv6 addresses
IP_PATTERN = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b|\b[a-f0-9:]+:[a-f0-9:]+\b', re.IGNORECASE)


class IOCExtractionService:
    @staticmethod
    def is_valid_ip(ip_str: str) -> bool:
        """Validates if a string is a correct IPv4 or IPv6 address."""
        try:
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            return False

    @staticmethod
    def is_valid_domain(domain_str: str) -> bool:
        """Validates if a string has a valid domain layout."""
        if not domain_str or len(domain_str) > 253:
            return False
        # Strip trailing dot if present
        if domain_str[-1] == ".":
            domain_str = domain_str[:-1]
        return bool(DOMAIN_PATTERN.match(domain_str))

    @classmethod
    def extract_iocs(cls, body_text: str, body_html: str, headers_text: str, attachments: List[Dict[str, Any]]) -> ExtractedIOCs:
        """Extracts, normalizes, validates, and deduplicates threat indicators (IOCs)."""
        combined_text = f"{body_text or ''} {body_html or ''} {headers_text or ''}"
        
        # --- 1. Extract URLs and Domains ---
        raw_urls = URL_PATTERN.findall(combined_text)
        urls: Set[str] = set()
        domains: Set[str] = set()
        
        for url in raw_urls:
            # Strip trailing punctuation commonly matched at end of sentences
            clean_url = url.strip(".,!?\"'()[]{}<>*")
            if clean_url:
                urls.add(clean_url)
                try:
                    parsed = urlparse(clean_url)
                    # Extract domain name
                    netloc = parsed.netloc or parsed.path.split("/")[0]
                    # Strip port if present (e.g. domain.com:8080)
                    domain = netloc.split(":")[0].lower()
                    if cls.is_valid_domain(domain):
                        domains.add(domain)
                except Exception:
                    pass

        # --- 2. Extract IPs (IPv4/IPv6) ---
        raw_ips = IP_PATTERN.findall(combined_text)
        ips: Set[str] = set()
        for ip in raw_ips:
            clean_ip = ip.strip(".,!?\"'()[]{}<>*")
            if cls.is_valid_ip(clean_ip):
                ips.add(clean_ip)

        # --- 3. Extract Email Addresses ---
        raw_emails = EMAIL_PATTERN.findall(combined_text)
        emails: Set[str] = set(email.lower() for email in raw_emails if email)

        # --- 4. Extract Hashes from Text ---
        md5_hashes = set(MD5_PATTERN.findall(combined_text))
        sha1_hashes = set(SHA1_PATTERN.findall(combined_text))
        sha256_hashes = set(SHA256_PATTERN.findall(combined_text))

        # --- 5. Extract Attachment Metadata & Hashes ---
        filenames: Set[str] = set()
        for att in attachments:
            name = att.get("filename")
            if name:
                filenames.add(name)
                
            # If attachment contains binary payload, compute MD5, SHA1 and SHA256 hashes
            payload = att.get("payload")
            if payload:
                md5_hashes.add(hashlib.md5(payload).hexdigest())
                sha1_hashes.add(hashlib.sha1(payload).hexdigest())
                sha256_hashes.add(hashlib.sha256(payload).hexdigest())
            
            # If hashes were passed as strings in metadata, merge them
            h_md5 = att.get("file_hash_md5")
            if h_md5:
                md5_hashes.add(h_md5)
            h_sha1 = att.get("file_hash_sha1")
            if h_sha1:
                sha1_hashes.add(h_sha1)
            h_sha256 = att.get("file_hash_sha256")
            if h_sha256:
                sha256_hashes.add(h_sha256)

        return ExtractedIOCs(
            urls=sorted(list(urls)),
            domains=sorted(list(domains)),
            ips=sorted(list(ips)),
            emails=sorted(list(emails)),
            md5_hashes=sorted(list(h.lower() for h in md5_hashes)),
            sha1_hashes=sorted(list(h.lower() for h in sha1_hashes)),
            sha256_hashes=sorted(list(h.lower() for h in sha256_hashes)),
            filenames=sorted(list(filenames))
        )
