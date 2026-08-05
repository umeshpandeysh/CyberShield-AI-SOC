import re
from urllib.parse import urlparse
from typing import Dict, List, Set, Any

# Compile regular expressions for IOC pattern matching
IP_REGEX = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
)
EMAIL_REGEX = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')
MD5_REGEX = re.compile(r'\b[a-fA-F0-9]{32}\b')
SHA1_REGEX = re.compile(r'\b[a-fA-F0-9]{40}\b')
SHA256_REGEX = re.compile(r'\b[a-fA-F0-9]{64}\b')
URL_REGEX = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+')

def extract_iocs_from_text(text: str) -> Dict[str, List[str]]:
    """Scans text content and extracts IPs, domains, emails, and file hashes."""
    if not text:
        return {
            "ips": [],
            "domains": [],
            "emails": [],
            "hashes_md5": [],
            "hashes_sha256": [],
            "urls": []
        }
        
    ips = set(IP_REGEX.findall(text))
    emails = set(EMAIL_REGEX.findall(text))
    md5s = set(MD5_REGEX.findall(text))
    sha256s = set(SHA256_REGEX.findall(text))
    
    # Extract URLs and resolve domains
    urls_found = URL_REGEX.findall(text)
    urls = set()
    domains = set()
    
    for url in urls_found:
        clean_url = url.strip(".,!?\"'()[]{}")
        urls.add(clean_url)
        try:
            parsed = urlparse(clean_url)
            # Handle case where URL might not start with http/https but starts with www.
            netloc = parsed.netloc or parsed.path.split("/")[0]
            if netloc:
                domains.add(netloc.lower())
        except Exception:
            pass
            
    return {
        "ips": sorted(list(ips)),
        "domains": sorted(list(domains)),
        "emails": sorted(list(emails)),
        "hashes_md5": sorted(list(md5s)),
        "hashes_sha256": sorted(list(sha256s)),
        "urls": sorted(list(urls))
    }
