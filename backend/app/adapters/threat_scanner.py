import hashlib
import logging
from typing import List, Dict, Any, Tuple
from app.adapters.scanners import scan_bytes_clamav, YaraScanner
from app.infra.config import settings

logger = logging.getLogger("threat_scanner")

class AttachmentScanResult:
    def __init__(self, filename: str, md5: str, sha1: str, sha256: str, virus_found: bool, threat_label: str, status: str):
        self.filename = filename
        self.md5 = md5
        self.sha1 = sha1
        self.sha256 = sha256
        self.virus_found = virus_found
        self.threat_label = threat_label
        self.status = status  # "Scanned", "Failed", "Clean"

class YaraScanResult:
    def __init__(self, rule_name: str, tags: str, matched_strings: List[str]):
        self.rule_name = rule_name
        self.tags = tags
        self.matched_strings = matched_strings

class ThreatScanReport:
    def __init__(self, attachments: List[AttachmentScanResult], yara_matches: List[YaraScanResult], risk_score: float):
        self.attachments = attachments
        self.yara_matches = yara_matches
        self.risk_score = risk_score


class ThreatScannerService:
    def __init__(self, rules_dir: str = "yara-rules"):
        self.yara_scanner = YaraScanner(rules_dir)

    @staticmethod
    def calculate_hashes(content: bytes) -> Tuple[str, str, str]:
        """Calculates MD5, SHA1, and SHA256 hashes for binary payload."""
        md5 = hashlib.md5(content).hexdigest()
        sha1 = hashlib.sha1(content).hexdigest()
        sha256 = hashlib.sha256(content).hexdigest()
        return md5, sha1, sha256

    def scan_attachment(self, filename: str, content: bytes) -> AttachmentScanResult:
        """Helper to run ClamAV scanning on a single attachment payload.
        Handles failures gracefully, returning standard status flags.
        """
        logger.info(f"Computing hashes for attachment {filename}...")
        md5, sha1, sha256 = self.calculate_hashes(content)
        
        logger.info(f"Sending attachment {filename} to ClamAV scanner...")
        try:
            virus_found, threat_label = scan_bytes_clamav(
                content, 
                settings.CLAMAV_HOST, 
                settings.CLAMAV_PORT
            )
            status = "Scanned"
            if virus_found:
                logger.warning(f"Malware detected in {filename}: {threat_label}")
            else:
                logger.info(f"Attachment {filename} is clean.")
        except Exception as e:
            logger.error(f"Failed to scan attachment {filename}: {str(e)}")
            virus_found = False
            threat_label = f"Scan error: {str(e)}"
            status = "Failed"
            
        return AttachmentScanResult(
            filename=filename,
            md5=md5,
            sha1=sha1,
            sha256=sha256,
            virus_found=virus_found,
            threat_label=threat_label,
            status=status
        )

    def scan_email_content(self, subject: str, body_text: str, body_html: str, headers: str) -> List[YaraScanResult]:
        """Matches email content strings against compiled YARA signature rules."""
        combined_payload = f"{subject or ''} {body_text or ''} {body_html or ''} {headers or ''}"
        logger.info("Executing YARA signature scan on email text and headers...")
        
        try:
            matches = self.yara_scanner.scan_text(combined_payload)
            results = []
            for m in matches:
                tags_str = ",".join(m["tags"]) if m.get("tags") else ""
                results.append(YaraScanResult(
                    rule_name=m["rule_name"],
                    tags=tags_str,
                    matched_strings=m["matched_strings"]
                ))
            return results
        except Exception as e:
            logger.error(f"YARA email text scanning failed: {str(e)}")
            return []

    def execute_pipeline(
        self, 
        subject: str, 
        body_text: str, 
        body_html: str, 
        headers: str, 
        attachments: List[Dict[str, Any]]
    ) -> ThreatScanReport:
        """Executes ClamAV scans on all files and YARA signature matches on email text.
        Computes a consolidated risk score.
        """
        # 1. Run YARA Scan
        yara_results = self.scan_email_content(subject, body_text, body_html, headers)
        
        # 2. Run ClamAV Scan on each attachment
        attachment_results = []
        for att in attachments:
            filename = att.get("filename", "unnamed_attachment")
            payload = att.get("payload", b"")
            res = self.scan_attachment(filename, payload)
            attachment_results.append(res)
            
        # 3. Calculate Consolidated Risk Score
        risk_score = 0.0
        virus_detected = any(res.virus_found for res in attachment_results)
        yara_matched = len(yara_results) > 0
        
        if virus_detected:
            risk_score = 0.99
        elif yara_matched:
            risk_score = 0.75
        elif len(attachments) > 0:
            # Benign attachments baseline risk
            risk_score = 0.10
            
        return ThreatScanReport(
            attachments=attachment_results,
            yara_matches=yara_results,
            risk_score=risk_score
        )
