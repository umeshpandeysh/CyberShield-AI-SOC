import os
import socket
import logging
from typing import List, Dict, Any, Tuple

logger = logging.getLogger("scanners")

# Try to import yara
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    logger.warning("YARA-python library not available. YARA scans will be skipped.")

# --- ClamAV Scanner Client ---
def scan_bytes_clamav(file_bytes: bytes, host: str, port: int) -> Tuple[bool, str]:
    """Scans file bytes via ClamAV clamd daemon over TCP socket INSTREAM protocol.
    Returns: (virus_found, virus_label)
    """
    if not file_bytes:
        return False, ""
        
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(12.0)
        s.connect((host, port))
        
        # Send INSTREAM command format
        s.sendall(b"zINSTREAM\0")
        
        # Stream chunk size (big-endian 4-bytes) followed by chunk data
        chunk_size = len(file_bytes)
        s.sendall(chunk_size.to_bytes(4, byteorder="big") + file_bytes)
        
        # End of stream chunk (0 length)
        s.sendall((0).to_bytes(4, byteorder="big"))
        
        response = s.recv(1024).decode("utf-8", errors="ignore")
        s.close()
        
        if "FOUND" in response:
            # Response is typically: "stream: Win.Trojan.Generic-99 FOUND\n"
            parts = response.split(":")
            virus_label = parts[1].replace("FOUND", "").strip() if len(parts) > 1 else "Malicious Binary"
            return True, virus_label
        return False, ""
    except Exception as e:
        logger.error(f"ClamAV scan failed: {str(e)}")
        # Degraded status or local sandbox mock fallback to avoid failing completely
        return False, f"Scan Failure: {str(e)}"

# --- YARA Scanning Engine ---
class YaraScanner:
    def __init__(self, rules_dir: str = "yara-rules"):
        self.rules_dir = rules_dir
        self.rules = None
        self.compile_rules()
        
    def compile_rules(self):
        """Finds and compiles all YARA files inside the rules directory."""
        if not YARA_AVAILABLE:
            return
            
        rule_filepaths = {}
        if os.path.exists(self.rules_dir):
            for file in os.listdir(self.rules_dir):
                if file.endswith(".yar") or file.endswith(".yara"):
                    path = os.path.join(self.rules_dir, file)
                    # Use filename as rule namespace key
                    rule_filepaths[file] = path
                    
        if rule_filepaths:
            try:
                self.rules = yara.compile(filepaths=rule_filepaths)
                logger.info(f"YARA successfully compiled {len(rule_filepaths)} rulesets.")
            except Exception as e:
                logger.error(f"YARA rules compilation failed: {str(e)}")
                self.rules = None
        else:
            logger.warning("No YARA rules found for compilation.")

    def scan_text(self, text: str) -> List[Dict[str, Any]]:
        """Matches a string payload against compiled YARA rules.
        Returns: list of match results: [{"rule_name": str, "tags": [str], "matches": [str]}]
        """
        if not YARA_AVAILABLE or not self.rules or not text:
            return []
            
        try:
            matches = self.rules.match(data=text)
            results = []
            for m in matches:
                matched_strings = []
                for match_str in m.strings:
                    offset = match_str[0]
                    name = match_str[1]
                    value = match_str[2]
                    # Decode matched string values
                    val_str = value.decode("utf-8", errors="ignore")
                    matched_strings.append(f"{name}: {val_str}")
                    
                results.append({
                    "rule_name": m.rule,
                    "tags": m.tags,
                    "matched_strings": list(set(matched_strings))
                })
            return results
        except Exception as e:
            logger.error(f"YARA scan failed: {str(e)}")
            return []
