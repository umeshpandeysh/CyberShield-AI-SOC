import pytest
from unittest.mock import MagicMock, patch
from app.adapters.scanners import scan_bytes_clamav, YaraScanner

@patch("socket.socket")
def test_scan_bytes_clamav_clean(mock_socket_class):
    mock_socket = MagicMock()
    mock_socket_class.return_value = mock_socket
    
    # Mock clamd clean response
    mock_socket.recv.return_value = b"stream: OK\n"
    
    found, label = scan_bytes_clamav(b"clean file bytes", "localhost", 3310)
    
    assert found is False
    assert label == ""
    
@patch("socket.socket")
def test_scan_bytes_clamav_infected(mock_socket_class):
    mock_socket = MagicMock()
    mock_socket_class.return_value = mock_socket
    
    # Mock clamd virus found response
    mock_socket.recv.return_value = b"stream: Win.Trojan.Generic FOUND\n"
    
    found, label = scan_bytes_clamav(b"infected file bytes", "localhost", 3310)
    
    assert found is True
    assert label == "Win.Trojan.Generic"

def test_yara_scanner_compilation():
    scanner = YaraScanner(rules_dir="yara-rules")
    # Verify rules are loaded and compiled successfully
    assert scanner.rules_dir == "yara-rules"
    
    # Scan standard clean vs flag keywords
    matches = scanner.scan_text("Hello, this is a normal business email.")
    assert len(matches) == 0
    
    matches_suspicious = scanner.scan_text("Please verify your account immediately.")
    assert len(matches_suspicious) > 0
    assert matches_suspicious[0]["rule_name"] == "Phishing_Suspicious_Keywords"
