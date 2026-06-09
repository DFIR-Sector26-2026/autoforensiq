import pytest
from src.wrappers.volatility_wrapper import VolatilityWrapper

def test_parse_malfind():
    wrapper = VolatilityWrapper()
    
    mock_output = """
Volatility 3 Framework 2.4.0
PID    Process    Start VPN    End VPN    Tag    Protection    CommitCharge    PrivateMemory    FileOutput    Disasm
4    System    0x10000    0x11000    VadS    PAGE_EXECUTE_READWRITE    1    1    -    
0x10000  4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00   MZ..............
0x10010  b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00   ........@.......
    """
    
    items = wrapper._parse("windows.malfind", mock_output)
    
    assert len(items) == 1
    assert items[0]["severity"] == "critical"
    assert "RWX region and embedded PE/shellcode detected" in items[0]["value"]
    assert items[0]["evidence_type"] == "injected_code"

def test_parse_filescan():
    wrapper = VolatilityWrapper()
    
    mock_output = """
Volatility 3 Framework 2.4.0
0x000000001000    \\Device\\HarddiskVolume2\\Intel\\ivecuqmanpnirkt615\\tasksche.exe
0x000000002000    \\Device\\HarddiskVolume2\\Windows\\System32\\kernel32.dll
0x000000003000    \\Device\\HarddiskVolume2\\Users\\Public\\malware.exe
    """
    
    items = wrapper._parse("windows.filescan", mock_output)
    
    assert len(items) == 2
    assert "tasksche.exe" in items[0]["value"]
    assert "malware.exe" in items[1]["value"]

def test_extract_strings():
    wrapper = VolatilityWrapper()
    
    corpus = """
    http://www.suspicious-domain-123.com/payload
    random_hex_string_that_looks_like_btc_but_invalid: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
    real_onion: exp1234567890abcdef.onion
    HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Malware
    ignore_this_file.dll
    1234567890abcdef1234567890abcdef1234.exe
    """
    
    items = wrapper._extract_strings(corpus)
    
    types = [item["evidence_type"] for item in items]
    values = [item["value"] for item in items]
    
    assert "suspicious_domain" in types
    assert "www.suspicious-domain-123.com" in values
    assert "exp1234567890abcdef.onion" in values
    assert "registry_key" in types
    assert "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Malware" in values
    assert "suspicious_crypto" in types
    assert "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" in values
    assert "ignore_this_file.dll" not in values