"""
MaKeVaslim Panel - Protocol Tests
"""
import pytest
from backend.protocols import (
    ProtocolConfig,
    generate_vless,
    generate_vmess,
    generate_trojan,
    generate_shadowsocks,
    generate_hysteria2,
    generate_tuic,
    generate_all_links,
    build_links,
)


@pytest.fixture
def sample_config():
    return ProtocolConfig(
        uuid="12345678-1234-1234-1234-123456789abc",
        host="example.com",
        port=443,
        remark="Test Config",
        transport="ws",
        fingerprint="chrome",
        alpn="h2,http/1.1",
        sni="example.com",
        path="/Ma_Ke_Vaslim",
        host_header="example.com",
        security="tls",
    )


def test_generate_vless(sample_config):
    link = generate_vless(sample_config)
    assert link.startswith("vless://")
    assert "12345678-1234-1234-1234-123456789abc" in link
    assert "example.com" in link
    assert "type=ws" in link
    assert "security=tls" in link


def test_generate_vmess(sample_config):
    link = generate_vmess(sample_config)
    assert link.startswith("vmess://")
    # VMess links are base64 encoded


def test_generate_trojan(sample_config):
    link = generate_trojan(sample_config)
    assert link.startswith("trojan://")
    assert "12345678-1234-1234-1234-123456789abc" in link


def test_generate_shadowsocks(sample_config):
    link = generate_shadowsocks(sample_config)
    assert link.startswith("ss://")


def test_generate_hysteria2(sample_config):
    link = generate_hysteria2(sample_config)
    assert link.startswith("hysteria2://")


def test_generate_tuic(sample_config):
    link = generate_tuic(sample_config)
    assert link.startswith("tuic://")


def test_generate_all_links(sample_config):
    links = generate_all_links(
        uuid=sample_config.uuid,
        host=sample_config.host,
        ports=[443, 8443],
        remark="Test",
        transport="ws",
        fingerprint="chrome",
        alpn="h2,http/1.1",
        sni="example.com",
        path="/Ma_Ke_Vaslim",
        host_header="example.com",
        security="tls",
    )
    
    assert "vless" in links
    assert "vmess" in links
    assert "trojan" in links
    # shadowsocks only on non-TLS ports
    # assert "shadowsocks" in links  # 443, 8443 are TLS ports
    assert "hysteria2" in links
    assert "tuic" in links
    
    # Should have 2 links per protocol (one per port)
    assert len(links["vless"]) == 2
    assert len(links["vmess"]) == 2


def test_build_links():
    from backend.database import User
    from backend.protocols import ProtocolConfig, generate_vless
    
    # Create a mock user
    class MockUser:
        def __init__(self):
            self.uuid = "12345678-1234-1234-1234-123456789abc"
            self.label = "Test User"
            self.port = "443,8443"
            self.fingerprint = "chrome"
            self.alpn = ""
            self.transport = "ws"
            self.protocol = "vless"
    
    u = MockUser()
    links = build_links(u, "example.com", [443, 8443])
    
    assert "vless" in links
    assert len(links["vless"]) == 2
    for link in links["vless"]:
        assert link.startswith("vless://")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])