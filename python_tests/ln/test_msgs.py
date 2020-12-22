from conftest import get_random_net_addr, get_random_bytes
from ldk_python.ln.msgs import NetAddress


def test_netaddress_ipv4():
    ipv4, port = get_random_net_addr("ipv4")
    netaddr = NetAddress.ipv4(ipv4, port)

    assert isinstance(netaddr, NetAddress)
    assert netaddr.addr == ipv4
    assert netaddr.port == port
    assert netaddr.version == None
    assert netaddr.checksum == None


def test_netaddress_ipv6():
    ipv6, port = get_random_net_addr("ipv6")
    netaddr = NetAddress.ipv6(ipv6, port)

    assert isinstance(netaddr, NetAddress)
    assert netaddr.addr == ipv6
    assert netaddr.port == port
    assert netaddr.version == None
    assert netaddr.checksum == None


def test_netaddress_onionv2():
    onionv2, port = get_random_net_addr("onionv2")
    netaddr = NetAddress.onionv2(onionv2, port)

    assert isinstance(netaddr, NetAddress)
    assert netaddr.addr == onionv2
    assert netaddr.port == port
    assert netaddr.version == None
    assert netaddr.checksum == None


def test_netaddress_onionv3():
    onionv3, port = get_random_net_addr("onionv3")
    version = 1
    checksum = int.from_bytes(get_random_bytes(2), "big")
    netaddr = NetAddress.onionv3(onionv3, checksum, version, port)

    assert isinstance(netaddr, NetAddress)
    assert netaddr.addr == onionv3
    assert netaddr.checksum == checksum
    assert netaddr.version == version
    assert netaddr.port == port
