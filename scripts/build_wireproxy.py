#!/usr/bin/env python3
"""Build pinned wireproxy with WARP reserved support and ordered tunneled DNS.

Usage: python scripts/build_wireproxy.py --platform linux-amd64
       python scripts/build_wireproxy.py --platform windows-amd64
       python scripts/build_wireproxy.py --platform all

The upstream wireproxy release cannot send the three Cloudflare WARP
"reserved" bytes, so the helper is built here from a pinned upstream source
archive that is downloaded over verified TLS and checked against a pinned
SHA-256 before anything is patched. wireproxy learns a Reserved key for its
[Peer] sections, and a patched copy of the pinned golang.zx2c4.com/wireguard
module injects those bytes for the configured endpoint and masks the mirrored
bytes in responses. A lookup-wide DNS policy bounds failover and cancellation;
its native Go tests run before cross-compilation. Failures never leave a partial
vendor binary behind.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import re
import shutil
import ssl
import subprocess
import sys
import tarfile
import tempfile
from urllib.error import URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[1]
PLATFORMS = ("linux-amd64", "windows-amd64")
ALL_TARGETS = "all"
TARGETS = {
    "linux-amd64": ("linux", "amd64", "wireproxy"),
    "windows-amd64": ("windows", "amd64", "wireproxy.exe"),
}
WIREPROXY_REPOSITORY = "windtf/wireproxy"
WIREGUARD_MODULE = "golang.zx2c4.com/wireguard"
WIREGUARD_REPLACE = "replace golang.zx2c4.com/wireguard => ./wireguard-go"
SUPPORTED_PATCH = "reserved-support+ordered-dns"
MAX_SOURCE_BYTES = 20 * 1024 * 1024
CHUNK_BYTES = 64 * 1024
SOCKET_TIMEOUT = 120.0
MODULE_TIMEOUT = 600
TIDY_TIMEOUT = 600
BUILD_TIMEOUT = 900
TEST_TIMEOUT = 300
STDERR_TAIL_CHARS = 1500


class BuildError(Exception):
    """Pinned sources could not be fetched, patched or built; do not trust output."""


def target_for(platform: str) -> tuple[str, str, str]:
    """Map a supported platform to its GOOS, GOARCH and binary name."""
    try:
        return TARGETS[platform]
    except KeyError as exc:
        raise BuildError(f"Unsupported platform: {platform}") from exc


def load_pins(root: Path = ROOT) -> dict:
    """Read only the checked-in build pins; the CLI never accepts remote URLs."""
    try:
        data = json.loads((root / "vendor" / "wireproxy-build.json").read_text("utf-8"))
    except (OSError, ValueError) as exc:
        raise BuildError(f"Cannot read wireproxy build pins: {exc}") from exc
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise BuildError("Unsupported wireproxy build pin schema")
    wireproxy, wireguard = data.get("wireproxy"), data.get("wireguard")
    if not isinstance(wireproxy, dict) or not isinstance(wireguard, dict):
        raise BuildError("Build pins must contain wireproxy and wireguard records")
    version = wireproxy.get("version")
    if not isinstance(version, str) or not version:
        raise BuildError("Wireproxy source pin is missing its version")
    url = wireproxy.get("url")
    expected_path = f"/{WIREPROXY_REPOSITORY}/archive/refs/tags/v{version}.tar.gz"
    if not isinstance(url, str):
        raise BuildError("Invalid wireproxy source pin URL")
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.netloc != "github.com"
        or parsed.path != expected_path
        or parsed.query
        or parsed.fragment
    ):
        raise BuildError(
            f"Wireproxy source pin must be https://github.com{expected_path}"
        )
    digest = wireproxy.get("sha256")
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise BuildError("Wireproxy source SHA-256 must be 64 lowercase hex digits")
    if wireguard.get("module") != WIREGUARD_MODULE:
        raise BuildError(f"Wireguard pin module must be {WIREGUARD_MODULE}")
    module_version = wireguard.get("version")
    if not isinstance(module_version, str) or not module_version.startswith("v0.0.0-"):
        raise BuildError("Wireguard pin version must be a pinned pseudo-version (v0.0.0-)")
    if data.get("patch") != SUPPORTED_PATCH:
        raise BuildError(f"Unsupported wireproxy patch pin: {data.get('patch')!r}")
    return data


def download_source(pins: dict) -> bytes:
    """Download the pinned archive over verified TLS and check its digest first."""
    wireproxy = pins["wireproxy"]
    digest = hashlib.sha256()
    chunks: list[bytes] = []
    total = 0
    request = Request(wireproxy["url"], headers={"User-Agent": "WarpPocket-build/0.1"})
    try:
        context = ssl.create_default_context()
        with urlopen(request, timeout=SOCKET_TIMEOUT, context=context) as response:
            if urlsplit(response.geturl()).scheme != "https":
                raise BuildError("Refusing a non-HTTPS wireproxy source response")
            while True:
                chunk = response.read(CHUNK_BYTES)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_SOURCE_BYTES:
                    raise BuildError("Wireproxy source exceeds the size limit")
                digest.update(chunk)
                chunks.append(chunk)
    except (URLError, OSError, ValueError) as exc:
        raise BuildError(f"Wireproxy source download failed: {exc}") from exc
    if total == 0:
        raise BuildError("Downloaded an empty wireproxy source archive")
    if not hmac.compare_digest(digest.hexdigest(), wireproxy["sha256"]):
        raise BuildError("Wireproxy source SHA-256 mismatch; refusing to build")
    return b"".join(chunks)


def extract_source(archive: bytes, version: str) -> Path:
    """Extract only regular files of the tag archive into a fresh temporary tree."""
    base = f"wireproxy-{version}"
    root = Path(tempfile.mkdtemp(prefix="warppocket-wireproxy-"))
    try:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as package:
            for member in package.getmembers():
                name = Path(member.name)
                if name.parts[:1] != (base,):
                    raise BuildError(f"Unexpected archive member: {member.name}")
                if len(name.parts) == 1:
                    continue  # The archive's top-level directory entry.
                if name.is_absolute() or ".." in name.parts:
                    raise BuildError(f"Unsafe archive member: {member.name}")
                target = root.joinpath(*name.parts[1:])
                if member.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                if not member.isfile() or member.issparse():
                    raise BuildError(f"Unsupported archive member: {member.name}")
                if member.size <= 0:
                    raise BuildError(f"Empty archive member: {member.name}")
                with package.extractfile(member) as stream:
                    if stream is None:
                        raise BuildError(f"Cannot read archive member: {member.name}")
                    payload = stream.read()
                if len(payload) != member.size:
                    raise BuildError(f"Truncated archive member: {member.name}")
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(payload)
    except (tarfile.TarError, OSError, EOFError) as exc:
        remove_tree(root)
        raise BuildError(f"Invalid wireproxy source archive: {exc}") from exc
    except BaseException:
        remove_tree(root)
        raise
    return root


def _read_text(path: Path) -> str:
    try:
        return path.read_text("utf-8")
    except OSError as exc:
        raise BuildError(f"Cannot read {path.name}: {exc}") from exc


def _write_text(path: Path, text: str) -> None:
    try:
        path.write_text(text, "utf-8")
    except OSError as exc:
        raise BuildError(f"Cannot write {path.name}: {exc}") from exc


def replace_once(text: str, old: str, new: str, label: str) -> str:
    """Apply one exact anchored replacement; the anchor must match exactly once."""
    count = text.count(old)
    if count != 1:
        raise BuildError(
            f"Patch anchor {label} matched {count} times, expected exactly one; "
            "upstream sources changed"
        )
    return text.replace(old, new)


# --- known upstream wireproxy 1.1.3 anchors (see vendor/wireproxy-build.json) ---

CONFIG_STRUCT_OLD = """type PeerConfig struct {
\tPublicKey    string
\tPreSharedKey string
\tEndpoint     *string
\tKeepAlive    int
\tAllowedIPs   []netip.Prefix
}
"""

CONFIG_STRUCT_NEW = """type PeerConfig struct {
\tPublicKey    string
\tPreSharedKey string
\tEndpoint     *string
\tKeepAlive    int
\tAllowedIPs   []netip.Prefix
\tReserved     *[3]uint8
}
"""

CONFIG_ENDPOINT_OLD = """\t\tif sectionKey, err := section.GetKey("Endpoint"); err == nil {
"""

CONFIG_RESERVED_NEW = """\t\tif sectionKey, err := section.GetKey("Reserved"); err == nil {
\t\t\tparts := strings.Split(sectionKey.String(), ",")
\t\t\tif len(parts) != 3 {
\t\t\t\treturn errors.New("Reserved should contain exactly three bytes")
\t\t\t}
\t\t\tvar reserved [3]uint8
\t\t\tfor index, part := range parts {
\t\t\t\tvalue, err := strconv.Atoi(strings.TrimSpace(part))
\t\t\t\tif err != nil || value < 0 || value > 255 {
\t\t\t\t\treturn errors.New("Reserved entries should be bytes")
\t\t\t\t}
\t\t\t\treserved[index] = uint8(value)
\t\t\t}
\t\t\tpeer.Reserved = &reserved
\t\t}

\t\tif sectionKey, err := section.GetKey("Endpoint"); err == nil {
"""

CONFIG_IMPORTS_OLD = """import (
\t"encoding/base64"
\t"encoding/hex"
\t"errors"
\t"net"
\t"os"
\t"path/filepath"
\t"strings"
"""

CONFIG_IMPORTS_NEW = """import (
\t"encoding/base64"
\t"encoding/hex"
\t"errors"
\t"net"
\t"os"
\t"path/filepath"
\t"strconv"
\t"strings"
"""

WIREGUARD_BIND_OLD = """\tdev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(logLevel, ""))
"""

WIREGUARD_BIND_NEW = """\tbind := conn.NewDefaultBind()
\tif len(deviceConf.Peers) == 1 && deviceConf.Peers[0].Reserved != nil && deviceConf.Peers[0].Endpoint != nil {
\t\tif address, parseErr := netip.ParseAddrPort(*deviceConf.Peers[0].Endpoint); parseErr == nil {
\t\t\tbind.SetReservedForEndpoint(address, *deviceConf.Peers[0].Reserved)
\t\t}
\t}
\tdev := device.NewDevice(tun, bind, device.NewLogger(logLevel, ""))
"""


def patch_wireproxy(src: Path) -> None:
    """Teach exact wireproxy 1.1.3 sources to parse and forward WARP reserved bytes."""
    config = _read_text(src / "config.go")
    config = replace_once(config, CONFIG_STRUCT_OLD, CONFIG_STRUCT_NEW,
                          "config.go PeerConfig.Reserved")
    config = replace_once(config, CONFIG_ENDPOINT_OLD, CONFIG_RESERVED_NEW,
                          "config.go Reserved parsing")
    config = replace_once(config, CONFIG_IMPORTS_OLD, CONFIG_IMPORTS_NEW,
                          "config.go strconv import")
    _write_text(src / "config.go", config)

    wireguard = _read_text(src / "wireguard.go")
    wireguard = replace_once(wireguard, WIREGUARD_BIND_OLD, WIREGUARD_BIND_NEW,
                             "wireguard.go bind")
    _write_text(src / "wireguard.go", wireguard)


# --- pinned netstack anchors; DNS parsing and tunnel dialers remain upstream ---

DNS_LOOKUP_PREFIX = '''func (tnet *Net) LookupContextHost(ctx context.Context, host string) ([]string, error) {
	if host == "" || (!tnet.hasV6 && !tnet.hasV4) {
		return nil, &net.DNSError{Err: errNoSuchHost.Error(), Name: host, IsNotFound: true}
	}
	zlen := len(host)
	if strings.IndexByte(host, ':') != -1 {
		if zidx := strings.LastIndexByte(host, '%'); zidx != -1 {
			zlen = zidx
		}
	}
	if ip, err := netip.ParseAddr(host[:zlen]); err == nil {
		return []string{ip.String()}, nil
	}

	if !isDomainName(host) {
		return nil, &net.DNSError{Err: errNoSuchHost.Error(), Name: host, IsNotFound: true}
	}
'''

DNS_LOOKUP_PREFIX_NEW = '''func (tnet *Net) lookupContextHostAtServer(ctx context.Context, host string, exchange warpDNSExchange) ([]string, error) {
'''

DNS_EXCHANGE_LOOP = '''	for _, useUDP := range []bool{true, false} {
		ctx, cancel := context.WithDeadline(ctx, time.Now().Add(timeout))
		defer cancel()

'''

DNS_EXCHANGE_LOOP_NEW = '''	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for _, useUDP := range []bool{true, false} {
		if ctx.Err() != nil {
			return dnsmessage.Parser{}, dnsmessage.Header{}, ctx.Err()
		}

'''

DNS_CONNECTION_DEADLINE = '''		if d, ok := ctx.Deadline(); ok && !d.IsZero() {
			err := c.SetDeadline(d)
			if err != nil {
				return dnsmessage.Parser{}, dnsmessage.Header{}, err
			}
		}
'''

DNS_CONNECTION_DEADLINE_NEW = '''		stop := context.AfterFunc(ctx, func() { c.Close() })
		if d, ok := ctx.Deadline(); ok && !d.IsZero() {
			err := c.SetDeadline(d)
			if err != nil {
				stop()
				c.Close()
				return dnsmessage.Parser{}, dnsmessage.Header{}, err
			}
		}
'''

DNS_TRY_EXCHANGE = '''		for _, server := range tnet.dnsServers {
			p, h, err := tnet.exchange(ctx, server, q, time.Second*5)
'''

DNS_TRY_EXCHANGE_NEW = '''		for _, server := range tnet.dnsServers {
			if ctx.Err() != nil {
				return dnsmessage.Parser{}, "", warpDNSContextError(ctx, name)
			}
			p, h, err := exchange(ctx, server, q, warpDNSStageTimeout)
			if ctx.Err() != nil {
				return dnsmessage.Parser{}, "", warpDNSContextError(ctx, name)
			}
'''

DNS_RESULT_ERROR = '''		if result.error != nil {
			if lastErr == nil {
				lastErr = result.error
			}
			continue
		}
'''

DNS_RESULT_ERROR_NEW = '''		if result.error != nil {
			var dnsErr *net.DNSError
			if errors.As(result.error, &dnsErr) && dnsErr.IsNotFound {
				negativeErr = result.error
			}
			if lastErr == nil {
				lastErr = result.error
			}
			continue
		}
'''


def patch_wireguard_dns(destination: Path) -> None:
    """Coordinate A/AAAA per resolver; bound and cancel the original DNS I/O."""
    path = destination / "tun" / "netstack" / "tun.go"
    text = _read_text(path)
    replacements = [
        (DNS_LOOKUP_PREFIX, DNS_LOOKUP_PREFIX_NEW, "lookup stage entry"),
        ('\t"strings"\n', "", "relocated host-validation import"),
        ("qtype dnsmessage.Type) (dnsmessage.Parser, string, error) {",
         "qtype dnsmessage.Type, exchange warpDNSExchange) (dnsmessage.Parser, string, error) {",
         "tryOneName exchange dependency"),
        (DNS_TRY_EXCHANGE, DNS_TRY_EXCHANGE_NEW, "per-stage retries"),
        ('tnet.tryOneName(ctx, host+".", dnsmessage.TypeA)',
         'tnet.tryOneName(ctx, host+".", dnsmessage.TypeA, exchange)', "A exchange"),
        ('tnet.tryOneName(ctx, host+".", dnsmessage.TypeAAAA)',
         'tnet.tryOneName(ctx, host+".", dnsmessage.TypeAAAA, exchange)', "AAAA exchange"),
        ("lane := make(chan result, lanes)\n\tvar lastErr error\n",
         "lane := make(chan result, lanes)\n\tvar lastErr error\n\tvar negativeErr error\n",
         "negative response state"),
        (DNS_RESULT_ERROR, DNS_RESULT_ERROR_NEW, "negative response precedence"),
        ("\tif len(addrs) == 0 && lastErr != nil {\n\t\treturn nil, lastErr\n\t}\n",
         "\tif len(addrs) == 0 {\n\t\tif negativeErr != nil {\n\t\t\treturn nil, negativeErr\n\t\t}\n"
         "\t\tif lastErr != nil {\n\t\t\treturn nil, lastErr\n\t\t}\n\t}\n",
         "negative response return"),
        (DNS_EXCHANGE_LOOP, DNS_EXCHANGE_LOOP_NEW, "shared UDP/TCP deadline"),
        (DNS_CONNECTION_DEADLINE, DNS_CONNECTION_DEADLINE_NEW, "cancel DNS connection"),
        ("\t\tc.Close()\n\t\tif err != nil {\n\t\t\tif err == context.Canceled {",
         "\t\tstop()\n\t\tc.Close()\n\t\tif err != nil {\n"
         "\t\t\tif ctx.Err() != nil {\n\t\t\t\terr = ctx.Err()\n\t\t\t}\n"
         "\t\t\tif err == context.Canceled {", "DNS I/O cleanup"),
    ]
    for old, new, label in replacements:
        text = replace_once(text, old, new, f"tun/netstack {label}")
    payload = _read_text(ROOT / "scripts" / "wireproxy_dns.go")
    tests = _read_text(ROOT / "tests" / "wireproxy_dns_test.go")
    _write_text(path, text)
    _write_text(path.with_name("warppocket_dns.go"), payload)
    _write_text(path.with_name("warppocket_dns_test.go"), tests)


# --- known golang.zx2c4.com/wireguard conn anchors (pinned pseudo-version) ---

CONN_INTERFACE_OLD = """\t// Send writes one or more packets in bufs to address ep. The length of
\t// bufs must not exceed BatchSize().
\tSend(bufs [][]byte, ep Endpoint) error
"""

CONN_INTERFACE_NEW = CONN_INTERFACE_OLD + """
\t// SetReservedForEndpoint stores the three reserved bytes that Cloudflare
\t// WARP requires after the WireGuard message type for this endpoint.
\tSetReservedForEndpoint(destination netip.AddrPort, reserved [3]byte)
"""

STD_STRUCT_OLD = """\tblackhole4 bool
\tblackhole6 bool
}
"""

STD_STRUCT_NEW = """\tblackhole4 bool
\tblackhole6 bool

\treservedAccess      sync.RWMutex
\treservedForEndpoint map[netip.AddrPort][3]uint8
}
"""

STD_CONSTRUCTOR_OLD = """\treturn &StdNetBind{
\t\tudpAddrPool: sync.Pool{"""

STD_CONSTRUCTOR_NEW = """\treturn &StdNetBind{
\t\treservedForEndpoint: make(map[netip.AddrPort][3]uint8),
\t\tudpAddrPool: sync.Pool{"""

STD_RECEIVE_OLD = """\t\tsizes[i] = msg.N
\t\tif sizes[i] == 0 {
\t\t\tcontinue
\t\t}
\t\taddrPort := msg.Addr.(*net.UDPAddr).AddrPort()
"""

STD_RECEIVE_NEW = """\t\tsizes[i] = msg.N
\t\tif sizes[i] == 0 {
\t\t\tcontinue
\t\t}
\t\t// Cloudflare WARP mirrors the 24-bit client id in the reserved header
\t\t// field of its responses. Clear it so the device reads the exact WireGuard
\t\t// message type. For ordinary peers the bytes are already zero.
\t\tif sizes[i] > 3 {
\t\t\tclear(bufs[i][1:4])
\t\t}
\t\taddrPort := msg.Addr.(*net.UDPAddr).AddrPort()
"""

STD_SEND_OLD = """\tua.Port = int(endpoint.(*StdNetEndpoint).Port())
\tvar (
\t\tretried bool
\t\terr     error
\t)
"""

STD_SEND_NEW = """\tua.Port = int(endpoint.(*StdNetEndpoint).Port())
\ts.reservedAccess.RLock()
\treserved, reservedFound := s.reservedForEndpoint[netip.AddrPortFrom(endpoint.DstIP(), uint16(endpoint.(*StdNetEndpoint).Port()))]
\ts.reservedAccess.RUnlock()
\tif reservedFound {
\t\tfor i := range bufs {
\t\t\tif len(bufs[i]) > 3 {
\t\t\t\tcopy(bufs[i][1:4], reserved[:])
\t\t\t}
\t\t}
\t}
\tvar (
\t\tretried bool
\t\terr     error
\t)
"""

STD_METHOD_NEW = """
// SetReservedForEndpoint stores the reserved bytes for one destination.
func (s *StdNetBind) SetReservedForEndpoint(destination netip.AddrPort, reserved [3]byte) {
\ts.reservedAccess.Lock()
\tif s.reservedForEndpoint == nil {
\t\ts.reservedForEndpoint = make(map[netip.AddrPort][3]uint8)
\t}
\ts.reservedForEndpoint[destination] = reserved
\ts.reservedAccess.Unlock()
}

func (s *StdNetBind) BatchSize() int {"""

STD_METHOD_OLD = """
func (s *StdNetBind) BatchSize() int {"""

WIN_STRUCT_OLD = """type WinRingBind struct {
\tv4, v6 afWinRingBind
\tmu     sync.RWMutex
\tisOpen atomic.Uint32 // 0, 1, or 2
}
"""

WIN_STRUCT_NEW = """type WinRingBind struct {
\tv4, v6 afWinRingBind
\tmu     sync.RWMutex
\tisOpen atomic.Uint32 // 0, 1, or 2

\treservedAccess      sync.RWMutex
\treservedForEndpoint map[WinRingEndpoint][3]uint8
}
"""

WIN_SEND_OLD = """\tbind.mu.RLock()
\tdefer bind.mu.RUnlock()
\tfor _, buf := range bufs {
\t\tswitch nend.family {
"""

WIN_SEND_NEW = """\tbind.mu.RLock()
\tdefer bind.mu.RUnlock()
\tbind.reservedAccess.RLock()
\treserved, reservedFound := bind.reservedForEndpoint[*nend]
\tbind.reservedAccess.RUnlock()
\tfor _, buf := range bufs {
\t\tif reservedFound && len(buf) > 3 {
\t\t\tcopy(buf[1:4], reserved[:])
\t\t}
\t\tswitch nend.family {
"""

WIN_RECEIVE_OLD = """\tn, ep, err := bind.%s.Receive(bufs[0], &bind.isOpen)
\tsizes[0] = n
\teps[0] = ep
\treturn 1, err
"""

WIN_RECEIVE_NEW = """\tn, ep, err := bind.%s.Receive(bufs[0], &bind.isOpen)
\tsizes[0] = n
\tif n > 3 {
\t\t// Cloudflare WARP mirrors the 24-bit client id in the reserved header
\t\t// field of its responses; clear it before the device reads the type.
\t\tclear(bufs[0][1:4])
\t}
\teps[0] = ep
\treturn 1, err
"""

WIN_METHOD_NEW = """
// SetReservedForEndpoint stores the reserved bytes for one destination.
func (bind *WinRingBind) SetReservedForEndpoint(destination netip.AddrPort, reserved [3]byte) {
\tendpoint, err := bind.ParseEndpoint(destination.String())
\tif err != nil {
\t\treturn
\t}
\twin, ok := endpoint.(*WinRingEndpoint)
\tif !ok {
\t\treturn
\t}
\tbind.reservedAccess.Lock()
\tif bind.reservedForEndpoint == nil {
\t\tbind.reservedForEndpoint = make(map[WinRingEndpoint][3]uint8)
\t}
\tbind.reservedForEndpoint[*win] = reserved
\tbind.reservedAccess.Unlock()
}

func (bind *WinRingBind) BatchSize() int {"""

WIN_METHOD_OLD = """
func (bind *WinRingBind) BatchSize() int {"""


def patch_wireguard_conn(destination: Path) -> None:
    """Add reserved-byte injection and response masking to the wireguard bind."""
    path = destination / "conn" / "conn.go"
    text = _read_text(path)
    text = replace_once(text, CONN_INTERFACE_OLD, CONN_INTERFACE_NEW,
                        "conn.go Bind interface")
    _write_text(path, text)

    path = destination / "conn" / "bind_std.go"
    text = _read_text(path)
    text = replace_once(text, STD_STRUCT_OLD, STD_STRUCT_NEW,
                        "bind_std.go StdNetBind fields")
    text = replace_once(text, STD_CONSTRUCTOR_OLD, STD_CONSTRUCTOR_NEW,
                        "bind_std.go NewStdNetBind")
    text = replace_once(text, STD_RECEIVE_OLD, STD_RECEIVE_NEW,
                        "bind_std.go Receive masking")
    text = replace_once(text, STD_SEND_OLD, STD_SEND_NEW,
                        "bind_std.go Send injection")
    text = replace_once(text, STD_METHOD_OLD, STD_METHOD_NEW,
                        "bind_std.go SetReservedForEndpoint")
    _write_text(path, text)

    path = destination / "conn" / "bind_windows.go"
    text = _read_text(path)
    text = replace_once(text, WIN_STRUCT_OLD, WIN_STRUCT_NEW,
                        "bind_windows.go WinRingBind fields")
    text = replace_once(text, WIN_SEND_OLD, WIN_SEND_NEW,
                        "bind_windows.go Send injection")
    for family in ("v4", "v6"):
        text = replace_once(
            text,
            WIN_RECEIVE_OLD % family,
            WIN_RECEIVE_NEW % family,
            f"bind_windows.go {family} Receive masking",
        )
    text = replace_once(text, WIN_METHOD_OLD, WIN_METHOD_NEW,
                        "bind_windows.go SetReservedForEndpoint")
    _write_text(path, text)


def make_tree_writable(path: Path) -> None:
    """Restore owner access to a tree copied from the read-only module cache."""
    if path.is_dir() and not path.is_symlink():
        for item in path.rglob("*"):
            if item.is_dir() and not item.is_symlink():
                item.chmod(0o700)
            else:
                item.chmod(0o600)
        path.chmod(0o700)
    else:
        path.chmod(0o600)


def remove_tree(path: Path) -> None:
    if not path.exists() and not path.is_symlink():
        return
    make_tree_writable(path)
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    else:
        path.unlink()


def run_go(command: list[str], cwd: Path, env: dict, timeout: float, label: str):
    """Run one Go command and turn every failure into a BuildError."""
    try:
        result = subprocess.run(
            command, cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout
        )
    except FileNotFoundError as exc:
        raise BuildError("The Go toolchain is not installed or not on PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise BuildError(f"{label} exceeded its time budget") from exc
    except OSError as exc:
        raise BuildError(f"{label} could not run: {exc}") from exc
    if result.returncode != 0:
        tail = (result.stderr or result.stdout or "").strip()[-STDERR_TAIL_CHARS:]
        raise BuildError(f"{label} failed with exit code {result.returncode}: {tail}")
    return result


def download_wireguard_module(src: Path, pins: dict) -> Path:
    """Fetch the pinned wireguard module and return its cache directory."""
    module, version = pins["wireguard"]["module"], pins["wireguard"]["version"]
    environment = {**os.environ, "GOFLAGS": "-mod=mod", "CGO_ENABLED": "0"}
    result = run_go(
        ["go", "mod", "download", "-json", f"{module}@{version}"],
        src, environment, MODULE_TIMEOUT, "go mod download",
    )
    try:
        payload = json.loads(result.stdout)
    except ValueError as exc:
        raise BuildError(f"Cannot parse go mod download output: {exc}") from exc
    directory = payload.get("Dir") if isinstance(payload, dict) else None
    if not isinstance(directory, str) or not Path(directory).is_dir():
        raise BuildError("go mod download did not report a module directory")
    return Path(directory)


def copy_wireguard_module(module: Path, destination: Path) -> None:
    """Copy the module out of the read-only cache and make the copy writable."""
    if destination.exists() or destination.is_symlink():
        remove_tree(destination)
    shutil.copytree(module, destination, symlinks=False)
    for item in destination.rglob("*"):
        if item.is_dir() and not item.is_symlink():
            item.chmod(0o700)
        else:
            item.chmod(0o600)


def patch_go_mod(src: Path) -> None:
    """Point the wireguard requirement at the patched local copy, idempotently."""
    path = src / "go.mod"
    text = _read_text(path)
    pattern = re.compile(r"(?m)^replace golang\.zx2c4\.com/wireguard => .*$")
    if pattern.search(text):
        updated = pattern.sub(WIREGUARD_REPLACE, text, count=1)
    else:
        updated = text.rstrip("\n") + "\n" + WIREGUARD_REPLACE + "\n"
    if updated != text:
        _write_text(path, updated)


def build_target(src: Path, platform: str, out_root: Path) -> Path:
    """Tidy and build one platform, staging beside the target then replacing it."""
    goos, goarch, filename = target_for(platform)
    directory = out_root / "vendor" / platform
    try:
        directory.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise BuildError(f"Cannot create {directory}: {exc}") from exc
    output = directory / filename
    environment = {
        **os.environ,
        "GOFLAGS": "-mod=mod",
        "CGO_ENABLED": "0",
        "GOOS": goos,
        "GOARCH": goarch,
    }
    run_go(["go", "mod", "tidy"], src, environment, TIDY_TIMEOUT, "go mod tidy")

    handle, temporary = tempfile.mkstemp(
        prefix=f".{filename}-", suffix=".tmp", dir=directory
    )
    os.close(handle)
    staged = Path(temporary)
    try:
        run_go(
            ["go", "build", "-trimpath", "-o", str(staged), "./cmd/wireproxy"],
            src, environment, BUILD_TIMEOUT, "go build",
        )
        if goos == "linux":
            staged.chmod(0o755)
        else:
            try:
                staged.chmod(0o644)
            except OSError:
                pass  # Windows only tracks the read-only attribute.
        os.replace(staged, output)
    finally:
        staged.unlink(missing_ok=True)
    return output


def test_dns_policy(src: Path) -> None:
    """Run the patched nested module's tests natively, even for a cross build."""
    environment = {**os.environ, "GOFLAGS": "-mod=mod", "CGO_ENABLED": "0"}
    result = run_go(["go", "env", "GOHOSTOS", "GOHOSTARCH"], src, environment, 30, "go env host")
    host = result.stdout.split()
    if len(host) != 2:
        raise BuildError("go env did not report the native host target")
    environment.update({"GOOS": host[0], "GOARCH": host[1]})
    result = run_go(
        ["go", "test", "./tun/netstack", "-run", "^TestWarpPocketDNS", "-count=1", "-v"],
        src / "wireguard-go", environment, TEST_TIMEOUT, "native DNS tests",
    )
    print(result.stdout, file=sys.stderr, end="")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--platform", choices=(*PLATFORMS, ALL_TARGETS), default=ALL_TARGETS)
    parser.add_argument("--out-root", default=str(ROOT),
                        help="Directory holding vendor/<platform>/wireproxy (default: repo root)")
    args = parser.parse_args(argv)
    out_root = Path(args.out_root)
    platforms = PLATFORMS if args.platform == ALL_TARGETS else (args.platform,)
    source = None
    built: list[Path] = []
    try:
        pins = load_pins(ROOT)
        if shutil.which("go") is None:
            raise BuildError("The Go toolchain is not installed or not on PATH")
        source = extract_source(download_source(pins), pins["wireproxy"]["version"])
        patch_wireproxy(source)
        module = download_wireguard_module(source, pins)
        copy_wireguard_module(module, source / "wireguard-go")
        patch_wireguard_conn(source / "wireguard-go")
        patch_wireguard_dns(source / "wireguard-go")
        patch_go_mod(source)
        test_dns_policy(source)
        for platform in platforms:
            built.append(build_target(source, platform, out_root))
    except (BuildError, OSError) as exc:
        print(f"Wireproxy build failed: {exc}", file=sys.stderr)
        return 1
    finally:
        if source is not None:
            try:
                remove_tree(source)
            except OSError:
                pass
    for platform, output in zip(platforms, built):
        digest = hashlib.sha256(output.read_bytes()).hexdigest()
        print(json.dumps({
            "platform": platform,
            "output": str(output),
            "sha256": digest,
            "bytes": output.stat().st_size,
        }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
