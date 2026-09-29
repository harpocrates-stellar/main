"""Stellar-facing encodings: hex, strkey, network identifiers, Soroban ScVal bytes, wallet network guard."""
import base64
import hashlib
import struct

from .common import Area, syn

NETWORKS = {
    "Public Global Stellar Network ; September 2015": "Mainnet",
    "Test SDF Network ; September 2015": "Testnet",
    "Test SDF Future Network ; October 2022": "Futurenet",
    "Local Sandbox Stellar Network ; September 2022": "Sandbox",
    "Standalone Network ; February 2017": "Standalone",
}
TESTNET = "Test SDF Network ; September 2015"
MAINNET = "Public Global Stellar Network ; September 2015"


def crc16_xmodem(data: bytes) -> int:
    crc = 0
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def strkey_encode(version_byte: int, payload: bytes) -> str:
    body = bytes([version_byte]) + payload
    body += struct.pack("<H", crc16_xmodem(body))
    return base64.b32encode(body).decode().rstrip("=")


def contract_id(label: str) -> str:
    return strkey_encode(2 << 3, hashlib.sha256(b"hpx-conformance/v1/strkey/" + label.encode()).digest())


def account_id(label: str) -> str:
    return strkey_encode(6 << 3, hashlib.sha256(b"hpx-conformance/v1/strkey/" + label.encode()).digest())


def scval_bytes(data: bytes) -> str:
    # XDR: SCV_BYTES discriminant (13), u32 length, data, zero padding to a 4-byte boundary.
    pad = (-len(data)) % 4
    return (struct.pack(">II", 13, len(data)) + data + b"\x00" * pad).hex()


def build_encodings() -> Area:
    a = Area("stellar-encoding", "Hex, strkey, network id, and Soroban ScVal byte encodings")

    h = syn("enc/h")
    # -- hex32 --
    a.add("se-hex32-pos-001-lower", "hex32_normalize", {"value": h}, ok={"hex": h}, desc="Lowercase passes unchanged.")
    a.add("se-hex32-pos-002-upper-lowered", "hex32_normalize", {"value": h.upper()}, ok={"hex": h}, desc="Uppercase is normalized to lowercase.")
    a.add("se-hex32-pos-003-mixed", "hex32_normalize", {"value": h[:32].upper() + h[32:]}, ok={"hex": h}, desc="Mixed case is normalized.")
    for n, slug, v, d in (
        (1, "short", h[:-1], "63 chars."), (2, "long", h + "0", "65 chars."), (3, "empty", "", "Empty string."),
        (4, "non-hex", "g" + h[1:], "Non-hex character."), (5, "trailing-newline", h + "\n", "Trailing newline: Python `$` accepts it, JS does not."),
        (6, "leading-space", " " + h[:-1], "Leading whitespace."), (7, "0x-prefix", "0x" + h[2:], "0x prefix."),
        (8, "fullwidth-digits", "\uff10" * 64, "Fullwidth digits U+FF10 are not hex."),
        (9, "embedded-nul", h[:10] + "\x00" + h[11:], "Embedded NUL."),
    ):
        a.add(f"se-hex32-neg-{n:03d}-{slug}", "hex32_normalize", {"value": v}, code="invalid_hex32", desc=d)
    # -- hex bytes --
    a.add("se-hexb-pos-001-empty", "hex_bytes_normalize", {"value": ""}, ok={"hex": ""}, desc="Empty byte string is valid.")
    a.add("se-hexb-pos-002-upper", "hex_bytes_normalize", {"value": "00FFaB"}, ok={"hex": "00ffab"}, desc="Lowercased.")
    for n, slug, v, d in ((1, "odd", "abc", "Odd length."), (2, "non-hex", "zz", "Non-hex."),
                          (3, "trailing-newline", "ab\n", "Trailing newline."), (4, "space", "ab cd", "Embedded space.")):
        a.add(f"se-hexb-neg-{n:03d}-{slug}", "hex_bytes_normalize", {"value": v}, code="invalid_hex_bytes", desc=d)
    # -- bytes -> hex --
    a.add("se-b2h-pos-001-basic", "bytes_to_hex", {"bytes": [0, 1, 15, 16, 255]}, ok={"hex": "00010f10ff"}, desc="Zero-padded lowercase pairs.")
    a.add("se-b2h-pos-002-empty", "bytes_to_hex", {"bytes": []}, ok={"hex": ""}, desc="Empty.")
    a.add("se-b2h-adv-001-out-of-range", "bytes_to_hex", {"bytes": [256]}, code="invalid_byte",
          desc="Deployed `bytesToHex` prints 256 as '100' (3 chars) instead of rejecting, silently producing malformed hex.",
          tier="advisory", why="known_defect")
    a.add("se-b2h-adv-002-negative", "bytes_to_hex", {"bytes": [-1]}, code="invalid_byte",
          desc="Deployed `bytesToHex` prints -1 as '-1'.", tier="advisory", why="known_defect")

    # -- strkey --
    c, acct = contract_id("contract-a"), account_id("account-a")
    cp = hashlib.sha256(b"hpx-conformance/v1/strkey/contract-a").hexdigest()
    ap = hashlib.sha256(b"hpx-conformance/v1/strkey/account-a").hexdigest()
    a.add("se-strkey-pos-001-contract", "strkey_decode", {"strkey": c, "expect": "contract"}, ok={"type": "contract", "payload_hex": cp}, desc="A valid C... contract id.")
    a.add("se-strkey-pos-002-account", "strkey_decode", {"strkey": acct, "expect": "account"}, ok={"type": "account", "payload_hex": ap}, desc="A valid G... account id.")

    def bad(n, slug, v, exp, d):
        a.add(f"se-strkey-neg-{n:03d}-{slug}", "strkey_decode", {"strkey": v, "expect": exp}, code="strkey_invalid", desc=d)

    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    last = c[-1]
    swapped = c[:-1] + alphabet[(alphabet.index(last) + 1) % 32]
    bad(1, "bad-checksum", swapped, "contract", "Last character changed: CRC16 mismatch.")
    bad(2, "wrong-type-expected-account", c, "account", "A contract id where an account id is required.")
    bad(3, "wrong-type-expected-contract", acct, "contract", "An account id where a contract id is required.")
    bad(4, "lowercase", c.lower(), "contract", "Strkey is upper-case only; Python b32decode(casefold=True) would accept.")
    bad(5, "truncated", c[:-1], "contract", "55 characters.")
    bad(6, "extended", c + "A", "contract", "57 characters.")
    bad(7, "trailing-newline", c + "\n", "contract", "Trailing newline.")
    bad(8, "padding", c + "====", "contract", "Base32 padding characters are not part of strkey.")
    bad(9, "alphabet-1", c[:5] + "1" + c[6:], "contract", "'1' is not in the RFC 4648 base32 alphabet.")
    bad(10, "alphabet-0", c[:5] + "0" + c[6:], "contract", "'0' is not in the base32 alphabet.")
    bad(11, "embedded-space", c[:5] + " " + c[6:], "contract", "Embedded space.")
    bad(12, "empty", "", "contract", "Empty string.")
    bad(13, "mixed-case", c[:10] + c[10:].lower(), "contract", "Mixed case.")
    bad(14, "hex-instead", cp, "contract", "A 64-char hex digest is not a strkey.")

    # -- network id and names --
    import hashlib as _h

    def nid(p):
        return _h.sha256(p.encode()).hexdigest()

    assert nid(TESTNET) == "cee0302d59844d32bdca915c8203dd44b33fbb7edc19051ea37abedf28ecd472"
    assert nid(MAINNET) == "7ac33997544e3175d266bd022439b22cdb16508c01163f26e5cb2a3e1045a979"
    for n, p in enumerate(NETWORKS, 1):
        a.add(f"se-netid-pos-{n:03d}-{NETWORKS[p].lower()}", "network_id", {"passphrase": p}, ok={"network_id": nid(p)},
              desc=f"Network id of the {NETWORKS[p]} passphrase is SHA-256 of its UTF-8 bytes.")
    a.add("se-netid-pos-006-non-ascii", "network_id", {"passphrase": "Caf\u00e9 Net ; 2026"}, ok={"network_id": nid("Caf\u00e9 Net ; 2026")},
          desc="Hashed as UTF-8, not Latin-1 or UTF-16.")
    a.add("se-netid-pos-007-trailing-space-differs", "network_id", {"passphrase": TESTNET + " "}, ok={"network_id": nid(TESTNET + " ")},
          desc="No trimming: a trailing space is a different network.")
    for n, p in enumerate(NETWORKS, 1):
        a.add(f"se-netname-pos-{n:03d}", "network_name", {"passphrase": p}, ok={"name": NETWORKS[p]}, desc=f"Known passphrase -> {NETWORKS[p]}.")
    a.add("se-netname-pos-006-unknown-falls-back", "network_name", {"passphrase": "Private Net ; 2026"}, ok={"name": "Private Net ; 2026"},
          desc="Unknown passphrases are echoed unchanged.")
    a.add("se-netname-pos-007-case-sensitive", "network_name", {"passphrase": TESTNET.lower()}, ok={"name": TESTNET.lower()},
          desc="Passphrase lookup is exact and case-sensitive.")

    # -- Soroban ScVal bytes XDR --
    for n, nbytes in enumerate((32, 5, 0, 1, 4, 33), 1):
        data = hashlib.sha256(b"scval" + bytes([nbytes])).digest() * 2
        data = data[:nbytes]
        a.add(f"se-scval-pos-{n:03d}-len-{nbytes}", "scval_bytes_xdr", {"hex": data.hex()}, ok={"xdr_hex": scval_bytes(data)},
              desc=f"{nbytes}-byte value: discriminant 13, u32 length, data, zero padding to a 4-byte boundary.")
    a.add("se-scval-neg-001-odd-hex", "scval_bytes_xdr", {"hex": "abc"}, code="invalid_hex_bytes", desc="Odd-length hex.")
    a.add("se-scval-neg-002-non-hex", "scval_bytes_xdr", {"hex": "zz"}, code="invalid_hex_bytes", desc="Non-hex.")
    return a


def build_network_guard() -> Area:
    a = Area("network-guard", "Wallet/contract network mismatch guard (fail closed)")
    T, M = TESTNET, MAINNET

    def ok(n, slug, wallet, contract, desc):
        a.add(f"ng-pos-{n:03d}-{slug}", "network_check", {"wallet": wallet, "contract": contract}, ok={"match": True}, desc=desc)

    ok(1, "same", T, T, "Identical passphrases.")
    ok(2, "wallet-trimmed", "  " + T + "\n", T, "The wallet value is trimmed before comparison.")
    ok(3, "nbsp-trimmed", "\u00a0" + T + "\u00a0", T, "U+00A0 is ECMAScript whitespace and is trimmed.")
    ok(4, "bom-trimmed", T + "\ufeff", T,
       "U+FEFF (ZWNBSP) is ECMAScript whitespace and IS trimmed; Python str.strip() does not trim it.")
    ok(5, "ideographic-space-trimmed", "\u3000" + T + "\u2003", T, "Unicode Zs spaces are trimmed.")
    ok(6, "line-separators-trimmed", "\u2028" + T + "\u2029", T, "U+2028/U+2029 are line terminators and are trimmed.")

    def unavailable(n, slug, inp, desc):
        a.add(f"ng-neg-{n:03d}-{slug}", "network_check", inp, code="wallet_network_unavailable", desc=desc)

    unavailable(1, "null", {"wallet": None, "contract": T}, "null: wallet locked or unavailable.")
    unavailable(2, "absent", {"contract": T}, "Member absent (undefined).")
    unavailable(3, "empty", {"wallet": "", "contract": T}, "Empty string.")
    unavailable(4, "blank", {"wallet": " \t\n ", "contract": T}, "Whitespace only.")

    def mismatch(n, slug, wallet, contract, wl, cl, desc):
        a.add(f"ng-neg-{n:03d}-{slug}", "network_check", {"wallet": wallet, "contract": contract},
              code="network_mismatch", detail={"wallet_network": wl, "contract_network": cl}, desc=desc)

    mismatch(10, "mainnet-vs-testnet", M, T, "Mainnet", "Testnet", "Wallet on Mainnet, contract on Testnet.")
    mismatch(11, "testnet-vs-mainnet", T, M, "Testnet", "Mainnet", "Wallet on Testnet, contract on Mainnet.")
    mismatch(12, "futurenet-vs-testnet", "Test SDF Future Network ; October 2022", T, "Futurenet", "Testnet", "Futurenet vs Testnet.")
    mismatch(13, "unknown-wallet-network", "Private Net ; 2026", T, "Private Net ; 2026", "Testnet", "Unknown wallet network is reported by its raw passphrase.")
    mismatch(14, "case-differs", T.lower(), T, T.lower(), "Testnet", "Comparison is exact; case differences are a mismatch.")
    mismatch(15, "contract-side-not-trimmed", T, T + " ", "Testnet", T + " ", "Only the wallet value is trimmed; a padded contract passphrase never matches.")
    # The wallet value is trimmed with ECMAScript WhiteSpace + LineTerminator semantics (JS `trim()`).
    # Python's str.strip() differs: it also strips U+0085 and U+001C..U+001F but NOT U+FEFF.
    mismatch(16, "nel-is-not-js-whitespace", T + "\u0085", T, T + "\u0085", "Testnet",
             "U+0085 is not ECMAScript whitespace: it is not trimmed, so the value differs (Python strip() would trim it).")
    mismatch(17, "unit-separator-is-not-js-whitespace", T + "\x1f", T, T + "\x1f", "Testnet",
             "U+001F is not ECMAScript whitespace (Python str.strip() strips it).")
    return a
