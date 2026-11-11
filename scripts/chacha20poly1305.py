"""ChaCha20, Poly1305 and ChaCha20-Poly1305 (RFC 8439) in plain Python, for test-vector generation.

Not constant time; never use it for real secrets. Importing the module checks the
implementation against the RFC 8439 test vectors of sections 2.4.2, 2.5.2 and 2.8.2.
"""

import struct

MASK = 0xFFFFFFFF


def _quarter_round(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & MASK
    s[d] ^= s[a]
    s[d] = ((s[d] << 16) | (s[d] >> 16)) & MASK
    s[c] = (s[c] + s[d]) & MASK
    s[b] ^= s[c]
    s[b] = ((s[b] << 12) | (s[b] >> 20)) & MASK
    s[a] = (s[a] + s[b]) & MASK
    s[d] ^= s[a]
    s[d] = ((s[d] << 8) | (s[d] >> 24)) & MASK
    s[c] = (s[c] + s[d]) & MASK
    s[b] ^= s[c]
    s[b] = ((s[b] << 7) | (s[b] >> 25)) & MASK


def chacha20_block(key, counter, nonce):
    """One 64-byte keystream block; `nonce` is 12 bytes (RFC 8439 section 2.3)."""
    assert len(key) == 32 and len(nonce) == 12
    state = (
        [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
        + list(struct.unpack("<8I", key))
        + [counter & MASK]
        + list(struct.unpack("<3I", nonce))
    )
    s = list(state)
    for _ in range(10):
        _quarter_round(s, 0, 4, 8, 12)
        _quarter_round(s, 1, 5, 9, 13)
        _quarter_round(s, 2, 6, 10, 14)
        _quarter_round(s, 3, 7, 11, 15)
        _quarter_round(s, 0, 5, 10, 15)
        _quarter_round(s, 1, 6, 11, 12)
        _quarter_round(s, 2, 7, 8, 13)
        _quarter_round(s, 3, 4, 9, 14)
    return struct.pack("<16I", *((x + y) & MASK for x, y in zip(s, state)))


def chacha20(key, counter, nonce, data):
    """XOR `data` with the keystream starting at block `counter`."""
    out = bytearray()
    for i in range(0, len(data), 64):
        block = chacha20_block(key, counter + i // 64, nonce)
        out += bytes(a ^ b for a, b in zip(data[i : i + 64], block))
    return bytes(out)


def poly1305(key, message):
    """The 16-byte Poly1305 tag of `message` under a 32-byte one-time key."""
    assert len(key) == 32
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:], "little")
    p = (1 << 130) - 5
    acc = 0
    for i in range(0, len(message), 16):
        chunk = message[i : i + 16]
        acc = (acc + int.from_bytes(chunk + b"\x01", "little")) * r % p
    return ((acc + s) % (1 << 128)).to_bytes(16, "little")


def _pad16(data):
    return bytes(-len(data) % 16)


def aead_encrypt(key, nonce, plaintext, aad=b""):
    """ChaCha20-Poly1305 (RFC 8439 section 2.8): ciphertext followed by the 16-byte tag."""
    otk = chacha20_block(key, 0, nonce)[:32]
    ciphertext = chacha20(key, 1, nonce, plaintext)
    mac_data = (
        aad
        + _pad16(aad)
        + ciphertext
        + _pad16(ciphertext)
        + struct.pack("<QQ", len(aad), len(ciphertext))
    )
    return ciphertext + poly1305(otk, mac_data)


def _self_test():
    key = bytes(range(32))
    block = chacha20_block(key, 1, bytes.fromhex("000000090000004a00000000"))
    assert block.hex().startswith("10f1e7e4d13b5915500fdd1fa32071c4"), "RFC 8439 2.3.2"
    sunscreen = (
        b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip"
        b" for the future, sunscreen would be it."
    )
    stream = chacha20(key, 1, bytes.fromhex("000000000000004a00000000"), sunscreen)
    assert stream.hex().startswith("6e2e359a2568f98041ba0728dd0d6981"), "RFC 8439 2.4.2"
    assert stream.hex().endswith("5af90bbf74a35be6b40b8eedf2785e42874d"), "RFC 8439 2.4.2"
    tag = poly1305(
        bytes.fromhex(
            "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b"
        ),
        b"Cryptographic Forum Research Group",
    )
    assert tag.hex() == "a8061dc1305136c6c22b8baf0c0127a9", "RFC 8439 2.5.2"
    sealed = aead_encrypt(
        bytes(range(0x80, 0xA0)),
        bytes.fromhex("070000004041424344454647"),
        sunscreen,
        bytes.fromhex("50515253c0c1c2c3c4c5c6c7"),
    )
    assert sealed.hex().startswith("d31a8d34648e60db7b86afbc53ef7ec2"), "RFC 8439 2.8.2"
    assert sealed[-16:].hex() == "1ae10b594f09e26a7e902ecbd0600691", "RFC 8439 2.8.2"


_self_test()
