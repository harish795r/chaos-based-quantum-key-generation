"""
Standalone test for Module 2 (Adaptive Engine) + Module 5 (AES-256-GCM).

Run this independently — does NOT require Modules 1, 3, or 4.
A dummy 256-bit key simulates what Module 4 (HKDF) would produce.
"""

import os
from module2_adaptive_engine import run_adaptive_engine
from module5_aes_gcm import encrypt, decrypt


def test_text_message():
    print("\n" + "━" * 55)
    print("  TEST 1 — Plain text message")
    print("━" * 55)

    profile = run_adaptive_engine(verbose=True)

    # Simulate HKDF output (Module 4 will provide this for real)
    dummy_session_key = os.urandom(profile.hkdf_length)

    plaintext = b"Hybrid post-quantum encryption: ML-KEM + Chaos + AES-256-GCM"

    enc = encrypt(plaintext, dummy_session_key, profile, verbose=True)
    dec = decrypt(enc.payload, dummy_session_key, verbose=True)

    assert dec.tag_verified,        "Tag verification failed!"
    assert dec.plaintext == plaintext, "Decrypted text does not match!"
    print("  ✅  TEST 1 PASSED — round-trip successful\n")


def test_image_like_binary():
    print("\n" + "━" * 55)
    print("  TEST 2 — Large binary payload (simulated image, 1 MB)")
    print("━" * 55)

    profile = run_adaptive_engine(verbose=False)   # silent for brevity
    dummy_session_key = os.urandom(profile.hkdf_length)

    # 1 MB of random bytes simulating raw image data
    plaintext = os.urandom(1024 * 1024)

    enc = encrypt(plaintext, dummy_session_key, profile, verbose=True)
    dec = decrypt(enc.payload, dummy_session_key, verbose=True)

    assert dec.tag_verified,           "Tag verification failed!"
    assert dec.plaintext == plaintext, "Decrypted image does not match!"
    print("  ✅  TEST 2 PASSED — 1 MB image round-trip successful\n")


def test_tamper_detection():
    print("\n" + "━" * 55)
    print("  TEST 3 — Tamper detection (ciphertext modified)")
    print("━" * 55)

    profile = run_adaptive_engine(verbose=False)
    dummy_session_key = os.urandom(profile.hkdf_length)
    plaintext = b"Sensitive data that must not be modified."

    enc = encrypt(plaintext, dummy_session_key, profile, verbose=False)

    # Flip one byte in the ciphertext to simulate an attacker
    tampered_ct = bytearray(enc.payload.ciphertext)
    tampered_ct[0] ^= 0xFF
    enc.payload.ciphertext = bytes(tampered_ct)

    dec = decrypt(enc.payload, dummy_session_key, verbose=True)

    assert not dec.tag_verified, "Expected tamper detection — tag should have failed!"
    print("  ✅  TEST 3 PASSED — tamper correctly detected\n")


def test_wrong_key():
    print("\n" + "━" * 55)
    print("  TEST 4 — Wrong session key (simulates attacker)")
    print("━" * 55)

    profile = run_adaptive_engine(verbose=False)
    correct_key = os.urandom(profile.hkdf_length)
    wrong_key   = os.urandom(profile.hkdf_length)   # completely different key

    plaintext = b"Top secret payload."

    enc = encrypt(plaintext, correct_key, profile, verbose=False)
    dec = decrypt(enc.payload, wrong_key, verbose=True)

    assert not dec.tag_verified, "Expected failure with wrong key!"
    print("  ✅  TEST 4 PASSED — wrong key correctly rejected\n")


def test_aad_integrity():
    print("\n" + "━" * 55)
    print("  TEST 5 — AAD integrity (modified header detected)")
    print("━" * 55)

    profile = run_adaptive_engine(verbose=False)
    key = os.urandom(profile.hkdf_length)
    plaintext = b"Packet payload data."
    aad = b"packet-header-session-id-12345"

    enc = encrypt(plaintext, key, profile, aad=aad, verbose=False)

    # Receiver uses WRONG AAD → tag must fail
    dec = decrypt(enc.payload, key, aad=b"tampered-header", verbose=True)

    assert not dec.tag_verified, "Expected AAD mismatch to be detected!"
    print("  ✅  TEST 5 PASSED — AAD tampering correctly detected\n")


if __name__ == "__main__":
    test_text_message()
    test_image_like_binary()
    test_tamper_detection()
    test_wrong_key()
    test_aad_integrity()

    print("=" * 55)
    print("  ALL 5 TESTS PASSED ✅")
    print("=" * 55)
