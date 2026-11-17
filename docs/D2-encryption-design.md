# D2: Secure Symmetric Encryption Module

This module protects files for a **single owner**. D3 and D5 use the same cryptographic core for the separate `SDV2` sharing format with public-key wrapping and signatures.

Security goal: *an attacker who obtains the encrypted file must not be able to read or modify its contents without detection.*

## 1. Module layout

| File | Responsibility |
| --- | --- |
| `vault/crypto_core.py` | Key and nonce generation, metadata canonicalization, AES-256-GCM encrypt/decrypt |
| `vault/container.py` | `.sdv` binary format: pack, unpack, structural validation |
| `vault/file_vault.py` | File-level API: `encrypt_file`, `decrypt_file`, atomic writes |
| `vault/cli.py` | Command-line interface |
| `vault/exceptions.py` | `VaultError`, `IntegrityError`, `ContainerFormatError` |

## 2. Encryption design

### Selected AEAD algorithm

**AES-256-GCM**, through the `AESGCM` class of the Python `cryptography` library. GCM gives confidentiality (AES in counter mode) and integrity of both the ciphertext and the associated data (GHASH authentication tag) in a single primitive. It is a NIST standard (SP 800-38D), it is hardware-accelerated on most CPUs (AES-NI), and the library implementation is widely reviewed. ChaCha20-Poly1305 would have been an equally valid choice; we chose AES-GCM because of hardware support on the machines we target.

### Key size

256-bit keys. A **fresh key is generated for every file** with `AESGCM.generate_key(bit_length=256)`, which draws from the operating system CSPRNG. The key is never written inside the container. In D2 the CLI saves it as hex in a separate `.key` file with owner-only permissions; protecting that key properly (Key Store, password-based wrapping, recipient public key) is deferred to later deliverables.

### Nonce strategy

- 96-bit (12-byte) nonces, the size GCM is designed for.
- Generated with `os.urandom(12)` **inside** `crypto_core.encrypt()`, so the caller cannot pass, fix or reuse a nonce.
- Stored in clear in the container, right after the header. A nonce does not need to be secret, only unique per key.
- Because every file gets its own key and each key encrypts exactly one message, a nonce collision under the same key is not just unlikely but structurally impossible in the current design. The random nonce is still kept as defense in depth for when keys get reused in future versions (re-encryption, versioning).

`encrypt()` also refuses to run without AAD (`None` or empty bytes), so the metadata can never be left unbound by mistake. This was added after code review in PR #1.

### Metadata confidentiality and authentication

Metadata is a JSON object:

```json
{"algorithm":"AES-256-GCM","key_bits":256,"nonce_bytes":12,"original_name":"contract.pdf","tag_bytes":16,"timestamp":1760650000,"version":"1.0"}
```

It is serialized canonically (`sort_keys=True`, no spaces, ASCII). New single-owner packages use `SDV3` and encrypt the metadata length, the JSON and the original file bytes as one AES-GCM message. The `SDV3` identifier serves as AAD. The metadata's `version` field describes its JSON schema and stays at `1.0`.

Existing `SDV1` packages store that JSON in the clear. Their raw header, including the length and metadata bytes, is the AAD. Both formats parse the metadata JSON after the tag has been verified.

### Container format (`.sdv`)

```
SDV3 (new)      magic "SDV3" (4 B, AAD) | nonce (12 B) | ciphertext | tag (16 B)
                encrypted plaintext: uint32 BE metadata length | metadata JSON | file bytes

SDV1 (legacy)   magic "SDV1" (4 B) | uint32 BE metadata length | metadata JSON |
                nonce (12 B) | ciphertext | tag (16 B)
                AAD: the raw header through the metadata JSON
```

The parser checks the public structure before calling AES-GCM. Metadata length is limited to 64 KiB and must fit in the corresponding buffer. For `SDV3` this check runs after authentication, because its length field is inside the encrypted payload.

### Decryption order and safe failure

1. Parse the structure (offsets only; nothing is trusted yet).
2. Verify the tag and decrypt with the stored header as AAD.
3. After authentication, split the `SDV3` payload or read the authenticated `SDV1` metadata bytes. Parse the JSON and validate the original file name.
4. Write the output through a temporary file and an atomic rename.

Any failure raises an exception and **no output file is created**, not even a partial one. Decryption also refuses to replace an existing file (for example, the original document sitting next to its `.sdv`) unless the caller passes `overwrite=True` (`--force` in the CLI). Authentication errors carry a generic message ("authentication failed") that does not reveal whether the key, nonce, ciphertext or metadata was the problem. The original file name from the metadata is reduced to its base name before use, so a stored name cannot point outside the output folder.

## 3. Security decisions

### Why AEAD instead of encryption + hash?

A plain hash next to the ciphertext protects nothing: the hash is public and keyless, so an attacker who modifies the ciphertext simply recomputes the hash. Integrity needs a **keyed** check (a MAC). Building encryption + MAC by hand is possible (encrypt-then-MAC with HMAC) but it is easy to get wrong: MAC-then-encrypt or encrypt-and-MAC orderings have led to real attacks (padding oracles), the MAC must also cover the IV and metadata, two independent keys are needed, and the comparison must be constant-time. AEAD solves all of this in a single, standardized and reviewed primitive: one key, one call, and the tag covers the ciphertext, the nonce and the associated data together. Decryption refuses to return plaintext if the tag does not verify.

### What happens if a nonce repeats?

GCM encrypts by XORing the plaintext with a keystream derived from the key and the nonce. If the same (key, nonce) pair is used twice:

1. **Confidentiality breaks.** Both messages are XORed with the same keystream, so `C1 ⊕ C2 = P1 ⊕ P2`. Anyone who knows or guesses one plaintext (and file formats like PDF have very predictable headers) recovers the other. The test `test_nonce_reuse_leaks_plaintext_xor` demonstrates this.
2. **Integrity breaks.** With two tags under the same nonce, an attacker can solve for the GHASH authentication key `H` (the "forbidden attack", Joux 2006). With `H` they can forge valid tags for arbitrary ciphertexts under that key, so tamper detection is lost entirely.

Our design prevents this by generating the nonce inside `encrypt()` from the OS CSPRNG and by using a new key for every file.

### What attacker are we defending against?

The same attacker defined in D1 for the untrusted zone: someone who can **read, copy, modify, truncate, replace or delete** the encrypted file while it is stored or in transit, and who knows exactly how the system and the container format work (Kerckhoffs's principle). Against that attacker the module guarantees:

| Attacker action | Result |
| --- | --- |
| Reads an `SDV3` package | Sees the format identifier, nonce and package size. Metadata and content stay confidential |
| Reads a legacy `SDV1` package | Sees the clear metadata and package size. Content stays confidential |
| Flips bits in the ciphertext or tag | `IntegrityError`, nothing written |
| Edits the metadata (name, timestamp, algorithm) | `IntegrityError`, nothing written |
| Changes the nonce | `IntegrityError`, nothing written |
| Truncates or corrupts the structure | `ContainerFormatError` for an invalid structure, or `IntegrityError` if only authentication detects the change. Nothing written |
| Tries a different key | `IntegrityError`, nothing written |

The default external file name `<input>.sdv` still exposes the original name outside the package. Use a neutral path with `encrypt -o` when the external name matters. Existing `SDV1` packages keep their original visibility and can be decrypted and encrypted again as `SDV3`. This format does not address a compromised endpoint, theft of the `.key` file, deletion or replay.

## 4. Tests

Run with `python -m pytest -v`.

| Requirement | Tests |
| --- | --- |
| Encrypt → decrypt returns identical file | `test_encrypt_decrypt_identical_file`, `test_roundtrip`, `test_cli_roundtrip` |
| Wrong key fails | `test_wrong_key_fails` (AEAD and file level) |
| Modified ciphertext fails | `test_modified_ciphertext_fails`, `test_modified_tag_fails`, `test_truncated_ciphertext_fails` |
| Private metadata and compatible legacy restoration | `test_private_container_hides_and_restores_original_name`, `test_legacy_container_restores_original_name` |
| Modified metadata fails | `test_modified_private_metadata_ciphertext_fails`, `test_modified_metadata_fails`, `test_modified_timestamp_fails` |
| Multiple encryptions produce different ciphertexts | `test_two_encryptions_differ`, `test_same_input_gives_different_ciphertexts` |
| Nonce uniqueness / secure randomness | `test_nonces_are_unique`, `test_keys_are_fresh` |
| Safe failure | `test_malformed_private_metadata_writes_nothing`, `test_failed_decryption_writes_nothing`, `test_cli_tampered_container_returns_error`, `test_decrypt_does_not_overwrite_existing_file` |
| Metadata always bound | `test_encrypt_requires_aad` |

## References

[1] M. Dworkin, "Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC," NIST SP 800-38D, 2007.
[2] A. Joux, "Authentication Failures in NIST version of GCM," comments to NIST, 2006.
[3] D. McGrew and J. Viega, "The Galois/Counter Mode of Operation (GCM)," 2005.
[4] Python Cryptographic Authority, "Authenticated encryption — cryptography documentation." [Online]. Available: https://cryptography.io/en/latest/hazmat/primitives/aead/
