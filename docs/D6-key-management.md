# D6: Key Management

Up to D5 the vault encrypted, shared and signed files, but every guarantee rested on private keys kept in passphrase-protected PEM files whose KDF and parameters were chosen by the library and documented nowhere. If a private key is exposed, all of that collapses. D6 replaces those files with a keystore the team defines: each private key is encrypted under a key derived from the user's password, the file states exactly how, and any change to it is detected. This is what D1 asks for in SR-08 (private keys never leave the Key Store in usable form) and SR-09 (the password is never stored and a wrong one reveals nothing).

## 1. Module layout

| File | Change |
| --- | --- |
| `vault/keystore.py` | New: password-derived key (scrypt), encrypted keystore, backup and restore |
| `vault/keys.py` | Generates key pairs and handles public keys and key IDs; it no longer writes private keys |
| `vault/cli.py` | `keygen` writes keystores, `share` and `open` unlock them, new `backup` and `restore` commands |
| `tests/test_keystore.py` | The five required tests |

Unlocking follows the steps D6 requires. The CLI prompts for the password, scrypt derives a 256-bit key from it and the stored salt, AES-256-GCM decrypts the private key, and the key is used for that one command. The password is never written anywhere, and the decrypted key lives only in the memory of that process, which ends when the command finishes.

## 2. Key management design

### KDF selection and parameters

The KDF is scrypt [1] with N = 2^17, r = 8, p = 1, a 16-byte random salt and a 32-byte output, one of the configurations OWASP recommends [2]. Every guess costs about 128 MiB of memory and around 0.3 s in our test runs. We chose scrypt over PBKDF2 because it is memory-hard: an attacker who runs many guesses in parallel on GPUs has to pay for memory on each one, not only for computation. OWASP ranks Argon2id first, but the `cryptography` versions our `requirements.txt` allows (42 and later) only include it from version 44, while scrypt is available in all of them [4].

The derived key has a single use: it is the AES-256-GCM key that encrypts the private key. The encryption goes through the D2 core (`crypto_core.encrypt`), so every keystore gets a fresh random nonce, and a new salt is drawn from `os.urandom` each time a keystore is written. Passwords shorter than 12 characters are refused when a keystore is created.
