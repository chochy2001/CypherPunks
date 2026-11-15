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

### Key storage format

Each private key is stored in its own JSON file. `python -m vault keygen alice` writes four files:

```text
keystore/
├── alice.key.json      RSA-3072 private key (usage "wrap"), encrypted
├── alice.pub.pem       RSA public key, given to senders
├── alice.sign.key.json Ed25519 private key (usage "sign"), encrypted
└── alice.sign.pub.pem  Ed25519 public key, given to recipients
```

A keystore file looks like this (Base64 values shortened):

```json
{
  "format": "SDV-KEYSTORE-1",
  "kdf_parameters": {"algorithm": "scrypt", "n": 131072, "r": 8, "p": 1, "length": 32},
  "salt": "p+ddvM+kMXc1SLiCp08U4g==",
  "metadata": {"key_id": "44f33404...513564b", "usage": "wrap", "created_at": 1794187007},
  "nonce": "Ov+ywbMzrKnWEylV",
  "encrypted_private_key": "gcpS4Q..."
}
```

| Field | Content | Protection |
| --- | --- | --- |
| `format` | `SDV-KEYSTORE-1` | AAD |
| `kdf_parameters` | KDF name, N, r, p and output length | AAD |
| `salt` | 16 random bytes | AAD |
| `metadata` | `key_id`, `usage` (`wrap` or `sign`) and `created_at` | AAD |
| `nonce` | 12-byte GCM nonce | Input to GCM |
| `encrypted_private_key` | PKCS#8 DER private key encrypted with AES-256-GCM, followed by the 16-byte tag | Encrypted and covered by the tag |

The first four fields are the AAD of the encryption, so a change to the salt, the parameters or the metadata makes the tag check fail exactly like a wrong password. Binary values are Base64. The file is created with owner-only permissions where the operating system supports them, and an existing keystore is never overwritten.

### Backup strategy

A backup is an exact copy of the keystore file. Because the file is already encrypted, making a backup needs no password, and the copy can be kept on a USB drive or in a cloud folder with the same protection as the original:

```bash
python -m vault backup keystore/alice.key.json keystore/alice.sign.key.json # -> backups/
python -m vault restore backups/alice.key.json                  # -> keystore/
```

Restoring is stricter than backing up. `restore` asks for the password and unlocks the backup
before copying it, so a modified backup or one that belongs to another user is refused instead
of replacing a working keystore, and an existing keystore is never overwritten. Backups should
be kept away from the device that holds the keystore, because a single loss would otherwise
take both. Public keys are not secret and need no special handling.