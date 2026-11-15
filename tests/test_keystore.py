"""D6 required tests: a private key is usable only with its password."""
import base64
import json

import pytest

from vault import hybrid, keys, keystore
from vault.exceptions import KeyManagementError

PASSWORD = b"correct horse battery staple"
PLAINTEXT = b"%PDF-1.7\n" + b"llave protegida " * 2000


@pytest.fixture(scope="module")
def bob():
    return keys.generate_keypair()


@pytest.fixture
def bob_keystore(tmp_path, bob):
    path = tmp_path / "bob.key.json"
    keystore.save_keystore(bob, "wrap", path, PASSWORD)
    return path


@pytest.fixture
def shared(bob):
    return hybrid.encrypt_for_recipients(PLAINTEXT, [bob.public_key()])


# Required test 1
def test_correct_password_grants_access(bob_keystore, bob, shared):
    unlocked = keystore.load_keystore(bob_keystore, PASSWORD, "wrap")
    assert keys.key_id(unlocked.public_key()) == keys.key_id(bob.public_key())
    assert hybrid.decrypt_as_recipient(shared, unlocked) == PLAINTEXT


# Required test 2
def test_wrong_password_denied(bob_keystore):
    with pytest.raises(KeyManagementError):
        keystore.load_keystore(bob_keystore, b"correct horse battery stapler", "wrap")


def _flip(value: str) -> str:
    """Change one bit of a Base64 field."""
    data = bytearray(base64.b64decode(value))
    data[0] ^= 0x01
    return base64.b64encode(bytes(data)).decode("ascii")


# Required test 3
@pytest.mark.parametrize("mutate", [
    lambda store: store.update(
        encrypted_private_key=_flip(store["encrypted_private_key"])
    ),
    lambda store: store.update(salt=_flip(store["salt"])),
    lambda store: store["kdf_parameters"].update(n=2**14),
    lambda store: store["metadata"].update(key_id="0" * 64),
], ids=["encrypted_key", "salt", "kdf_parameters", "metadata"])
def test_modified_keystore_fails(bob_keystore, mutate):
    store = json.loads(bob_keystore.read_text(encoding="utf-8"))
    mutate(store)
    bob_keystore.write_text(json.dumps(store), encoding="utf-8")

    with pytest.raises(KeyManagementError):
        keystore.load_keystore(bob_keystore, PASSWORD, "wrap")