"""D6 required tests: a private key is usable only with its password."""
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
