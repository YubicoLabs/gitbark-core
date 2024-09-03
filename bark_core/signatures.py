# Copyright 2023 Yubico AB

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from gitbark.git import Commit, BARK_CONFIG
from gitbark.rule import CommitRule, RuleViolation
from gitbark.cli.util import get_root, click_prompt
from gitbark.util import cmd

from pgpy import PGPKey as _PGPKey, PGPSignature
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePublicKey,
    ECDSA,
    SECP256R1,
    SECP384R1,
    SECP521R1,
)
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey, RSAPublicNumbers
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.dsa import (
    DSAPublicKey,
    DSAParameterNumbers,
    DSAPublicNumbers,
)
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.serialization import SSHPublicKeyTypes
from cryptography.hazmat.primitives.hashes import Hash, SHA1, SHA256, SHA384, SHA512
from typing import Any, Union, Optional, Tuple
from base64 import b64decode, b64encode
from abc import ABC, abstractmethod

import warnings
import os
import click

warnings.filterwarnings("ignore")


class Pubkey(ABC):
    def __init__(self, pubkey: bytes) -> None:
        self._bytes = pubkey

    def __bytes__(self):
        return self._bytes

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Pubkey):
            return other.fingerprint == self.fingerprint
        return False

    def __hash__(self) -> int:
        return hash(self.fingerprint)

    @property
    @abstractmethod
    def fingerprint(self) -> str:
        pass

    @property
    @abstractmethod
    def type(self) -> str:
        pass

    @abstractmethod
    def verify_signature(self, email: str, signature: bytes, subject: bytes) -> bool:
        pass

    @classmethod
    @abstractmethod
    def _load_blob(cls, identifier: str) -> bytes:
        pass

    @classmethod
    def from_identifier(cls, identifier: str) -> "Pubkey":
        for key_class in cls.__subclasses__():
            try:
                blob = key_class._load_blob(identifier)
                return key_class(blob)
            except Exception:
                pass
        raise ValueError("Unsupported key type")

    @classmethod
    def from_blob(cls, pubkey: bytes) -> "Pubkey":
        for key_class in cls.__subclasses__():
            try:
                return key_class(pubkey)
            except Exception:
                pass
        raise ValueError("Unsupported key type")


# OpenPGP


class PgpKey(Pubkey):
    def __init__(self, pubkey: bytes) -> None:
        super().__init__(pubkey)
        key, _ = _PGPKey.from_blob(pubkey)
        self._key = key
        self._emails = [u.email for u in self._key.userids]

    @property
    def type(self) -> str:
        return "PGP"

    @property
    def fingerprint(self) -> str:
        return str(self._key.fingerprint)

    def verify_signature(self, email: str, signature: bytes, subject: bytes) -> bool:
        if email not in self._emails:
            return False
        if self._is_pgp_signature(signature):
            signature = PGPSignature.from_blob(signature)
            try:
                if self._key.verify(subject, signature):
                    return True
                else:
                    return False
            except Exception:
                return False
        return False

    @classmethod
    def _load_blob(cls, identifier: str) -> bytes:
        try:
            pubkey = cmd("gpg", "--armor", "--export", identifier, text=False)[0]
            return pubkey
        except Exception:
            raise ValueError(f"Could not parse PGP key from identifier '{identifier}'")

    def _is_pgp_signature(self, signature: bytes):
        if b"-----BEGIN PGP SIGNATURE-----" in signature:
            return True
        else:
            return False


# SSH


def ssh_get_int(buf: bytes) -> Tuple[int, bytes]:
    return int.from_bytes(buf[:4], "big"), buf[4:]


def ssh_get_string(buf: bytes) -> Tuple[bytes, bytes]:
    ln, buf = ssh_get_int(buf)
    return buf[:ln], buf[ln:]


def ssh_get_bigint(buf: bytes) -> Tuple[int, bytes]:
    value, rest = ssh_get_string(buf)
    return int.from_bytes(value, "big"), rest


def ssh_put_string(value: bytes) -> bytes:
    return len(value).to_bytes(4, "big") + value


# Public key types
_SSH_DSA = b"ssh-dss"
_SSH_RSA = b"ssh-rsa"
_SSH_ED25519 = b"ssh-ed25519"
_ECDSA_NISTP256 = b"ecdsa-sha2-nistp256"
_ECDSA_NISTP384 = b"ecdsa-sha2-nistp384"
_ECDSA_NISTP521 = b"ecdsa-sha2-nistp521"
_SK_SSH_ED25519 = b"sk-ssh-ed25519@openssh.com"
_SK_ECDSA_NISTP256 = b"sk-ecdsa-sha2-nistp256@openssh.com"

_SUPPORTED_KEYS = (
    _SSH_DSA,
    _SSH_RSA,
    _SSH_ED25519,
    _ECDSA_NISTP256,
    _ECDSA_NISTP384,
    _ECDSA_NISTP521,
    _SK_SSH_ED25519,
    _SK_ECDSA_NISTP256,
)

_ECDSA_CURVES = {
    _ECDSA_NISTP256: SECP256R1,
    _ECDSA_NISTP384: SECP384R1,
    _ECDSA_NISTP521: SECP521R1,
    _SK_ECDSA_NISTP256: SECP256R1,
}


# Hashes

_H_MESSAGE = {
    b"sha256": SHA256,
    b"sha512": SHA512,
}

_H_RSA = {
    b"rsa-sha2-256": SHA256,
    b"rsa-sha2-512": SHA512,
}

_H_ECDSA = {
    _ECDSA_NISTP256: SHA256,
    _ECDSA_NISTP384: SHA384,
    _ECDSA_NISTP521: SHA512,
    _SK_ECDSA_NISTP256: SHA256,
}

_H_DSA = {
    _SSH_DSA: SHA1,
}


def ssh_verify_signature(keydata: bytes, payload: bytes, signature_pem: bytes) -> None:
    parts = signature_pem.split(b"\n")
    b64 = b"".join(parts[1:-1])
    buf = b64decode(b64)

    prefix, buf = buf[:6], buf[6:]
    assert prefix == b"SSHSIG"
    version, buf = ssh_get_int(buf)
    assert version == 1
    pk_m, buf = ssh_get_string(buf)
    namespace, buf = ssh_get_string(buf)
    reserved, buf = ssh_get_string(buf)
    hash_algo, buf = ssh_get_string(buf)
    sig_m, buf = ssh_get_string(buf)

    if keydata != pk_m:
        raise ValueError("Public key mismatch")

    sign_keytype, sig_m = ssh_get_string(sig_m)
    signature, sig_m = ssh_get_string(sig_m)

    md = Hash(_H_MESSAGE[hash_algo]())
    md.update(payload)
    h_message = md.finalize()
    message = (
        prefix
        + ssh_put_string(namespace)
        + ssh_put_string(reserved)
        + ssh_put_string(hash_algo)
        + ssh_put_string(h_message)
    )

    key, pk_m = load_ssh_key(pk_m)

    if sign_keytype.startswith(b"sk-"):
        # Message is embedded into FIDO structure
        application, pk_m = ssh_get_string(pk_m)
        md = Hash(SHA256())
        md.update(application)
        app_param = md.finalize()
        md = Hash(SHA256())
        md.update(message)
        client_param = md.finalize()
        message = (
            app_param  # sha256("ssh:")
            + sig_m  # flags + counter
            + b""  # extensions
            + client_param  # sha256(message)
        )

    if isinstance(key, RSAPublicKey):
        key.verify(signature, message, PKCS1v15(), _H_RSA[sign_keytype]())
    elif isinstance(key, EllipticCurvePublicKey):
        # R and S encoded in SSH format
        r, signature = ssh_get_bigint(signature)
        s, signature = ssh_get_bigint(signature)
        signature = encode_dss_signature(r, s)
        key.verify(signature, message, ECDSA(_H_ECDSA[sign_keytype]()))
    elif isinstance(key, DSAPublicKey):
        # R and S encoded as 20 byte integers
        r = int.from_bytes(signature[:20], "big")
        s = int.from_bytes(signature[20:], "big")
        signature = encode_dss_signature(r, s)
        key.verify(signature, message, _H_DSA[sign_keytype]())
    else:
        key.verify(signature, message)


def load_ssh_key(data: bytes) -> Tuple[SSHPublicKeyTypes, bytes]:
    keytype, data = ssh_get_string(data)
    if keytype == _SSH_RSA:
        e, data = ssh_get_bigint(data)
        n, data = ssh_get_bigint(data)
        return RSAPublicNumbers(e, n).public_key(), data
    if keytype in _ECDSA_CURVES:
        curve, data = ssh_get_string(data)
        point, data = ssh_get_string(data)
        return (
            EllipticCurvePublicKey.from_encoded_point(_ECDSA_CURVES[keytype](), point),
            data,
        )
    if keytype in (_SSH_ED25519, _SK_SSH_ED25519):
        pub_bytes, data = ssh_get_string(data)
        return Ed25519PublicKey.from_public_bytes(pub_bytes), data
    if keytype == _SSH_DSA:
        p, data = ssh_get_bigint(data)
        q, data = ssh_get_bigint(data)
        g, data = ssh_get_bigint(data)
        y, data = ssh_get_bigint(data)
        pn = DSAParameterNumbers(p, q, g)
        return DSAPublicNumbers(y, pn).public_key(), data
    raise UnsupportedAlgorithm()


class SshKey(Pubkey):
    def __init__(self, pubkey: bytes) -> None:
        super().__init__(pubkey)
        parts = pubkey.split()
        self._emails = parts[0].decode().split(",")
        i = 1
        while not parts[i] in _SUPPORTED_KEYS:
            i += 1

        self._key = b64decode(parts[i + 1])

    @property
    def type(self) -> str:
        return "SSH"

    @property
    def fingerprint(self) -> str:
        md = Hash(SHA256())
        md.update(self._key)
        return b64encode(md.finalize()).decode().rstrip("=")

    def verify_signature(self, email: str, signature: bytes, subject: bytes) -> bool:
        if email not in self._emails:
            return False
        if self._is_ssh_signature(signature):
            try:
                ssh_verify_signature(self._key, subject, signature)
                return True
            except (InvalidSignature, ValueError):
                return False
        return False

    @classmethod
    def _load_blob(cls, identifier: str) -> bytes:
        try:
            # expanduser to catch relative paths like ~/.ssh/key.pub
            identifier = os.path.expanduser(identifier)
            with open(identifier, "rb") as f:
                pubkey = f.read()
                return pubkey
        except Exception:
            raise ValueError(f"Could not parse SSH key from '{identifier}'")

    def _is_ssh_signature(self, signature: bytes):
        if b"-----BEGIN SSH SIGNATURE-----" in signature:
            return True
        else:
            return False


def verify_signature_bulk(
    pubkeys: list[Pubkey], email: str, signature: Any, subject: Any
) -> bool:
    for pubkey in pubkeys:
        if pubkey.verify_signature(email, signature, subject):
            return True

    return False


def get_authorized_pubkeys(
    validator: Commit, authorized_keys_patterns: Union[list[str], str]
) -> list[Pubkey]:
    files = validator.list_files(authorized_keys_patterns, f"{BARK_CONFIG}/pubkeys")
    blobs = [validator.read_file(f) for f in files]
    return [Pubkey.from_blob(blob) for blob in blobs]


def get_pubkey_from_git() -> Optional[Pubkey]:
    identifier = cmd("git", "config", "user.signingKey", check=False)[0]
    if identifier:
        gpg_format = cmd("git", "config", "gpg.format", check=False)[0]
        # check if signingKey is ssh
        if gpg_format and gpg_format == "ssh":
            email = cmd("git", "config", "user.email", check=False)[0]
            identifier = os.path.expanduser(identifier) # expand path if relative
            with open(identifier, 'r') as file: # read public key
                pubkey = file.read()
                return SshKey(f"{email} ".encode() + pubkey.encode())
        return Pubkey.from_identifier(identifier)
    return None


def load_public_key_files(name_only: bool = False) -> list[str]:
    toplevel = get_root()
    pubkeys_folder = os.path.join(toplevel, BARK_CONFIG, "pubkeys")
    if os.path.exists(pubkeys_folder):
        if name_only:
            return os.listdir(pubkeys_folder)
        else:
            return [f"{pubkeys_folder}/{file}" for file in os.listdir(pubkeys_folder)]
    return []


def load_public_keys() -> set[Pubkey]:
    pubkeys = set()
    for pubkey_file in load_public_key_files():
        with open(pubkey_file, "rb") as f:
            pubkeys.add(Pubkey.from_blob(f.read()))
    return pubkeys


def _add_public_key_to_repo(pubkey: Pubkey, file_name: str) -> None:
    pubkeys_folder = os.path.join(get_root(), BARK_CONFIG, "pubkeys")
    if not os.path.exists(pubkeys_folder):
        os.makedirs(pubkeys_folder)

    with open(f"{pubkeys_folder}/{file_name}", "wb") as f:
        f.write(bytes(pubkey))
    cmd("git", "add", f"{pubkeys_folder}/{file_name}")
    print(pubkey)


def add_public_keys_interactive() -> None:
    click.echo("This rule requires at least one public key to be added in your repo!\n")
    pubkeys = load_public_keys()

    if len(pubkeys) > 0:
        click.echo("Found public keys in your repository! ", nl=False)
        if not click.confirm("Do you want to add more public keys?"):
            return

    p_key = get_pubkey_from_git()
    if p_key and p_key not in pubkeys:
        click.echo(
            f"Found {p_key.type} key with identifier {p_key.fingerprint}. ", nl=False
        )
        if click.confirm("Do you want to add this public key to the repo?"):
            file_name = click_prompt(prompt="Enter the name for the public key")
            _add_public_key_to_repo(p_key, file_name)
            pubkeys.add(p_key)

    while True:
        if len(pubkeys) == 0:
            identifier = click_prompt("Enter the identifier for a new signing key")
        else:
            identifier = click_prompt(
                prompt="Enter the identifier for a new signing key "
                "(leave blank to skip)",
                default="",
                show_default=False,
            )
            if not identifier:
                break
        try:
            p_key = Pubkey.from_identifier(identifier)
        except Exception as e:
            click.echo(f"Failed to parse public key! {e}")
            continue

        file_name = click_prompt(prompt="Enter the name for the public key")
        _add_public_key_to_repo(p_key, file_name)
        pubkeys.add(p_key)


def add_authorized_keys_interactive(pubkeys: list[str]) -> str:
    click.echo("\nThe following public keys are included in your repo:")
    for pubkey in pubkeys:
        click.echo(" - {0}".format(pubkey))
    authorized_keys = click_prompt(
        f"\nEnter the set of authorized keys as a regex pattern (e.g. {pubkey})"
    )
    return authorized_keys


def require_signature(commit: Commit, authorized_pubkeys: list[Pubkey]):
    signature, commit_object = commit.signature
    _, email = commit.author

    if not signature:
        # No signature
        raise RuleViolation("Commit was not signed")

    if len(authorized_pubkeys) == 0:
        # No pubkeys specified
        raise RuleViolation("No public keys registered")

    if not verify_signature_bulk(authorized_pubkeys, email, signature, commit_object):
        raise RuleViolation("Commit was signed by untrusted key")


class RequireSignature(CommitRule):
    """Requires the commit to be signed."""

    def _parse_args(self, args):
        self.authorized_keys = args["authorized_keys"]

    def validate(self, commit: Commit):
        authorized_pubkeys = get_authorized_pubkeys(
            self.validator, self.authorized_keys
        )

        require_signature(commit, authorized_pubkeys)

    @staticmethod
    def setup() -> dict:
        add_public_keys_interactive()
        pubkeys = load_public_key_files(name_only=True)
        authorized_keys = add_authorized_keys_interactive(pubkeys)

        return {"require_signature": {"authorized_keys": authorized_keys}}
