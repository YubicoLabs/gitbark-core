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

from pgpy import PGPKey, PGPSignature
from paramiko import PKey
from typing import Any, Union, Optional, Tuple

import subprocess
import warnings
import os
import click

warnings.filterwarnings("ignore")


class Pubkey:
    def __init__(self, pubkey: bytes) -> None:
        self.bytes = pubkey
        self.key, self.fingerprint = self._parse_pubkey(pubkey)

    @property
    def type(self) -> str:
        if isinstance(self.key, PGPKey):
            return "PGP"
        else:
            return "SSH"

    @classmethod
    def parse(cls, identifier: str) -> "Pubkey":
        try:
            pubkey = subprocess.check_output(["gpg", "--armor", "--export", identifier])
            return cls(pubkey=pubkey)
        except Exception:
            pass
        try:
            with open(identifier, "rb") as f:
                pubkey = f.read()
            return cls(pubkey=pubkey)
        except Exception:
            pass
        raise

    def _parse_pubkey(self, pubkey: bytes) -> Tuple[Union[PGPKey, PKey], str]:
        try:
            key, _ = PGPKey.from_blob(pubkey)
            fingerprint = str(key.fingerprint)
            return key, fingerprint
        except Exception:
            pass
        try:
            key = PKey(data=pubkey)
            fingerprint = key.fingerprint.split(":")[1]
            return key, fingerprint
        except Exception:
            pass
        raise ValueError("Could not parse public key!")

    def verify_signature(self, signature, subject) -> bool:
        if isinstance(self.key, PGPKey):
            return self._verify_pgp_signature(self.key, signature, subject)
        else:
            return self._verify_ssh_signature(self.key, signature, subject)

    def _verify_ssh_signature(self, pubkey: PKey, signature: Any, subject: Any) -> bool:
        return pubkey.verify_ssh_sig(subject, signature)

    def _verify_pgp_signature(
        self, pubkey: PGPKey, signature: Any, subject: Any
    ) -> bool:
        signature = PGPSignature().from_blob(signature)
        try:
            if pubkey.verify(subject, signature):
                return True
            else:
                return False
        except Exception:
            return False

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Pubkey):
            return other.fingerprint == self.fingerprint
        return False

    def __hash__(self) -> int:
        return hash(self.fingerprint)


def verify_signature_bulk(pubkeys: list[Pubkey], signature: Any, subject: Any) -> bool:
    for pubkey in pubkeys:
        if pubkey.verify_signature(signature, subject):
            return True

    return False


def get_authorized_pubkeys(
    validator: Commit, authorized_keys_patterns: Union[list[str], str]
) -> list[Pubkey]:
    files = validator.list_files(authorized_keys_patterns, f"{BARK_CONFIG}/pubkeys")
    blobs = [validator.read_file(f) for f in files]
    return [Pubkey(blob) for blob in blobs]


def get_pubkey_from_git() -> Optional[Pubkey]:
    identifier = cmd("git", "config", "user.signingKey")[0]
    if identifier:
        return Pubkey.parse(identifier)
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
            pubkeys.add(Pubkey(f.read()))
    return pubkeys


def _add_public_key_to_repo(pubkey: Pubkey, file_name: str) -> None:
    pubkeys_folder = os.path.join(get_root(), BARK_CONFIG, "pubkeys")
    if not os.path.exists(pubkeys_folder):
        os.makedirs(pubkeys_folder)

    with open(f"{pubkeys_folder}/{file_name}", "wb") as f:
        f.write(pubkey.bytes)
    cmd("git", "add", f"{pubkeys_folder}/{file_name}")


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
            p_key = Pubkey.parse(identifier)
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
        f"\nEnter the set of authorized keys as a regex pattern (e.g. {pubkey[0]})"
    )
    return authorized_keys


def require_signature(commit: Commit, authorized_pubkeys: list[Pubkey]):
    signature, commit_object = commit.signature

    if not signature:
        # No signature
        raise RuleViolation("Commit was not signed")

    if len(authorized_pubkeys) == 0:
        # No pubkeys specified
        raise RuleViolation("No public keys registered")

    if not verify_signature_bulk(authorized_pubkeys, signature, commit_object):
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