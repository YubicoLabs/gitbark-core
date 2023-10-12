from gitbark.git import Commit, BARK_CONFIG
from gitbark.cli.util import get_root, click_prompt
from gitbark.util import cmd

from pgpy import PGPKey, PGPSignature
from paramiko import PKey
from typing import Any, Union, Optional
from pygit2 import Repository

import subprocess
import re
import warnings
import os
import click

warnings.filterwarnings("ignore")


class Pubkey:
    def __init__(self, pubkey: str) -> None:
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
            pubkey = subprocess.check_output([
                "gpg",
                "--armor",
                "--export",
                identifier
            ])
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

    def _parse_pubkey(self, pubkey: str) -> Union[PGPKey, PKey]:
        try:
            key, _ = PGPKey.from_blob(pubkey)
            fingerprint = str(key.fingerprint)
            return key, fingerprint
        except Exception:
            pass
        try:
            key = PKey(data=pubkey)
            fingerprint = key.fingerprint.split(":")[1]
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
    
    def _verify_pgp_signature(self, pubkey: PGPKey, signature: Any, subject: Any) -> bool:
        signature = PGPSignature().from_blob(signature)
        try:
            if pubkey.verify(subject, signature):
                return True
            else:
                return False
        except Exception:
            return False
        
    def __hash__(self) -> int:
        return int(self.fingerprint, base=16)


def verify_signature_bulk(pubkeys: list[Pubkey], signature: Any, subject: Any) -> bool:
    for pubkey in pubkeys:
        if pubkey.verify_signature(signature, subject):
            return True

    return False


def get_authorized_pubkeys(
    validator: Commit, authorized_keys_patterns: Union[list[str], str]
):
    files = validator.list_files(authorized_keys_patterns, f"{BARK_CONFIG}/pubkeys")
    blobs = [validator.read_file(f) for f in files]
    return [Pubkey(blob) for blob in blobs]

def get_pubkey_from_git(repo: Repository) -> Optional[Pubkey]:
    config = repo.config
    if "user.signingkey" in config:
        identifier = config["user.signingkey"]
        return Pubkey.parse(identifier)
    return None

def load_public_key_files(name_only: bool = False) -> list[str]:
    toplevel = get_root()
    pubkeys_folder = os.path.join(toplevel, ".gitbark", ".pubkeys")
    if os.path.exists(pubkeys_folder):
        if name_only:
            return os.listdir(pubkeys_folder)
        else:
            return [f"{pubkeys_folder}/{file}" for file in os.listdir(pubkeys_folder)]
    return []

def load_public_keys() -> set[Pubkey]:
    pubkeys = set()
    for pubkey_file in load_public_key_files():
        with open (pubkey_file, "rb") as f:
            pubkeys.add(Pubkey(f.read()))
    return pubkeys

def _add_public_key_to_repo(pubkey: Pubkey, file_name:str) -> None:
    pubkeys_folder = os.path.join(get_root(), ".gitbark", ".pubkeys")
    if not os.path.exists(pubkeys_folder):
        os.makedirs(pubkeys_folder)

    with open(f"{pubkeys_folder}/{file_name}", "wb") as f:
        f.write(pubkey.bytes)
    cmd("git", "add", f"{pubkeys_folder}/{file_name}")

def add_public_keys_interactive(repo: Repository) -> None:
    click.echo("This rule requires at least one public key to be added in your repo!\n")
    pubkeys = load_public_keys()
    
    if len(pubkeys) > 0:
        click.echo("Found public keys in your repository! ", nl=False)
        if not click.confirm(
            "Do you want to add more public keys?"
        ):
            return
        
    p_key = get_pubkey_from_git(repo)
    if p_key and p_key not in pubkeys:
        click.echo(f"Found {p_key.type} key with identifier {p_key.fingerprint}. ", nl=False)
        if click.confirm(
            "Do you want to add this public key to the repo?"
        ):
            file_name = click_prompt(
                prompt="Enter the name for the public key"
            )
            _add_public_key_to_repo(p_key, file_name)
            pubkeys.add(p_key)
            
    cont = True
    while cont:
        if len(pubkeys) == 0:
            identifier = click_prompt("Enter the identifier for a new signing key")
        else:
            identifier = click_prompt(
                prompt="Enter the identifier for a new signing key (leave blank to skip)",
                default="",
                show_default=False,
            )
            if not identifier:
                cont = False
                break
        try:
            p_key = Pubkey.parse(identifier)
        except Exception as e:
            click.echo(f"Failed to parse public key! {e}")
            continue
            
        file_name = click_prompt(
                prompt="Enter the name for the public key"
            )
        _add_public_key_to_repo(p_key, file_name)
        pubkeys.add(p_key)
    return pubkeys

def add_authorized_keys_interactive(pubkeys: list[str]) -> str:
    click.echo("\nThe following public keys are included in your repo:")
    for pubkey in pubkeys:
        click.echo(" - {0}".format(pubkey))
    authorized_keys = click_prompt(
        f"\nEnter the set of authorized keys as a regex pattern (e.g. {pubkey[0]})"
    )
    return authorized_keys

        







