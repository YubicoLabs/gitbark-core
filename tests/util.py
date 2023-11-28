from gitbark.util import cmd
from gitbark.git import Repository

from bark_core.signatures import _add_public_key_to_repo, Pubkey

from typing import Union
import subprocess
import re


class Key:
    def __init__(self, identifier: str) -> None:
        self.identifier = identifier

    @property
    def pubkey(self) -> Pubkey:
        return Pubkey.from_identifier(self.identifier)

    @classmethod
    def create_pgp_key(
        cls,
        key_type: str,
        key_length_or_curve: Union[int, str],
        name: str,
        email: str,
        expire_date: int = 0,
    ) -> "Key":
        gpg_input = f"Key-Type: {key_type}\n"
        gpg_input += (
            f"Key-Length: {key_length_or_curve}\n"
            if key_type == "RSA"
            else f"Key-Curve: {key_length_or_curve}\n"
        )
        gpg_input += f"Name-Real: {name}\n"
        gpg_input += f"Name-Email: {email}\n"
        gpg_input += f"Expire-Date: {expire_date}\n"
        gpg_input += "%no-protection\n"  # No passphrase

        gpg_command = ["gpg", "--batch", "--generate-key", "--status-fd", "1"]

        process = subprocess.Popen(
            gpg_command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        output, error = process.communicate(input=gpg_input)

        if process.returncode != 0:
            raise ValueError(f"Error running GPG: {error}")

        fingerprint_match = re.search(r"KEY_CREATED P (\w+)", output)

        fingerprint = fingerprint_match.group(1)
        return cls(fingerprint)

    @classmethod
    def create_ssh_key(cls, ssh_dir: str, key_type: str, file_name: str) -> "Key":
        ssh_key_path = f"{ssh_dir}/{file_name}"
        cmd("ssh-keygen", "-t", key_type, "-N", "", "-f", ssh_key_path)
        return cls(f"{ssh_key_path}.pub")

    def add_to_repo(self, file_name: str) -> None:
        _add_public_key_to_repo(self.pubkey, file_name)


def configure_ssh(repo: Repository, key: Key):
    cmd("git", "config", "gpg.format", "ssh", cwd=repo._path)
    cmd("git", "config", "user.signingkey", key.identifier, cwd=repo._path)
