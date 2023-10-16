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

from gitbark.git import Commit
from gitbark.cli.util import click_prompt, CliFail, click_callback

from dataclasses import dataclass
from enum import IntEnum
import subprocess
import click


class KeyType(IntEnum):
    GPG = 1
    SSH = 2


@dataclass
class SigningKey:
    identifier: str
    type: KeyType


@click_callback()
def click_parse_commit(ctx, param, val):
    project = ctx.obj["project"]
    repo = project.repo

    try:
        object = repo.revparse_single(val)
        return Commit(object.id)
    except Exception:
        raise CliFail(f"{val} is not a valid commit object!")


@click.command()
@click.pass_context
@click.argument("commit", default="HEAD", callback=click_parse_commit)
@click.option("--gpg-key-id", type=str, default="", help="The GPG key ID.")
@click.option(
    "--ssh-key-path",
    type=str,
    default="",
    help="The path to your private SSH key.",
)
def approve(ctx, commit, gpg_key_id, ssh_key_path):
    """Add your signature to a commit.

    This will create a signature over a given commit object, that
    is stored under `refs/signatures`.

    \b
    COMMIT the commit to sign.
    """

    project = ctx.obj["project"]
    repo = project.repo

    key = None

    if not gpg_key_id and not ssh_key_path:
        config = repo.config
        if "user.signingkey" in config:
            identifier = config["user.signingkey"]
            type = config["gpg.format"] if "gpg.format" in config else "openpgp"

            if type == "openpgp":
                key = SigningKey(identifier, KeyType.GPG)
            elif type == "ssh":
                key = SigningKey(identifier, KeyType.SSH)

    if gpg_key_id:
        key = SigningKey(identifier, KeyType.GPG)

    if ssh_key_path:
        key = SigningKey(identifier, KeyType.SSH)

    if not key:
        identifier = click_prompt(prompt="Enter key identifier")
        type = click_prompt(
            prompt="Enter the key type (GPG or SSH)",
            type=click.Choice(["GPG", "SSH"]),
            show_choices=False,
        )
        type = KeyType.GPG if type == "GPG" else KeyType.SSH
        key = SigningKey(identifier, type)

    sig, key_id = sign_commit(commit, key)

    blob_id = repo.create_blob(sig)
    repo.references.create(f"refs/signatures/{commit.hash}/{key_id}", blob_id)


def sign_commit(commit: Commit, key: SigningKey):
    commit_obj = commit.object
    if key.type == KeyType.GPG:
        gpg_process = subprocess.Popen(
            ["gpg", "-u", key.identifier, "--armor", "--detach-sign", "-"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )
        sig, _ = gpg_process.communicate(input=commit_obj)
        return sig, key.identifier
    else:
        ssh_process = subprocess.Popen(
            ["ssh-keygen", "-Y", "sign", "-f", key.identifier, "-n", "git"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )
        sig, _ = ssh_process.communicate(input=commit_obj)
        return sig, get_ssh_key_id(key.identifier)


def get_ssh_key_id(ssh_key_path: str):
    output = subprocess.check_output(
        ["ssh-keygen", "-l", "-f", ssh_key_path], text=True
    ).rstrip()
    key_id = output.split(":")[1].split()[0]
    return key_id
