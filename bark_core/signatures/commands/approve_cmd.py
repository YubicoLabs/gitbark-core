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
from ..approvals import ApprovalRequest, SigningKey, PgpSigningKey, SshSigningKey

import click


@click_callback()
def click_parse_commit(ctx, param, val):
    project = ctx.obj["project"]
    repo = project.repo

    try:
        target = repo.revparse_single(val)
        return Commit(target.id.hex, repo)
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
    branch = repo.head.shorthand

    key: SigningKey

    if not gpg_key_id and not ssh_key_path:
        config = repo.config
        if "user.signingkey" in config:
            identifier = config["user.signingkey"]
            type = config["gpg.format"] if "gpg.format" in config else "openpgp"

            if type == "openpgp":
                key = PgpSigningKey(identifier)
            elif type == "ssh":
                key = SshSigningKey(identifier)

    if gpg_key_id:
        key = PgpSigningKey(identifier)

    if ssh_key_path:
        key = SshSigningKey(identifier)

    if not key:
        identifier = click_prompt(prompt="Enter key identifier")
        type = click_prompt(
            prompt="Enter the key type (GPG or SSH)",
            type=click.Choice(["GPG", "SSH"]),
            show_choices=False,
        )
        if type == "GPG":
            key = PgpSigningKey(identifier)
        else:
            key = SshSigningKey(identifier)

    request = ApprovalRequest.lookup(commit, branch)
    if not request:
        raise CliFail("Approval request not found")
    request.approve(key)
