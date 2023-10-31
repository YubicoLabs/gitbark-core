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
from gitbark.cli.util import CliFail, click_callback

import click


@click_callback()
def click_parse_commit(ctx, param, val):
    project = ctx.obj["project"]
    repo = project.repo

    try:
        target = repo.revparse_single(val)
        return Commit(target.id.raw, repo)
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

    # project = ctx.obj["project"]
    # repo = project.repo
    # branch = repo.head.shorthand

    # TODO: Implement
    raise CliFail("Approval request not found")
