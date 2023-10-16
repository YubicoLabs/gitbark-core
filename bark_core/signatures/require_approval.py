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
from gitbark.rule import Rule, RuleViolation
from gitbark.util import cmd
from gitbark.cli.util import CliFail, get_root

from .util import (
    Pubkey,
    get_authorized_pubkeys,
    add_public_keys_interactive,
    add_authorized_keys_interactive,
    load_public_key_files,
    click_prompt,
)

from pygit2 import Repository, Blob
import re
import logging

logger = logging.getLogger(__name__)


class RequireApproval(Rule):
    """Requires merge commits to include signature approvals."""

    def _parse_args(self, args):
        self.authorized_keys = args["authorized_keys"]
        self.threshold = int(args["threshold"])

    def validate(self, commit: Commit):
        authorized_pubkeys = get_authorized_pubkeys(
            self.validator, self.authorized_keys
        )

        require_approval(commit, self.threshold, authorized_pubkeys)

    def prepare_merge_msg(self, commit_msg_file: str) -> None:
        merge_head = Commit(self.repo.references["MERGE_HEAD"].resolve().target)
        approvals = get_approvals_detached(merge_head, self.repo)
        if len(approvals) < self.threshold:
            raise CliFail(
                f"Found {len(approvals)} approvals for {merge_head.hash} "
                f"but expected {self.threshold}."
            )

        with open(commit_msg_file, "a") as f:
            f.writelines(
                ["\n", "\n", f"Including commit: {merge_head.hash}\n", "Approvals:\n"]
            )
            for approval in approvals:
                f.write(approval + "\n")


def require_approval(commit: Commit, threshold: int, authorized_pubkeys: list[Pubkey]):
    """
    Verifies that the parent from the merged branch contains a threshold of approvals.
    These approvals are detached signatures included in the merge commit message.

    Note: The second parent of a merge request will always be the parent
    of the merged branch.
    """
    parents = commit.parents

    if len(parents) <= 1:
        # Require approval can only be applied on pull requests
        raise RuleViolation("Commit does not originate from a pull request")

    # The merge head
    require_approval_for = parents[-1]

    signatures = get_approvals_in_commit(commit)

    valid_approvals = 0
    approvers = set()

    for signature in signatures:
        for pubkey in authorized_pubkeys:
            if (
                pubkey.verify_signature(signature, require_approval_for.object)
                and pubkey.fingerprint not in approvers
            ):
                valid_approvals = valid_approvals + 1
                approvers.add(pubkey.fingerprint)

    if valid_approvals < threshold:
        raise RuleViolation(
            f"Commit {commit.hash} has {valid_approvals} valid approvals "
            f" but expected {threshold}"
        )


def get_approvals_in_commit(commit: Commit):
    commit_msg = commit.message

    pattern = re.compile(
        r"-----BEGIN (PGP|SSH) SIGNATURE-----(.*?)-----END (PGP|SSH) SIGNATURE-----",
        re.DOTALL,
    )
    signature_blobs = []
    for match in re.finditer(pattern, commit_msg):
        signature_blobs.append(match.group(0))

    return signature_blobs


def get_approvals_detached(commit: Commit, repo: Repository) -> list[str]:
    try:
        cmd("git", "fetch", "origin", "refs/signatures/*:refs/signatures/*")
    except Exception:
        logger.warn("Failed to fetch from 'refs/signatures'")

    references = repo.references.iterator()
    approvals = []
    for ref in references:
        if re.match(f"refs/signatures/{commit.hash}/*", ref.name):
            object = repo.get(ref.target)
            if isinstance(object, Blob):
                approvals.append(object.data.decode())
    return approvals


def setup() -> dict:
    repo = Repository(get_root())
    add_public_keys_interactive(repo)
    pubkeys = load_public_key_files(name_only=True)
    authorized_keys = add_authorized_keys_interactive(pubkeys)
    threshold = click_prompt("Enter the approval threshold", type=int)

    return {
        "require_approval": {"authorized_keys": authorized_keys, "threshold": threshold}
    }
