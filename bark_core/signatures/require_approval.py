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
from gitbark.rule import Rule
from gitbark.util import cmd
from gitbark.cli.util import CliFail

from .util import Pubkey, get_authorized_pubkeys

from pygit2 import Repository, Blob
import re
import logging

logger = logging.getLogger(__name__)


class RequireApproval(Rule):
    def validate(self, commit: Commit) -> bool:
        authorized_keys_pattern, threshold = (
            self.args["authorized_keys"],
            int(self.args["threshold"]),
        )
        threshold = int(threshold)
        authorized_pubkeys = get_authorized_pubkeys(
            self.validator, authorized_keys_pattern
        )

        passes_rule, violation = require_approval(commit, threshold, authorized_pubkeys)
        self.add_violation(violation)
        return passes_rule
    
    def prepare_merge_msg(self, commit_msg_file: str) -> None:
        threshold = int(self.args["threshold"])

        merge_head = Commit(
            self.repo.references["MERGE_HEAD"].resolve().target
        )
        approvals = get_approvals_detached(merge_head, self.repo)
        if len(approvals) < threshold:
            raise CliFail(
                f"Found {len(approvals)} approvals for {merge_head.hash} "
                f"but expected {threshold}."
            )
        
        with open(commit_msg_file, 'a') as f:
            f.writelines([
                "\n",
                "\n",
                f"Including commit: {merge_head.hash}\n",
                "Approvals:\n"
            ])
            for approval in approvals:
                f.write(approval + "\n")


def require_approval(commit: Commit, threshold: int, authorized_pubkeys: list[Pubkey]):
    """
    Verifies that the parent from the merged branch contains a threshold of approvals.
    These approvals are detached signatures included in the merge commit message.

    Note: The second parent of a merge request will always be the parent
    of the merged branch.
    """
    parents = commit.get_parents()
    violation = ""

    if len(parents) <= 1:
        # Require approval can only be applied on pull requests
        violation = "Commit does not originate from a pull request"
        return False, violation

    # The merge head
    require_approval_for = parents[-1]

    signatures = get_approvals_in_commit(commit)

    valid_approvals = 0
    approvers = set()

    for signature in signatures:
        for pubkey in authorized_pubkeys:
            if (
                pubkey.verify_signature(
                    signature, require_approval_for.get_commit_object()
                )
                and pubkey.fingerprint not in approvers
            ):
                valid_approvals = valid_approvals + 1
                approvers.add(pubkey.fingerprint)

    if valid_approvals < threshold:
        violation = (
            f"Commit {commit.hash} has {valid_approvals} valid approvals "
            f" but expected {threshold}"
        )
        return False, violation

    return True, violation


def get_approvals_in_commit(commit: Commit):
    commit_msg = commit.get_commit_message()

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


        


