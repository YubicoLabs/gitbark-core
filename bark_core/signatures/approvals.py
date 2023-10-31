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
from gitbark.rule import BranchRule, RuleViolation
from gitbark.util import cmd

from hashlib import sha256
import logging
import os

logger = logging.getLogger(__name__)


class RequireApproval(BranchRule):
    """Requires merge commits to include approvals."""

    def _parse_args(self, args):
        self.authors = set(args["authorized_authors"])
        self.threshold = int(args["threshold"])

    def validate(self, commit: Commit, branch: str):
        approvals = {p for p in commit.parents if p.tree_hash == commit.tree_hash}
        parents = {p for p in commit.parents if p not in approvals}
        authors = {a.author[1] for a in approvals}

        # Need at least <threshold> approved authors
        valid_approvals = len(self.authors.intersection(authors))
        if valid_approvals < self.threshold:
            raise RuleViolation(
                f"Commit {commit.hash.hex()} has {valid_approvals} valid approvals "
                f" but expected {self.threshold}"
            )

        # All approvals must be valid
        for a in approvals:
            if not self.cache.get(a):
                raise RuleViolation(f"Approval {a.hash.hex()} is not itself valid")

        # All approvals must use same parents
        first = approvals.pop()
        for a in approvals:
            if a.parents != first.parents:
                raise RuleViolation("All approvals do not have the same parents")

        # Merge may not add additional parents
        unapproved = parents.difference(set(first.parents))
        if unapproved:
            raise RuleViolation(
                "Commit adds unapproved parents: "
                + ", ".join(u.hash.hex() for u in unapproved)
            )


def base_ref(source_commit_hash: str, target_branch: str) -> str:
    return f"refs/approvals/{source_commit_hash}/{target_branch}"


def merge_id(commit: Commit) -> str:
    return sha256(
        b"".join(p.hash for p in commit.parents) + commit.tree_hash
    ).hexdigest()


def approval_ref_base(commit: Commit, target_branch: str) -> str:
    mid = merge_id(commit)
    return f"refs/approvals/{target_branch}/{mid}/"


def create_request(commit: Commit, target_branch: str):
    ref_base = approval_ref_base(commit, target_branch)
    ref = f"{ref_base}{os.urandom(8).hex()}"
    r = commit._Commit__repo
    r.create_reference(ref, r.branches.get(target_branch).target)
    r.checkout(ref)
    cmd("git", "merge", "--no-ff", commit.hash.hex())
    # TODO: commit needs to be verified!


def add_approval(commit: Commit, target_branch: str):
    ref_base = approval_ref_base(commit, target_branch)
    ref = f"{ref_base}{os.urandom(8).hex()}"
    r = commit._Commit__repo
    parents = [p.hash.hex() for p in commit.parents]
    parents_args: list = sum([["-p", p] for p in parents], [])
    c_id = cmd(
        "git", "commit-tree", commit.tree_hash.hex(), "-m", "Approved ", *parents_args
    )[0]
    r.create_reference(ref, c_id)
    r.checkout(ref)
    cmd("git", "commit", "--amend")
    # TODO: commit needs to be verified!


def create_merge(commit: Commit, target_branch: str):
    ref_base = approval_ref_base(commit, target_branch)
    r = commit._Commit__repo
    approvals = [
        ref.target.hex
        for ref in r.references.iterator()
        if ref.name.startswith(ref_base)
    ]
    branch_parent = commit.parents[0].hash.hex()
    parents = [branch_parent] + approvals
    parents_args: list = sum([["-p", p] for p in parents], [])
    # Does not sign!
    print(
        "git",
        "commit-tree",
        commit.tree_hash.hex(),
        "-m",
        "Approved merge",
        *parents_args,
    )
