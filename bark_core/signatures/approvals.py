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
        c = commit._Commit__object
        approvals = {p for p in c.parents if p.tree_id == c.tree_id}
        parents = {p for p in c.parents if p not in approvals}
        authors = {a.author.email for a in approvals}

        # Need at least <threshold> approved authors
        valid_approvals = len(self.authors.intersection(authors))
        if valid_approvals < self.threshold:
            raise RuleViolation(
                f"Commit {commit.hash} has {valid_approvals} valid approvals "
                f" but expected {self.threshold}"
            )

        # All approvals must be valid
        for a in approvals:
            if not self.cache.get(a.id.hex):
                raise RuleViolation(f"Approval {a.id.hex} is not itself valid")

        # All approvals must use same parents
        first = approvals.pop()
        for a in approvals:
            if a.parents != first.parents:
                print(a.parents, first.parents)
                raise RuleViolation("All approvals do not have the same parents")

        # Merge may not add additional parents
        unapproved = parents.difference(set(first.parents))
        if unapproved:
            raise RuleViolation(
                "Commit adds unapproved parents: "
                + ", ".join(u.id.hex for u in unapproved)
            )


def base_ref(source_commit_hash: str, target_branch: str) -> str:
    return f"refs/approvals/{source_commit_hash}/{target_branch}"


def merge_id(commit: Commit) -> str:
    c = commit._Commit__object
    return sha256(b"".join(p.raw for p in c.parent_ids) + c.tree_id.raw).hexdigest()


def approval_ref_base(commit: Commit, target_branch: str) -> str:
    mid = merge_id(commit)
    return f"refs/approvals/{target_branch}/{mid}/"


def create_request(commit: Commit, target_branch: str):
    ref_base = approval_ref_base(commit, target_branch)
    ref = f"{ref_base}{os.urandom(8).hex()}"
    r = commit._Commit__repo
    r.create_reference(ref, r.branches.get(target_branch).target)
    r.checkout(ref)
    cmd("git", "merge", "--no-ff", commit.hash)


def add_approval(commit: Commit, target_branch: str):
    ref_base = approval_ref_base(commit, target_branch)
    ref = f"{ref_base}{os.urandom(8).hex()}"
    r = commit._Commit__repo
    c = commit._Commit__object
    parents = [p.hex for p in c.parent_ids]
    parents_args: list = sum([["-p", p] for p in parents], [])
    c_id = r.create_commit()
    c_id = cmd("git", "commit-tree", c.tree_id.hex, "-m", "Approved ", *parents_args)[0]
    r.create_reference(ref, c_id)
    r.checkout(ref)
    cmd("git", "commit", "--amend")


def create_merge(commit: Commit, target_branch: str):
    r = commit._Commit__repo
    ref_base = approval_ref_base(commit, target_branch)
    approvals = [
        ref.target.hex
        for ref in r.references.iterator()
        if ref.name.startswith(ref_base)
    ]
    c = commit._Commit__object
    branch_parent = c.parent_ids[0].hex
    parents = [branch_parent] + approvals
    parents_args: list = sum([["-p", p] for p in parents], [])
    # Does not sign!
    print("git", "commit-tree", c.tree_id.hex, "-m", "Approved merge", *parents_args)
