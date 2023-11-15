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
from gitbark.rule import CommitRule, BranchRule, RuleViolation
from gitbark.util import cmd
from gitbark.project import Cache
from gitbark.cli.util import click_prompt

import click


def is_descendant(prev: Commit, new: Commit) -> bool:
    """Checks that the current tip is a descendant of the old tip"""

    _, exit_status = cmd(
        "git",
        "merge-base",
        "--is-ancestor",
        prev.hash.hex(),
        new.hash.hex(),
        check=False,
    )

    return exit_status == 0


class RequireFastForward(BranchRule):
    """Prevents force pushing (non-linear history)."""

    def validate(self, commit: Commit, branch: str):
        prev_head, _ = self.repo.resolve(branch)
        if not is_descendant(prev_head, commit):
            raise RuleViolation(f"Commit is not a descendant of {prev_head.hash.hex()}")

    @staticmethod
    def setup():
        return "require_fast_forward"


class MaxParents(CommitRule):
    """Specifies the maximum number of parents for a commit."""

    def _parse_args(self, args):
        self.threshold = args["threshold"]

    def validate(self, commit: Commit):
        parents = commit.parents
        if len(parents) > self.threshold:
            raise RuleViolation(
                f"Commit has {len(parents)} parent(s) but expected {self.threshold}"
            )

    @staticmethod
    def setup():
        threshold = click_prompt(
            prompt="Enter the maxmimum number of parents for a commit", type=int
        )
        return {"max_parents": {"threshold": threshold}}


def validate_invalid_parents(
    commit: Commit, cache: Cache, allow_explicit: bool
) -> None:
    parents = commit.parents
    invalid_parents = []

    for parent in parents:
        if not cache.get(parent):
            invalid_parents.append(parent)

    if len(invalid_parents) == 0:
        return

    if len(invalid_parents) > 0 and not allow_explicit:
        raise RuleViolation("Commit has invalid parents")

    invalid_parent_hashes = [parent.hash.hex() for parent in invalid_parents]
    commit_msg = commit.message
    for hash in invalid_parent_hashes:
        if hash not in commit_msg:
            raise RuleViolation("Commit has invalid parents")


class RequireValidParents(CommitRule):
    """Specifies whether non-valid parents should be allowed."""

    def _parse_args(self, args):
        self.allow_explicit = args and args.get("allow_explicit", False)

    def validate(self, commit: Commit):
        cache = self.cache
        validate_invalid_parents(commit, cache, self.allow_explicit)

    @staticmethod
    def setup():
        allow_explicit = click.confirm(
            "Do you want to allow non-valid parents if their hashes are included in "
            "the commit message?"
        )
        if allow_explicit:
            return {"require_valid_parents": {"allow_explicit": allow_explicit}}
        else:
            return "require_valid_parents"
