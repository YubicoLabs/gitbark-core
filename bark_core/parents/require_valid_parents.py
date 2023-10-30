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
from gitbark.project import Cache
from gitbark.rule import CommitRule, RuleViolation

import click


class RequireValidParents(CommitRule):
    """Specifies whether non-valid parents should be allowed."""

    def _parse_args(self, args):
        self.allow_explicit = args.get("allow_explicit", False)

    def validate(self, commit: Commit):
        cache = self.cache
        validate_invalid_parents(commit, cache, self.allow_explicit)


def validate_invalid_parents(commit: Commit, cache: Cache, allow_explicit: bool):
    parents = commit.parents
    invalid_parents = []

    for parent in parents:
        value = cache.get(parent.hash)
        if value and not value.valid:
            invalid_parents.append(parent)

    if len(invalid_parents) == 0:
        return

    if len(invalid_parents) > 0 and not allow_explicit:
        raise RuleViolation("Commit has invalid parents")

    invalid_parent_hashes = [parent.hash for parent in invalid_parents]
    commit_msg = commit.message
    for hash in invalid_parent_hashes:
        if hash not in commit_msg:
            raise RuleViolation("Commit has invalid parents")


def setup():
    allow_explicit = click.confirm(
        "Do you want to allow non-valid parents if their hashes are included in the "
        "commit message?"
    )
    if allow_explicit:
        return {"require_valid_parents": {"allow_explicit": allow_explicit}}
    else:
        return {"require_valid_parents": None}
