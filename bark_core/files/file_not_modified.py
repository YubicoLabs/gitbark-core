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

from pygit2 import Repository
import re


class FileNotModified(Rule):
    """Prevents modification to specific files."""

    def _parse_args(self, args):
        self.pattern = args["pattern"]

    def validate(self, commit: Commit) -> bool:
        validate_file_not_modified(commit, self.validator, self.pattern, self.repo)


def validate_file_not_modified(
    commit: Commit,
    validator: Commit,
    pattern: str,
    repo: Repository,
):
    files_modified = get_files_modified(commit, validator, repo)
    file_matches = list(filter(lambda f: re.match(pattern, f), files_modified))

    if len(file_matches) > 0:
        # Commit modifies locked file
        files = ", ".join(file_matches)
        raise RuleViolation(f"Commit modified locked file(s): {files}")


def get_files_modified(commit: Commit, validator: Commit, repo: Repository):
    diff = repo.diff(commit.hash, validator.hash)
    return [delta.new_file.path for delta in diff.deltas]
