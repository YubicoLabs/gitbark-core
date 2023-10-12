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

from typing import Union
import re


class FileNotModified(Rule):
    """Prevents modification to specific files."""

    def _parse_args(self, args):
        self.pattern = args["pattern"]

    def validate(self, commit: Commit) -> bool:
        validate_file_not_modified(commit, self.validator, self.pattern)


def validate_file_not_modified(
    commit: Commit,
    validator: Commit,
    patterns: Union[list[str], str],
):
    locked_files = commit.list_files(patterns)
    files_modified = validator.get_files_modified(commit)
    file_matches = locked_files.intersection(files_modified)

    if file_matches:
        # Commit modifies locked file
        files = ", ".join(file_matches)
        raise RuleViolation(f"Commit modified locked file(s): {files}")
