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
from gitbark.rule import CommitRule, RuleViolation
from gitbark.cli.util import click_prompt


class MaxParents(CommitRule):
    """Specifies the maximum number of parents for a commit."""

    def _parse_args(self, args):
        self.threshold = args["threshold"]

    def validate(self, commit: Commit):
        parents = commit.parents
        if len(parents) < self.threshold:
            raise RuleViolation(
                f"Commit has {len(parents)} parent(s) but expected {self.threshold}"
            )


def setup():
    threshold = click_prompt(
        prompt="Enter the maxmimum number of parents for a commit", type=int
    )
    return {"max_parents": {"threshold": threshold}}
