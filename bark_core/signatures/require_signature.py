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

from .util import (
    Pubkey,
    get_authorized_pubkeys,
    verify_signature_bulk,
    add_public_keys_interactive,
    add_authorized_keys_interactive,
    load_public_key_files
)

from pygit2 import Repository


class RequireSignature(Rule):
    """Requires the commit to be signed."""

    def _parse_args(self, args):
        self.authorized_keys = args["authorized_keys"]

    def validate(self, commit: Commit):
        authorized_pubkeys = get_authorized_pubkeys(
            self.validator, self.authorized_keys
        )

        require_signature(commit, authorized_pubkeys)


def require_signature(commit: Commit, authorized_pubkeys: list[Pubkey]):
    signature, commit_object = commit.signature

    if not signature:
        # No signature
        raise RuleViolation("Commit was not signed")

    if len(authorized_pubkeys) == 0:
        # No pubkeys specified
        raise RuleViolation("No public keys registered")

    if not verify_signature_bulk(authorized_pubkeys, signature, commit_object):
        raise RuleViolation("Commit was signed by untrusted key")
    

def init(repo: Repository) -> dict:
    add_public_keys_interactive(repo)
    pubkeys = load_public_key_files(name_only=True)
    authorized_keys = add_authorized_keys_interactive(pubkeys)
    
    return {"require_signature": {"authorized_keys": authorized_keys}}
