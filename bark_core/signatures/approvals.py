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
from gitbark.util import cmd

from pygit2 import Blob
from dataclasses import dataclass
from typing import Optional
import abc
import logging
import subprocess

logger = logging.getLogger(__name__)


class SigningKey(abc.ABC):
    identifier: str

    @abc.abstractmethod
    def sign(self, message: bytes) -> bytes:
        """Signs the given message"""


class PgpSigningKey(SigningKey):
    def __init__(self, key_id: str):
        self.identifier = key_id

    def sign(self, message: bytes) -> bytes:
        return subprocess.Popen(
            ["gpg", "-u", self.identifier, "--armor", "--detach-sign", "-"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
        ).communicate(input=message)[0]


class SshSigningKey(SigningKey):
    def __init__(self, ssh_key_path: str):
        self._ssh_key_path = ssh_key_path
        output = subprocess.check_output(
            ["ssh-keygen", "-l", "-f", ssh_key_path], text=True
        ).rstrip()
        self.identifier = output.split(":")[1].split()[0]

    def sign(self, message: bytes) -> bytes:
        return subprocess.Popen(
            ["ssh-keygen", "-Y", "sign", "-f", self._ssh_key_path, "-n", "git"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
        ).communicate(input=message)[0]


def base_ref(source_commit_hash: str, target_branch: str) -> str:
    return f"refs/approvals/{source_commit_hash}/{target_branch}"


@dataclass
class ApprovalRequest:
    merge_commit: Commit
    target_branch: str

    @classmethod
    def create(cls, merge_commit: Commit, target_branch: str) -> "ApprovalRequest":
        c = merge_commit._Commit__object
        source_commit_hash = c.parents[1].id.hex
        merge_ref = f"{base_ref(source_commit_hash, target_branch)}/merge"
        r = merge_commit._Commit__repo
        r.create_reference(merge_ref, merge_commit.hash)
        return cls(merge_commit, target_branch)

    @classmethod
    def lookup(
        cls, source_commit: Commit, target_branch: str
    ) -> Optional["ApprovalRequest"]:
        ref = base_ref(source_commit.hash, target_branch)
        r = source_commit._Commit__repo
        try:
            cmd("git", "fetch", "origin", f"{ref}/*:{ref}/*")
        except Exception:
            logger.warn(f"Failed to fetch from '{ref}/*'")
        try:
            merge_hash = r.lookup_reference(f"{ref}/merge").target.hex
            merge_commit = Commit(merge_hash, r)
            return cls(merge_commit, target_branch)
        except KeyError:
            return None

    @property
    def message(self) -> bytes:
        c = self.merge_commit._Commit__object
        return b"".join(p.raw for p in c.parent_ids) + c.tree_id.raw

    @property
    def base_ref(self) -> str:
        c = self.merge_commit._Commit__object
        source_commit_hash = c.parents[1].id.hex
        return base_ref(source_commit_hash, self.target_branch)

    @property
    def tree_ref(self) -> str:
        c = self.merge_commit._Commit__object
        return f"{self.base_ref}/{c.tree_id.hex}"

    @property
    def approvals(self) -> list[str]:
        sig_refs = f"{self.tree_ref}/"
        try:
            cmd("git", "fetch", "origin", f"{sig_refs}*:{sig_refs}*")
        except Exception:
            logger.warn(f"Failed to fetch from '{sig_refs}*'")

        r = self.merge_commit._Commit__repo
        references = r.references.iterator()
        approvals = []
        for ref in references:
            if ref.name.startswith(sig_refs):
                target = r.get(ref.target)
                if isinstance(target, Blob):
                    approvals.append(target.data.decode())
        return approvals

    def approve(self, key: SigningKey) -> None:
        signature = key.sign(self.message)
        r = self.merge_commit._Commit__repo
        blob_id = r.create_blob(signature)
        r.create_reference(f"{self.tree_ref}/{key.identifier}", blob_id)

    def is_stale(self) -> bool:
        r = self.merge_commit._Commit__repo
        head_id = r.branches.get(self.target_branch).target
        c = self.merge_commit._Commit__object
        return head_id not in c.parent_ids

    def checkout(self) -> None:
        cmd("git", "checkout", f"{self.base_ref}/merge")

    def merge(self) -> None:
        if self.is_stale():
            raise ValueError("Cannot merge stale ApprovalRequest")

        self.checkout()
        message = "\n\n".join(
            [self.merge_commit.message, "Approvals:"] + self.approvals
        )
        subprocess.Popen(
            ["git", "commit", "--amend", "-F", "-"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
        ).communicate(input=message.encode())
        r = self.merge_commit._Commit__repo
        commit_id = r.head.target
        cmd("git", "checkout", self.target_branch)
        cmd("git", "reset", "--hard", commit_id.hex)
