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
from gitbark.cli.util import CliFail, click_prompt

from hashlib import sha256
from typing import Optional, Tuple
import click
import logging
import os

logger = logging.getLogger(__name__)


MERGE_HEAD = os.path.join(".git", "MERGE_HEAD")
ORIG_HEAD = os.path.join(".git", "ORIG_HEAD")
FAIL_HEAD = os.path.join(".git", "bark", "FAIL_HEAD")
APPROVALS = "refs/approvals/"
ID_LEN = 16


def get_author_id() -> str:
    email = cmd("git", "config", "user.email")[0]
    return sha256(email.encode()).hexdigest()[:ID_LEN]


def get_merge_id(commit: Commit) -> str:
    return sha256(
        b"".join(p.hash for p in commit.parents) + commit.tree_hash
    ).hexdigest()[:ID_LEN]


def approval_ref_base(commit: Commit, target_branch: str) -> str:
    return f"{APPROVALS}{target_branch}/{get_merge_id(commit)}/"


def parse_ref(ref: str) -> Tuple[str, str, str]:
    if not ref.startswith(APPROVALS):
        raise ValueError("Non-approval ref provided")
    branch, m_id, a_id = ref[len(APPROVALS) :].rsplit("/", 2)
    return branch, m_id, a_id


def fetch_approvals() -> None:
    pass  # cmd("git", "fetch", "origin", f"{APPROVALS}*:{APPROVALS}*")


def push_approvals() -> None:
    pass  # cmd("git", "push", "origin", f"{APPROVALS}*:{APPROVALS}*")


def list_approvals(references: dict[str, Commit], branch: str) -> dict[str, list[str]]:
    approvals: dict[str, list[str]] = {}
    base_ref = f"{APPROVALS}{branch}/"
    for ref in references:
        if ref.startswith(base_ref):
            m_id = parse_ref(ref)[1]
            approvals.setdefault(m_id, []).append(ref)
    return approvals


def create_request(commit: Commit, target_branch: str):
    """Takes a merge commit and moves it to a special approval ref"""
    # TODO: Assert target_branch currently points to commit
    ref_base = approval_ref_base(commit, target_branch)
    ref = f"{ref_base}{get_author_id()}"
    # Create the new ref
    cmd("git", "update-ref", ref, commit.hash.hex())
    # Reset the old one
    cmd(
        "git", "update-ref", f"refs/heads/{target_branch}", commit.parents[0].hash.hex()
    )
    cmd("git", "reset", "--hard")
    # TODO: commit needs to be verified!


def add_approval(
    commit: Commit, target_branch: str, message: str = "I approve this message"
):
    """Takes an existing approval commit, adds own approval to it"""
    ref_base = approval_ref_base(commit, target_branch)
    ref = f"{ref_base}{get_author_id()}"
    parents = [p.hash.hex() for p in commit.parents]
    parents_args: list = sum([["-p", p] for p in parents], [])
    c_id = cmd(
        "git", "commit-tree", commit.tree_hash.hex(), "-m", message, *parents_args
    )[0]
    cmd("git", "checkout", c_id)
    # Add signature, if configured
    cmd("git", "commit", "--amend", "--no-edit")
    c_id = cmd("git", "rev-parse", "HEAD")[0]
    cmd("git", "update-ref", ref, c_id)
    # TODO: commit needs to be verified!
    cmd("git", "checkout", target_branch)  # Restore prev HEAD


def create_merge(
    commit: Commit, target_branch: str, references: dict[str, Commit]
) -> None:
    """Creates a merge commit over all approvals"""
    ref_base = approval_ref_base(commit, target_branch)
    approvals = [
        commit.hash.hex()
        for ref, commit in references.items()
        if ref.startswith(ref_base)
    ]
    branch_parent = commit.parents[0].hash.hex()
    parents = [branch_parent] + approvals
    parents_args: list = sum([["-p", p] for p in parents], [])
    # Does not sign!
    c_id = cmd(
        "git",
        "commit-tree",
        commit.tree_hash.hex(),
        "-m",
        f"Approved merge of {get_merge_id(commit)}.",
        *parents_args,
    )[0]
    cmd("git", "checkout", c_id)
    # Add signature, if configured
    cmd("git", "commit", "--amend", "--no-edit")
    c_id = cmd("git", "rev-parse", "HEAD")[0]
    cmd("git", "update-ref", f"refs/heads/{target_branch}", c_id)
    cmd("git", "checkout", target_branch)  # Restore prev HEAD
    # TODO: Delete approvals


def is_merging(commit: Commit) -> bool:
    """True if the commit was a merge rejected by bark."""
    if not all(os.path.exists(f) for f in (MERGE_HEAD, ORIG_HEAD)):
        return False
    with open(ORIG_HEAD) as f:
        parents = [f.read().strip()]
    with open(MERGE_HEAD) as f:
        parents.extend([p.strip() for p in f.readlines()])
    if parents != [p.hash.hex() for p in commit.parents]:
        return False
    tree_hash = cmd("git", "write-tree")[0]
    if commit.tree_hash.hex() != tree_hash:
        return False
    return True


class RequireApproval(BranchRule):
    """Requires merge commits to include approvals."""

    def _parse_args(self, args):
        self.authors = set(args["authorized_authors"])
        self.threshold = int(args["threshold"])

    def validate(self, commit: Commit, branch: str):
        # Must be a merge commit
        if len(commit.parents) < 2:
            raise RuleViolation("Not an approved merge commit")

        # Might be a normal merge that we'll want to create a request for
        if is_merging(commit):
            raise RuleViolation(
                "Merge must be approved. Run 'bark approve --create' "
                "to create a merge request."
            )

        approvals = {p for p in commit.parents if p.tree_hash == commit.tree_hash}
        parents = {p for p in commit.parents if p not in approvals}
        authors = {a.author[1] for a in approvals}

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

        # Need at least <threshold> approved authors
        valid_approvals = len(self.authors.intersection(authors))
        if valid_approvals < self.threshold:
            raise RuleViolation(
                f"Commit {commit.hash.hex()} has {valid_approvals} valid approvals "
                f"but expected {self.threshold}"
            )

    @staticmethod
    def setup():
        authors = click_prompt(
            "Enter the authorized approvers as a list of email addresses, "
            "using space as a separator"
        ).split()
        threshold = click_prompt("Enter the number of required approvals", type=int)

        return {
            "require_approval": {
                "threshold": threshold,
                "authorized_authors": authors,
            }
        }


@click.command()
@click.pass_context
@click.argument("merge_id", required=False)
@click.option(
    "--create",
    is_flag=True,
    default=False,
    help="Create a merge request from a merge commit.",
)
@click.option(
    "--checkout",
    is_flag=True,
    default=False,
    help="Checkout the request in a detached state.",
)
@click.option(
    "--merge",
    is_flag=True,
    default=False,
    help="Finalize a merge request by merging it to the target branch.",
)
def approve(ctx, merge_id: Optional[str], create: bool, checkout: bool, merge) -> None:
    """Approve a merge request.

    This will create an approval for creating a merge commit on a branch, which
    is stored under `refs/approvals/<target_branch>/<merge_id>/`.

    \b
    MERGE_ID the merge request ID to approve
    """

    project = ctx.obj["project"]
    repo = project.repo

    branch = cmd("git", "branch", "--show-current")[0]
    if not branch:
        # Check if an approval ref is checked out
        line = cmd("git", "log", "-n1", "--oneline", "--decorate")[0]
        line = line[line.index("(") + 1 : line.index(")")]
        refs = [r for r in line.split(", ") if r.startswith(APPROVALS)]
        approvals = {parse_ref(r)[:2] for r in refs}
        if len(approvals) != 1:
            raise CliFail("Target branch must be checked out")
        branch, m_id = approvals.pop()
        if merge_id and merge_id != m_id:
            raise CliFail("Explicit MERGE_ID given that doesn't match HEAD")
        merge_id = m_id

    fetch_approvals()
    requests = list_approvals(repo.references, branch)

    if merge_id:
        matched = [a for a in requests if a.startswith(merge_id)]
        if len(matched) > 1:
            raise CliFail("MERGE_ID matches multiple requests")
        elif len(matched) == 0:
            raise CliFail("Merge request not found")
        merge_id = matched[0]

    if checkout:
        # Check out the merge tree for testing
        if not merge_id:
            raise CliFail("--checkout requires MERGE_ID")
        cmd("git", "checkout", requests[merge_id][0])
    elif create:
        # Create a new merge request from a merge commit
        if merge_id:
            raise CliFail("--create should not be called with a MERGE_ID")

        # Use HEAD by default
        commit = repo.head

        # Failed verify may contain merge commit
        if os.path.exists(FAIL_HEAD):
            with open(FAIL_HEAD) as f:
                fail_hash = bytes.fromhex(f.read())
            fail_commit = Commit(fail_hash, repo)
            if is_merging(fail_commit):
                # Clean up merge in progress, we already have the completed commit
                cmd("git", "merge", "--abort")
                commit = fail_commit

        # TODO: Check for "dirty"
        if os.path.exists(MERGE_HEAD):
            raise CliFail("Git merge in progress, cannot create merge request")

        # Make sure it's a merge request
        if len(commit.parents) < 2:
            raise CliFail("Cannot create merge request from non merge commit")

        click.echo("Creating merge request...")
        create_request(commit, branch)
        push_approvals()
        click.echo(f"Merge request created: {get_merge_id(commit)}")
    elif merge:
        if not merge_id:
            raise CliFail("--merge requires MERGE_ID")
        c_id = cmd("git", "show-ref", requests[merge_id][0])[0].split()[0]
        commit = Commit(bytes.fromhex(c_id), repo)
        click.echo("Finalizing merge request...")
        create_merge(commit, branch, repo.references)
        click.echo("Merge request completed")
    elif merge_id:
        # Approve a request
        # TODO: Prevent multiple approvals by same author
        c_id = cmd("git", "show-ref", requests[merge_id][0])[0].split()[0]
        commit = Commit(bytes.fromhex(c_id), repo)
        message = click_prompt("Approval message")
        click.echo("Creating approval commit...")
        add_approval(commit, branch, message)
        push_approvals()
        click.echo("Merge request approved")
    else:
        # List requests
        click.echo("Available merge requests:")
        # TODO: How do we know how many approvals are needed?
        for m_id in requests:
            n_approvals = len(requests[m_id])
            click.echo(f"{m_id} ({n_approvals}/? approvals)")