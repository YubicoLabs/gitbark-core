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

from gitbark.git import Commit, Repository, is_descendant
from gitbark.rule import RefRule, RuleViolation
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
COMMIT_INFO_LEN = 75


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


def list_requests(
    references: dict[str, Commit], branch: Optional[str] = None
) -> dict[str, dict[str, list[str]]]:
    """Returns a dictionary that maps branches to merge requests."""
    branch_to_requests: dict[str, dict[str, list[str]]] = {}
    base_ref = f"{APPROVALS}{branch}/" if branch else f"{APPROVALS}"
    for ref in references:
        if ref.startswith(base_ref):
            branch, m_id, _ = parse_ref(ref)
            branch_to_requests.setdefault(branch, {}).setdefault(m_id, []).append(ref)
    return branch_to_requests


def create_request(commit: Commit, target_branch: str):
    """Takes a merge commit and moves it to a special approval ref"""
    ref_base = approval_ref_base(commit, target_branch)
    ref = f"{ref_base}{get_author_id()}"
    # Create the new ref
    cmd("git", "update-ref", ref, commit.hash.hex())


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
    clean_approvals(commit.repo, merge_id=get_merge_id(commit))


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


def clean_approvals(
    repo: Repository,
    merge_id: Optional[str] = None,
    branch: Optional[str] = None,
    force: bool = False,
) -> None:
    """Removes approvals if already included in final merge.

    If merge_id is provided, only approvals associated with that id will be removed.
    If branch is provided, all requests on that branch will be deleted, otherwise all
    merge requests on all branches will be considered for deletion.
    """
    branch_to_requests = list_requests(repo.references)

    if merge_id:
        matched = False
        for branch, requests in branch_to_requests.items():
            if merge_id in requests:
                branch_to_requests = {branch: {merge_id: requests[merge_id]}}
                matched = True
                break
        if not matched:
            raise CliFail("Merge request not found")
    if branch and not merge_id:
        if branch in branch_to_requests:
            branch_to_requests = {branch: branch_to_requests[branch]}

    not_deleted: dict[str, list[str]] = {}
    for branch, requests in branch_to_requests.items():
        branch_head = repo.resolve(branch)[0]
        for m_id, approvals in requests.items():
            merged = all(
                is_descendant(repo.references[a], branch_head) for a in approvals
            )
            if force or merged:
                for a in approvals:
                    cmd("git", "update-ref", "-d", a)
            else:
                not_deleted.setdefault(m_id, []).extend(approvals)

    if not_deleted:
        error_message = ""
        if merge_id:
            error_message = (
                f"Merge request ({merge_id}) is not fully merged. "
                f"If you are sure you want to delete it use "
                "'bark approvals clean {merge_id}' -f."
            )
        else:
            error_message = (
                "Some merge requests are not fully merged. "
                "If you are sure you want to delete them use 'bark approvals clean -f'."
            )
        raise CliFail(error_message)


class RequireApproval(RefRule):
    """Requires commits on the ref to be *Approved*.

    An *Approved* commit is a merge commit comprising a previous commit from the target
    ref, followed by one or more *Approval* commits. All its approval commits must have
    the same tree hash as the approved commit, and must include the approved commits
    initial parent in their set of parents. All approval commits must also have the same
    set of parents, and must be valid according to their commit rules.

    Essentially, an approval commit is a "normal" merge commit, with additional
    approvals being copies of the first approval, but with different authors (and
    possible messages). The *approved* commit is then an octo-merge commit containing
    the merge target, and all approval commits.
    """

    def _parse_args(self, args):
        self.authors = set(args["authorized_authors"])
        self.threshold = int(args["threshold"])

    def validate(self, commit: Commit, ref: str):
        # Must be a merge commit
        if len(commit.parents) < 2:
            raise RuleViolation("Not an approved merge commit")

        # Might be a normal merge that we'll want to create a request for
        if is_merging(commit):
            raise RuleViolation(
                "Merge must be approved. Run 'bark approvals create' "
                "to create a merge request."
            )

        approvals = commit.parents
        old_head = approvals.pop(0)  # First parent is old head of target ref
        authors = {a.author[1] for a in approvals}

        # All approvals must have same tree hash as commit
        for a in approvals:
            if a.tree_hash != commit.tree_hash:
                raise RuleViolation(f"Approval {a.hash.hex()} has wrong tree hash")

        # All approvals must be valid
        for a in approvals:
            if not self.cache.get(a):
                raise RuleViolation(f"Approval {a.hash.hex()} is not itself valid")

        # All approvals must use same parents
        first = approvals.pop()
        for a in approvals:
            if a.parents != first.parents:
                raise RuleViolation("All approvals do not have the same parents")

        # Old head must be in approvals
        if old_head not in first.parents:
            raise RuleViolation(f"Commit adds unapproved parent: {old_head}")

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


def get_approval_context(project, merge_id):
    repo = project.repo

    branch = repo.branch
    if not branch:
        # Check if an approval ref is checked out
        approvals = {
            parse_ref(r) for r in repo.head.references if r.startswith(APPROVALS)
        }
        if len(approvals) != 1:
            raise CliFail("Target branch must be checked out")
        branch, m_id, _ = approvals.pop()
        if merge_id and merge_id != m_id:
            raise CliFail("Explicit MERGE_ID given that doesn't match HEAD")
        merge_id = m_id

    fetch_approvals()
    branch_to_requests = list_requests(repo.references, branch)

    return branch, merge_id, branch_to_requests.get(branch, {})


@click.group()
def approvals():
    """Manage approvals."""


@approvals.command()
@click.pass_context
@click.argument("merge_id", required=False)
def approve(ctx, merge_id: Optional[str]) -> None:
    """Approve a merge request.

    This will create an approval for creating a merge commit on a branch, which
    is stored under `refs/approvals/<target_branch>/<merge_id>/`.

    \b
    MERGE_ID the merge request ID to approve
    """

    project = ctx.obj["project"]
    repo = project.repo

    branch, merge_id, requests = get_approval_context(project, merge_id)

    if merge_id:
        matched = [a for a in requests if a.startswith(merge_id)]
        if len(matched) > 1:
            raise CliFail("MERGE_ID matches multiple requests")
        elif len(matched) == 0:
            raise CliFail("Merge request not found")
        merge_id = matched[0]

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
        raise CliFail("Merge request not found")


@approvals.command()
@click.pass_context
@click.argument("merge_id", required=False)
def merge(ctx, merge_id: Optional[str]):
    """Finalize a merge request by merging it to the target branch.

    \b
    MERGE_ID the merge request ID to merge
    """

    project = ctx.obj["project"]
    repo = project.repo

    branch, merge_id, requests = get_approval_context(project, merge_id)

    if merge_id:
        matched = [a for a in requests if a.startswith(merge_id)]
        if len(matched) > 1:
            raise CliFail("MERGE_ID matches multiple requests")
        elif len(matched) == 0:
            raise CliFail("Merge request not found")
        merge_id = matched[0]

        c_id = cmd("git", "show-ref", requests[merge_id][0])[0].split()[0]
        commit = Commit(bytes.fromhex(c_id), repo)
        click.echo("Finalizing merge request...")
        create_merge(commit, branch, repo.references)
        click.echo("Merge request completed")
    else:
        raise CliFail("Merge request not found")


@approvals.command()
@click.pass_context
def create(ctx):
    """Create a merge request from a merge commit."""

    project = ctx.obj["project"]
    repo = project.repo

    branch = repo.branch

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


@approvals.command()
@click.pass_context
@click.argument("merge_id")
def checkout(ctx, merge_id: str) -> None:
    """Checkout a merge request in a detached state.

    \b
    MERGE_ID the merge request ID to chekout
    """

    project = ctx.obj["project"]

    _, _, requests = get_approval_context(project, merge_id)

    cmd("git", "checkout", requests[merge_id][0])


@approvals.command(name="list")
@click.pass_context
@click.option(
    "-a",
    "--all",
    is_flag=True,
    show_default=True,
    default=False,
    help="List all merge requests.",
)
def list_merge_requests(ctx, all: bool):
    """List merge requests on branch."""

    project = ctx.obj["project"]
    repo = project.repo

    branch = repo.branch
    if not all and not branch:
        raise CliFail("Target branch must be checked out")

    fetch_approvals()
    if all:
        branch_to_requests = list_requests(repo.references)
    else:
        branch_to_requests = list_requests(repo.references, branch)

    if not branch_to_requests:
        click.echo("No merge requests found")
    else:

        for branch, requests in branch_to_requests.items():
            # List requests on branch
            click.echo(f"Found {len(requests.keys())} merge request(s) on '{branch}'")
            format_str = "{0: <{m_id_length}}  {1: <{approvals_length}}  {2}"

            click.echo(
                format_str.format(
                    "Merge ID",
                    "Approvals",
                    "Commit",
                    m_id_length=ID_LEN,
                    approvals_length=9,
                )
            )

            # TODO: How do we know how many approvals are needed?
            for m_id, approvals in requests.items():
                m_commit, _ = repo.resolve(approvals[0])
                f_commit = m_commit.parents[1]  # the commit to be merged
                f_commit_info = str(f_commit)
                click.echo(
                    format_str.format(
                        m_id,
                        len(approvals),
                        (f_commit_info[:COMMIT_INFO_LEN] + "...")
                        if len(f_commit_info) > COMMIT_INFO_LEN
                        else f_commit_info,
                        m_id_length=ID_LEN,
                        approvals_length=9,
                    )
                )
            click.echo()


@approvals.command()
@click.pass_context
@click.argument("merge_id", required=False)
@click.option(
    "-a",
    "--all",
    is_flag=True,
    show_default=True,
    default=False,
    help="Delete approval refs on all branches.",
)
@click.option(
    "-f",
    "--force",
    is_flag=True,
    show_default=True,
    default=False,
    help="Delete approval refs that have not been merged.",
)
def clean(ctx, merge_id: Optional[str], all: bool, force: bool):
    """Delete approval refs on branch.

    This will delete any approval refs that are included in a
    finalized merge.
    """

    project = ctx.obj["project"]
    repo = project.repo

    branch = repo.branch
    if not all and not branch:
        raise CliFail("Target branch must be checked out")

    if merge_id:
        clean_approvals(repo, merge_id=merge_id, force=force)
    elif all:
        clean_approvals(repo, force=force)
    else:
        clean_approvals(repo, branch=branch, force=force)
