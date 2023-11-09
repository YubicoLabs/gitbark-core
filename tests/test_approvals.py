from bark_core.approvals import approval_ref_base, get_author_id, list_approvals

from gitbark.git import Repository
from gitbark.objects import BranchRuleData, BarkRules
from gitbark.core import BARK_RULES_BRANCH
from gitbark.util import cmd

from pytest_gitbark.util import (
    write_bark_rules,
    dump,
    restore_from_dump,
    verify_action,
    on_branch,
    on_dir,
    uninstall_hooks,
)

from typing import Callable
import pytest

APPROVER_1 = "test1@test.com"
APPROVER_2 = "test2@test.com"
TARGET_BRANCH = "feat"


@pytest.fixture(scope="session")
def repo_approvals_dump(repo_installed_dump: tuple[Repository, str], tmp_path_factory):
    repo, dump_path = repo_installed_dump
    restore_from_dump(repo, dump_path)

    bootstrap_main = repo.head

    with on_branch(repo, BARK_RULES_BRANCH):
        res = cmd(
            "git",
            "cat-file",
            "-p",
            f"{repo.head.hash.hex()}:.bark/requirements.txt",
            cwd=repo._path,
        )[0]
        print(res)

    branch_rule = BranchRuleData(
        pattern="main",
        bootstrap=bootstrap_main.hash.hex(),
        rules=[
            {
                "require_approval": {
                    "threshold": 2,
                    "authorized_authors": [APPROVER_1, APPROVER_2],
                }
            }
        ],
    )
    bark_rules = BarkRules(branches=[branch_rule])

    with on_branch(repo, BARK_RULES_BRANCH, True):
        write_bark_rules(repo, bark_rules)
        cmd("git", "commit", "-m", "Add require approval", cwd=repo._path)

    # Create feat branch
    with on_branch(repo, TARGET_BRANCH):
        cmd("git", "config", "user.email", APPROVER_1, cwd=repo._path)
        cmd("git", "commit", "-m", "Feature.", "--allow-empty", cwd=repo._path)

    dump_path = tmp_path_factory.mktemp("dump")
    dump(repo, dump_path)
    return repo, dump_path


@pytest.fixture(scope="session")
def repo_merge_request_dump(
    repo_approvals_dump: tuple[Repository, str], tmp_path_factory, bark_cli
):
    repo, dump_path = repo_approvals_dump
    restore_from_dump(repo, dump_path)

    with uninstall_hooks(repo):
        cmd("git", "config", "user.email", APPROVER_1, cwd=repo._path)
        cmd(
            "git",
            "merge",
            "--no-ff",
            TARGET_BRANCH,
            "-m",
            f"Merge {TARGET_BRANCH}",
            cwd=repo._path,
        )

    with on_dir(repo._path):
        bark_cli("approve", "--create")

    dump_path = tmp_path_factory.mktemp("dump")
    dump(repo, dump_path)
    return repo, dump_path


@pytest.fixture(scope="function")
def repo_approvals(repo_approvals_dump: tuple[Repository, str]):
    repo, dump_path = repo_approvals_dump
    restore_from_dump(repo, dump_path)
    return repo


@pytest.fixture(scope="function")
def repo_merge_request(repo_merge_request_dump: tuple[Repository, str]):
    repo, dump_path = repo_merge_request_dump
    restore_from_dump(repo, dump_path)
    return repo


def test_merge_no_approvals(repo_approvals: Repository):
    action: Callable[[Repository], None] = lambda repo: cmd(
        "git",
        "merge",
        "--no-ff",
        TARGET_BRANCH,
        "-m",
        f"Merge {TARGET_BRANCH}",
        cwd=repo._path,
    )
    verify_action(repo=repo_approvals, passes=False, action=action)


def test_create_merge_request(repo_approvals: Repository, bark_cli):
    with pytest.raises(Exception):
        cmd(
            "git",
            "merge",
            "--no-ff",
            TARGET_BRANCH,
            "-m",
            f"Merge {TARGET_BRANCH}",
            cwd=repo_approvals._path,
        )
    cmd("git", "config", "user.email", APPROVER_1, cwd=repo_approvals._path)
    with on_dir(repo_approvals._path):
        bark_cli("approve", "--create")


def test_approve_and_merge_request(repo_merge_request: Repository, bark_cli):
    requests = list_approvals(repo_merge_request.references, repo_merge_request.branch)
    m_id = list(requests.keys())[0]
    cmd("git", "config", "user.email", APPROVER_2, cwd=repo_merge_request._path)
    post_head = repo_merge_request.head
    with on_dir(repo_merge_request._path):
        bark_cli("approve", m_id, input=f"{APPROVER_2} approves!")
        bark_cli("approve", m_id, "--merge")

    # The new head should point to the merge commit
    assert post_head != repo_merge_request.head
