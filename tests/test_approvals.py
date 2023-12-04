from bark_core.approvals import list_requests

from gitbark.git import Repository
from gitbark.objects import BarkRules
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

import pytest

APPROVER_1 = "test1@test.com"
APPROVER_2 = "test2@test.com"
TARGET_BRANCH = "main"
FEATURE_BRANCH = "feat"


def approve_merge_request(repo: Repository, m_id: str, approver: str, bark_cli):
    cmd("git", "config", "user.email", approver, cwd=repo._path)
    with on_dir(repo._path):
        bark_cli("approvals", "approve", m_id, input=f"{approver} approves!")


def create_merge_request(repo: Repository, approver: str, branch: str, bark_cli):
    # Create feat branch
    with on_branch(repo, branch):
        cmd("git", "config", "user.email", approver, cwd=repo._path)
        cmd("git", "commit", "-m", "Feature.", "--allow-empty", cwd=repo._path)

    with uninstall_hooks(repo):
        cmd("git", "config", "user.email", approver, cwd=repo._path)
        cmd(
            "git",
            "merge",
            "--no-ff",
            branch,
            "-m",
            f"Merge {branch}",
            cwd=repo._path,
        )

    with on_dir(repo._path):
        bark_cli("approvals", "create")


@pytest.fixture(scope="session")
def repo_approvals_dump(
    repo_installed_dump: tuple[Repository, str], tmp_path_factory, bark_cli
):
    repo, dump_path = repo_installed_dump
    restore_from_dump(repo, dump_path)

    bootstrap_main = repo.head

    branch_rule = {
        "bootstrap": bootstrap_main.hash.hex(),
        "refs": [
            {
                "pattern": "refs/heads/main",
                "rules": [
                    {
                        "require_approval": {
                            "threshold": 2,
                            "authorized_authors": [APPROVER_1, APPROVER_2],
                        }
                    }
                ],
            }
        ],
    }

    bark_rules = BarkRules([], project=[branch_rule])

    with on_branch(repo, BARK_RULES_BRANCH, True):
        write_bark_rules(repo, bark_rules)
        cmd("git", "commit", "-m", "Add require approval", cwd=repo._path)

    dump_path = tmp_path_factory.mktemp("dump")
    dump(repo, dump_path)
    return repo, dump_path


@pytest.fixture(scope="session")
def repo_merge_request_dump(
    repo_approvals_dump: tuple[Repository, str], tmp_path_factory, bark_cli
):
    repo, dump_path = repo_approvals_dump
    restore_from_dump(repo, dump_path)

    create_merge_request(repo, APPROVER_1, FEATURE_BRANCH, bark_cli)

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


def test_create_merge_request_with_hooks(repo_approvals: Repository, bark_cli):
    with on_branch(repo_approvals, FEATURE_BRANCH):
        cmd("git", "config", "user.email", APPROVER_1, cwd=repo_approvals._path)
        cmd(
            "git", "commit", "-m", "Feature.", "--allow-empty", cwd=repo_approvals._path
        )
    # Should fail because of branch rule violation
    with pytest.raises(Exception):
        cmd(
            "git",
            "merge",
            "--no-ff",
            FEATURE_BRANCH,
            "-m",
            f"Merge {FEATURE_BRANCH}",
            cwd=repo_approvals._path,
        )

    # Create merge request
    cmd("git", "config", "user.email", APPROVER_1, cwd=repo_approvals._path)
    with on_dir(repo_approvals._path):
        bark_cli("approvals", "create")

    requests = list_requests(repo_approvals.references, repo_approvals.branch).get(
        repo_approvals.branch, {}
    )
    m_id = list(requests.keys())[0]
    merge_request_commit, _ = repo_approvals.resolve(requests[m_id][0])

    # Assert merge request has correct parents
    expected_parents = [repo_approvals.head]
    with on_branch(repo_approvals, FEATURE_BRANCH):
        expected_parents.append(repo_approvals.head)

    assert set(merge_request_commit.parents) == set(expected_parents)


def test_merge_not_sufficient_approvals(repo_merge_request: Repository):
    def action(repo: Repository):
        with on_branch(repo, FEATURE_BRANCH):
            cmd("git", "config", "user.email", APPROVER_1, cwd=repo._path)
            cmd("git", "commit", "-m", "Feature.", "--allow-empty", cwd=repo._path)
        cmd(
            "git",
            "merge",
            "--no-ff",
            FEATURE_BRANCH,
            "-m",
            f"Merge {FEATURE_BRANCH}",
            cwd=repo._path,
        )

    verify_action(repo=repo_merge_request, passes=False, action=action)


def test_approve_merge_request(repo_merge_request: Repository, bark_cli):
    requests = list_requests(
        repo_merge_request.references, repo_merge_request.branch
    ).get(repo_merge_request.branch, {})
    m_id = list(requests.keys())[0]

    approve_merge_request(repo_merge_request, m_id, APPROVER_2, bark_cli)
    requests = list_requests(
        repo_merge_request.references, repo_merge_request.branch
    ).get(repo_merge_request.branch, {})
    approval_commit, _ = repo_merge_request.resolve(requests[m_id][1])

    # Assert approval commit has same parents as merge request
    merge_request_commit, _ = repo_merge_request.resolve(requests[m_id][0])

    assert set(approval_commit.parents) == set(merge_request_commit.parents)


def test_merge_request(repo_merge_request: Repository, bark_cli):
    requests = list_requests(
        repo_merge_request.references, repo_merge_request.branch
    ).get(repo_merge_request.branch, {})
    m_id = list(requests.keys())[0]

    pre_head = repo_merge_request.head

    approve_merge_request(repo_merge_request, m_id, APPROVER_2, bark_cli)
    requests = list_requests(
        repo_merge_request.references, repo_merge_request.branch
    ).get(repo_merge_request.branch, {})
    approval_commits = [repo_merge_request.resolve(ref)[0] for ref in requests[m_id]]
    with on_dir(repo_merge_request._path):
        bark_cli("approvals", "merge", m_id)

    octo_merge = repo_merge_request.head

    # The new head should point to something else
    assert pre_head != repo_merge_request.head

    # Assert approval commits included in final merge
    for a in approval_commits:
        assert a in octo_merge.parents

    # Assert approvals are cleaned up after merge
    requests = list_requests(
        repo_merge_request.references, repo_merge_request.branch
    ).get(repo_merge_request.branch, {})
    assert m_id not in requests


def test_clean_requests(repo_approvals: Repository, bark_cli):
    for i in range(3):
        create_merge_request(
            repo_approvals, APPROVER_1, f"{FEATURE_BRANCH}-{i}", bark_cli
        )

    requests = list_requests(repo_approvals.references, repo_approvals.branch).get(
        repo_approvals.branch, {}
    )
    assert len(requests.values()) == 3

    with on_dir(repo_approvals._path):
        bark_cli("approvals", "clean", "-f")

    requests = list_requests(repo_approvals.references, repo_approvals.branch).get(
        repo_approvals.branch, {}
    )
    assert not requests
