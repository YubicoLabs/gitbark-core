from gitbark.git import Repository
from gitbark.objects import BarkRules
from gitbark.core import BARK_RULES_BRANCH
from gitbark.util import cmd

from pytest_gitbark.util import (
    write_bark_rules,
    write_commit_rules,
    on_branch,
    dump,
    restore_from_dump,
    verify_action,
)

from typing import Callable
import pytest


@pytest.fixture(scope="session")
def repo_parents_dump(
    repo_installed_dump: tuple[Repository, str], tmp_path_factory, module_path
):
    repo, dump_path = repo_installed_dump
    restore_from_dump(repo, dump_path)

    bootstrap_main = repo.head

    branch_rule = {
        "bootstrap": bootstrap_main.hash.hex(),
        "refs": [{"pattern": "refs/heads/main", "rules": ["require_fast_forward"]}],
    }

    bark_rules = BarkRules([], project=[branch_rule])

    with on_branch(repo, BARK_RULES_BRANCH, True):
        write_bark_rules(repo, bark_rules, module_path)
        cmd("git", "commit", "-m", "Add require fast forward", cwd=repo._path)

    commit_rules = {"rules": [{"max_parents": {"threshold": 1}}]}
    write_commit_rules(repo, commit_rules)
    cmd("git", "commit", "-m", "Max parents", cwd=repo._path)

    dump_path = tmp_path_factory.mktemp("dump")
    dump(repo, dump_path)
    return repo, dump_path


@pytest.fixture(scope="function")
def repo_parents(repo_parents_dump: tuple[Repository, str]):
    repo, dump_path = repo_parents_dump
    restore_from_dump(repo, dump_path)
    return repo


def test_fast_forward(repo_parents: Repository):
    action: Callable[[Repository], None] = lambda repo: cmd(
        "git", "commit", "-m", "Fast-forward", "--allow-empty", cwd=repo._path
    )
    verify_action(repo=repo_parents, passes=True, action=action)


def test_non_fast_forward(repo_parents: Repository):
    action: Callable[[Repository], None] = lambda repo: cmd(
        "git", "reset", "--hard", "HEAD^", cwd=repo._path
    )
    verify_action(repo=repo_parents, passes=False, action=action)


def test_max_parents_pass(repo_parents: Repository):
    action: Callable[[Repository], None] = lambda repo: cmd(
        "git", "commit", "-m", "One parent", "--allow-empty", cwd=repo._path
    )
    verify_action(repo=repo_parents, passes=True, action=action)


def test_max_parents_fail(repo_parents: Repository):
    with on_branch(repo_parents, "feat"):
        cmd("git", "commit", "-m", "Feature", "--allow-empty", cwd=repo_parents._path)
    action: Callable[[Repository], None] = lambda repo: cmd(
        "git", "merge", "--no-ff", "feat", "-m", "Merge feat", cwd=repo._path
    )
    verify_action(repo=repo_parents, passes=False, action=action)
