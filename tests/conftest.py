import pytest
import os

from gitbark.objects import BarkRules
from gitbark.project import Project
from gitbark.core import BARK_RULES_BRANCH
from gitbark.git import Repository
from gitbark.util import cmd

from pytest_gitbark.util import (
    on_dir,
    on_branch,
    write_bark_rules,
    dump,
    restore_from_dump,
)


@pytest.fixture(autouse=True, scope="session")
def module_path():
    return os.getcwd()


@pytest.fixture(scope="session")
def repo_installed_dump(
    repo_dump: tuple[Repository, str], tmp_path_factory, module_path, bark_cli
):
    repo, _ = repo_dump

    cmd("git", "commit", "-m", "Initial commit", "--allow-empty", cwd=repo._path)

    bootstrap_main = repo.head

    branch_rule = {
        "bootstrap": bootstrap_main.hash.hex(),
        "refs": [{"pattern": "refs/heads/main"}],
    }
    bark_rules = BarkRules([], project=[branch_rule])

    with on_branch(repo, BARK_RULES_BRANCH, True):
        write_bark_rules(repo, bark_rules, module_path)
        cmd("git", "commit", "-m", "Add initial bark rules", cwd=repo._path)

    with on_dir(repo._path):
        bark_cli("install", input="y")

    project = Project(repo._path)
    project.install_modules(module_path.encode())

    dump_path = tmp_path_factory.mktemp("dump")
    dump(repo, dump_path)
    return repo, dump_path


@pytest.fixture(scope="session")
def repo_installed(repo_installed_dump: tuple[Repository, str]):
    repo, dump_path = repo_installed_dump
    restore_from_dump(repo, dump_path)
    return repo
