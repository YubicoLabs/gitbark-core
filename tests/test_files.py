from gitbark.git import Repository
from gitbark.util import cmd

from pytest_gitbark.util import (
    write_commit_rules,
    dump,
    restore_from_dump,
    verify_action,
)

import pytest


@pytest.fixture(scope="session")
def repo_files_dump(repo_installed_dump: tuple[Repository, str], tmp_path_factory):
    repo, dump_path = repo_installed_dump
    restore_from_dump(repo, dump_path)

    commit_rules = {"rules": [{"file_not_modified": {"pattern": ["*.md"]}}]}
    write_commit_rules(repo, commit_rules)
    cmd("git", "commit", "-m", "File not modified", cwd=repo._path)

    dump_path = tmp_path_factory.mktemp("dump")
    dump(repo, dump_path)
    return repo, dump_path


@pytest.fixture(scope="function")
def repo_files(repo_files_dump: tuple[Repository, str]):
    repo, dump_path = repo_files_dump
    restore_from_dump(repo, dump_path)
    return repo


def test_modify_locked_file(repo_files: Repository):
    def action(repo: Repository):
        with open(f"{repo._path}/README.md", "w") as f:
            f.write("Test")
        cmd("git", "add", ".", cwd=repo._path)
        cmd("git", "commit", "-m", "Modify README.md", cwd=repo._path)

    verify_action(repo=repo_files, passes=False, action=action)


def test_modify_open_file(repo_files: Repository):
    def action(repo: Repository):
        with open(f"{repo._path}/test.py", "w") as f:
            f.write("Test")
        cmd("git", "add", ".", cwd=repo._path)
        cmd("git", "commit", "-m", "Modify test.py.", cwd=repo._path)

    verify_action(repo=repo_files, passes=True, action=action)
