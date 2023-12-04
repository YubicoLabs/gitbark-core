from gitbark.git import Repository
from gitbark.util import cmd

from pytest_gitbark.util import (
    verify_rules,
    verify_action,
    on_dir,
    write_commit_rules,
    dump,
    restore_from_dump,
)

from .util import configure_ssh, Key

from typing import Callable
import pytest
import shutil
import os


@pytest.fixture(autouse=True, scope="session")
def create_gpg_home():
    gnupg_dir = f"{os.getcwd()}/.gnupg"
    os.environ["GNUPGHOME"] = gnupg_dir
    yield gnupg_dir
    shutil.rmtree(gnupg_dir)


@pytest.fixture(autouse=True, scope="session")
def create_ssh_home():
    ssh_dir = f"{os.getcwd()}/.ssh"
    os.makedirs(ssh_dir)
    yield ssh_dir
    shutil.rmtree(ssh_dir)


@pytest.fixture(autouse=True, scope="session")
def alice_pgp_key(create_gpg_home):
    return Key.create_pgp_key("RSA", "1024", "Alice PGP", "alice@pgp.com")


@pytest.fixture(autouse=True, scope="session")
def bob_pgp_key(create_gpg_home):
    return Key.create_pgp_key("RSA", "1024", "Bob PGP", "bob@pgp.com")


@pytest.fixture(autouse=True, scope="session")
def eve_pgp_key(create_gpg_home):
    return Key.create_pgp_key("RSA", "1024", "Eve PGP", "eve@pgp.com")


@pytest.fixture(autouse=True, scope="session")
def alice_ssh_key(create_ssh_home):
    return Key.create_ssh_key(create_ssh_home, "ed25519", "alice", "alice@ssh.com")


@pytest.fixture(autouse=True, scope="session")
def bob_ssh_key(create_ssh_home):
    return Key.create_ssh_key(create_ssh_home, "ed25519", "bob", "bob@ssh.com")


@pytest.fixture(autouse=True, scope="session")
def eve_ssh_key(create_ssh_home):
    return Key.create_ssh_key(create_ssh_home, "ed25519", "eve", "eve@ssh.com")


@pytest.fixture(scope="session")
def repo_signatures_dump(
    repo_installed_dump: tuple[Repository, str],
    tmp_path_factory,
    alice_pgp_key: Key,
    bob_pgp_key: Key,
    alice_ssh_key: Key,
    bob_ssh_key: Key,
):
    repo, dump_path = repo_installed_dump
    restore_from_dump(repo, dump_path)

    with on_dir(repo._path):
        alice_pgp_key.add_to_repo("alice.asc")
        bob_pgp_key.add_to_repo("bob.asc")
        alice_ssh_key.add_to_repo("alice.pub")
        bob_ssh_key.add_to_repo("bob.pub")

    cmd("git", "add", ".", cwd=repo._path)

    commit_rules = {
        "rules": [
            {
                "require_signature": {
                    "authorized_keys": ["alice.asc", "bob.asc", "alice.pub", "bob.pub"]
                }
            }
        ]
    }

    write_commit_rules(repo, commit_rules)
    cmd(
        "git",
        "commit",
        "-m",
        "Require signature",
        f"--gpg-sign={alice_pgp_key.identifier}",
        cwd=repo._path,
    )

    dump_path = tmp_path_factory.mktemp("dump")
    dump(repo, dump_path)
    return repo, dump_path


@pytest.fixture(scope="function")
def repo_signatures(repo_signatures_dump: tuple[Repository, str]):
    repo, dump_path = repo_signatures_dump
    restore_from_dump(repo, dump_path)
    return repo


def test_commit_unsigned(repo_signatures: Repository):
    action: Callable[[Repository], None] = lambda repo: cmd(
        "git", "commit", "-m", "Untrusted", "--allow-empty", cwd=repo._path
    )
    verify_action(repo=repo_signatures, passes=False, action=action)


def test_commit_untrusted_gpg(repo_signatures: Repository, eve_pgp_key):
    action: Callable[[Repository], None] = lambda repo: cmd(
        "git",
        "commit",
        "-m",
        "Untrusted",
        "--allow-empty",
        f"--gpg-sign={eve_pgp_key.identifier}",
        cwd=repo._path,
    )
    verify_action(repo=repo_signatures, passes=False, action=action)


def test_commit_trusted(repo_signatures: Repository, alice_pgp_key):
    action: Callable[[Repository], None] = lambda repo: cmd(
        "git",
        "commit",
        "-m",
        "Trusted",
        "--allow-empty",
        "--author='Alice <alice@pgp.com>'",
        f"--gpg-sign={alice_pgp_key.identifier}",
        cwd=repo._path,
    )
    verify_action(repo=repo_signatures, passes=True, action=action)


def test_commit_untrusted_ssh(repo_signatures: Repository, eve_ssh_key):
    configure_ssh(repo_signatures, eve_ssh_key)
    action: Callable[[Repository], None] = lambda repo: cmd(
        "git", "commit", "-m", "Untrusted", "--allow-empty", "-S", cwd=repo._path
    )
    verify_action(repo=repo_signatures, passes=False, action=action)


def test_commit_trusted_ssh(repo_signatures: Repository, alice_ssh_key):
    configure_ssh(repo_signatures, alice_ssh_key)
    action: Callable[[Repository], None] = lambda repo: cmd(
        "git",
        "commit",
        "-m",
        "Trusted",
        "--allow-empty",
        "--author='Alice <alice@ssh.com>'",
        "-S",
        cwd=repo._path,
    )
    verify_action(repo=repo_signatures, passes=True, action=action)
