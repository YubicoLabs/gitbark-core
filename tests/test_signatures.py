from gitbark.git import Repository
from gitbark.util import cmd

from pytest_gitbark.util import (
    verify_action,
    on_dir,
    write_commit_rules,
    dump,
    restore_from_dump,
)

from .util import configure_ssh, Key, random_string

from typing import Callable
import pytest
import shutil
import os

_SSH_KEYS = [
    {"type": "rsa", "size": 1024},
    {"type": "rsa", "size": 2048},
    {"type": "rsa", "size": 3072},
    {"type": "rsa", "size": 4096},
    {"type": "ecdsa", "size": 256},
    {"type": "ecdsa", "size": 384},
    {"type": "ecdsa", "size": 521},
    {"type": "ed25519"},
    {"type": "dsa"},
]


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


@pytest.fixture(scope="session")
def alice_pgp_key(create_gpg_home):
    return Key.create_pgp_key("RSA", "1024", "Alice PGP", "alice@pgp.com")


@pytest.fixture(scope="session")
def eve_pgp_key(create_gpg_home):
    return Key.create_pgp_key("RSA", "1024", "Eve PGP", "eve@pgp.com")


def idfn(fixture_value):
    id = fixture_value["type"]
    if "size" in fixture_value:
        id = id + str(fixture_value["size"])
    return id


@pytest.fixture(scope="session", params=_SSH_KEYS, ids=idfn)
def alice_ssh_key_parameterized(create_ssh_home, request):
    key_type = request.param["type"]
    size = request.param.get("size", None)
    return Key.create_ssh_key(
        create_ssh_home, key_type, size, f"alice-{key_type}-{size}", "alice@ssh.com"
    )


@pytest.fixture(scope="session")
def alice_ssh_key(create_ssh_home):
    return Key.create_ssh_key(create_ssh_home, "rsa", 1024, "alice", "alice@ssh.com")


@pytest.fixture(scope="session")
def eve_ssh_key(create_ssh_home):
    return Key.create_ssh_key(create_ssh_home, "rsa", 1024, "eve", "eve@ssh.com")


def _initialize_require_signature(repo: Repository, keys: list[Key]):
    key_names = []
    with on_dir(repo._path):
        for key in keys:
            file_name = random_string()
            key_names.append(file_name)
            key.add_to_repo(file_name)

    cmd("git", "add", ".", cwd=repo._path)

    commit_rules = {"rules": [{"require_signature": {"authorized_keys": key_names}}]}

    write_commit_rules(repo, commit_rules)
    cmd(
        "git",
        "commit",
        "-m",
        "Init require signature",
        cwd=repo._path,
    )


@pytest.fixture(scope="session")
def repo_signatures_dump(
    repo_installed_dump: tuple[Repository, str],
    tmp_path_factory,
    alice_pgp_key: Key,
    alice_ssh_key: Key,
):
    repo, dump_path = repo_installed_dump
    restore_from_dump(repo, dump_path)

    _initialize_require_signature(repo, [alice_pgp_key, alice_ssh_key])

    dump_path = tmp_path_factory.mktemp("dump")
    dump(repo, dump_path)
    return repo, dump_path


@pytest.fixture(scope="session")
def repo_signatures_parameterized_dump(
    repo_installed_dump: tuple[Repository, str],
    tmp_path_factory,
    alice_ssh_key_parameterized: Key,
):
    repo, dump_path = repo_installed_dump
    restore_from_dump(repo, dump_path)

    _initialize_require_signature(repo, [alice_ssh_key_parameterized])

    dump_path = tmp_path_factory.mktemp("dump")
    dump(repo, dump_path)
    return repo, dump_path


@pytest.fixture(scope="function")
def repo_signatures(repo_signatures_dump: tuple[Repository, str]):
    repo, dump_path = repo_signatures_dump
    restore_from_dump(repo, dump_path)
    return repo


@pytest.fixture(scope="function")
def repo_signatures_parameterized(
    repo_signatures_parameterized_dump: tuple[Repository, str]
):
    repo, dump_path = repo_signatures_parameterized_dump
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


def test_commit_wrong_email_gpg(repo_signatures: Repository, alice_pgp_key):
    action: Callable[[Repository], None] = lambda repo: cmd(
        "git",
        "commit",
        "-m",
        "Untrusted",
        "--allow-empty",
        f"--gpg-sign={alice_pgp_key.identifier}",
        "--author='Eve <eve@pgp.com>'",
        cwd=repo._path,
    )
    verify_action(repo=repo_signatures, passes=False, action=action)


def test_commit_trusted_gpg(repo_signatures: Repository, alice_pgp_key):
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


def test_commit_wrong_email_ssh(repo_signatures: Repository, alice_ssh_key):
    configure_ssh(repo_signatures, alice_ssh_key)
    action: Callable[[Repository], None] = lambda repo: cmd(
        "git",
        "commit",
        "-m",
        "Untrusted",
        "--allow-empty",
        "-S",
        "--author='Eve <eve@ssh.com>'",
        cwd=repo._path,
    )
    verify_action(repo=repo_signatures, passes=False, action=action)


def test_commit_trusted_ssh(
    repo_signatures_parameterized: Repository, alice_ssh_key_parameterized
):
    configure_ssh(repo_signatures_parameterized, alice_ssh_key_parameterized)
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
    verify_action(repo=repo_signatures_parameterized, passes=True, action=action)
