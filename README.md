# GitBark Core

A collection of useful rules and subcommands for use in
[GitBark](https://github.com/YubicoLabs/gitbark).


## Usage
To use this package in [GitBark](https://github.com/YubicoLabs/gitbark), configure your [`bark_rules.yaml`]( https://github.com/YubicoLabs/gitbark) file as follows:

```yaml
modules:
    - https://github.com/YubicoLabs/gitbark-core
```

This will import the GitBark Core package into your GitBark project, allowing you to specify rule usage in [`commit_rules.yaml`](https://github.com/YubicoLabs/gitbark), and use subcommands.


## Rules

### Signatures
This specific module exposes two rules that employs the concept of signatures to enforce authorized commits and approvals. The rules are listed down below:

* `require_signature`

  Enforce commits to be signed by a specific key.

  * Specify the set of authorized public keys with `args: [authorized_keys=<regex_pattern>]`, where `regex_pattern` is the pattern to match corresponding public key files. **NOTE**: The public key files need to be checked in to the repository in the folder `.gitbark/.pubkeys/`.
  * If a commit is not signed, or signed by a key that does not belong to the set of trusted keys, that commit will be considered invalid.

  * Example:
    ```yaml
    rules:
      - rule: require_signature
        args: [authorized_keys=alice.pub]
    ```
    This commit rule configuration specifies that only commits signed with Alice's key are authorized.

* `require_approval`

  Enforce that pull requests are approved by authorized individuals.

  * Specify the set of authorized approvers and approval threshold with `args: [authorized_keys=<regex_pattern>, threhsold=<threshold>]`.

  * Approvals in the context of this rule are signatures over the latest commit in the pull request (i.e. `MERGE_HEAD`). Approvals are done using the `approve` command, see [here](#rules).

  * During merge the rule will check if sufficient authorized approvals are in place, and if so include them in the merge commit message.

  * Example:
    ```yaml
    rules:
      - rule: require_approval
        args: [
          authorized_keys=(alice|bob).pub,
          threshold=2
        ]
    ```
    This commit rule configuration specifies that pull requests must be approved by both Alice and Bob.

### Files
This module exposes one rule that allows locking files matching a specific pattern. This rule can also be used in combination with `require_signature` to achieve file-level authorization.

* `file_not_modified`

  Enforces certain files to be unmodified.

  * Specify the set of files to match with `args: [pattern=<regex_pattern>]`, where `regex_pattern` is the pattern to match the files you wish to stay unmodified.

  * Normally this rule is used in combination with `require_signature` to achieve file-level authorization, as shown below:

    ```yaml
    rules:
      - any:
          - rule: file_not_modified
            args: [pattern=Dockerfile]
          - rule: require_signature
            args: [authorized_keys=Alice.pub]
    ```

    In this commit rule configuration, `file_not_modified` and `require_signature` are included in the `any` clause which means that they will be evaluated using OR logic (at least one of them needs to be satisfied). The resulting behavior stipulates that "Dockerfile" cannot be modified unless the commit is signed by Alice.

### Parents
This module exposes two rules that set conditions for the parents of a commit.

* `invalid_parents`

  Specify if ALL parents of a commit must be VALID (this prevents "gaps" of non-valid commits). Optionally, only allow non-valid parents if their commit hashes are included in the commit message (this makes allowing them more explicit, which prevents accidental inclusion).

  * Specify that ALL parents of a commit must be valid with `args: [allow=False]`.

  * Specify that non-valid parents are allowed if their commit hashes are included in the commit message with `args: [allow=True, require_explicit_inclusion=True]`.

* `max_parents`

  Specify the maximum number of parents a commit can have.

  * Specify the parent threshold with `args: [threhsold=<threshold>]`.


## Subcommands

* `approve`

  Add your signature approval to a commit.

  **Usage**

  ```
  Usage: bark approve [OPTIONS] [COMMIT]

  Add your signature to a commit.

  This will create a signature over a given commit object, that is stored
  under `refs/signatures`.

  COMMIT the commit to sign.

  Options:
    --gpg-key-id TEXT    The GPG key ID.
    --ssh-key-path TEXT  The path to your private SSH key.
    --help               Show this message and exit.
  ```











