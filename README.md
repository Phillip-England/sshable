# sshable

`sshable` is a small Go CLI for saving SSH connections and setting up public-key access. It uses your installed OpenSSH `ssh` and `ssh-keygen` programs, so password prompts, host verification, and SSH configuration work as they normally do.

## Install

Requires Go 1.22 or newer and OpenSSH (`ssh` and `ssh-keygen`). Install on any machine where you want to run the CLI:

```sh
go install .
```

From another directory, install with `go install sshable` only after publishing this module under an importable module path. Until then, clone this repository and run `go install .` from its root, or build a binary with `go build -o sshable .`.

The remote machine must already have a working SSH server (`sshd`) and an account you can log into. `sshable` does not install or configure `sshd`.

## First connection

On the server, while logged in as the account you plan to use:

```sh
sshable server init
```

This creates `~/.ssh/authorized_keys` and sets the expected permissions. If you do not have `sshable` installed on the server, the client workflow still works when `sshd` permits that account to log in and write to its home directory.

On your client:

```sh
sshable add work alice@server.example.com
sshable copy-id work
sshable connect work
```

`add` creates an Ed25519 key at `~/.ssh/sshable/id_ed25519` if needed, then stores the connection. `ssh-keygen` asks for a passphrase when creating it. `copy-id` logs in using your current SSH authentication (usually a password the first time) and appends the public key to the remote account's `authorized_keys` if it is not already there. OpenSSH asks you to verify an unknown server's host key; check its fingerprint with your server administrator before accepting it.

You can connect with a password without installing a key: run `sshable connect work` after `add`. If the server allows password authentication, OpenSSH will prompt for it.

## Commands

```text
sshable keygen [--path PATH] [--no-passphrase]
sshable add [--port PORT] [--identity PATH] NAME USER@HOST
sshable list
sshable connect NAME [-- REMOTE_COMMAND...]
sshable copy-id NAME
sshable remove NAME
sshable server init
sshable server authorize PUBLIC_KEY_FILE
sshable server keygen [--path PATH] [--no-passphrase]
```

Examples:

```sh
sshable add --port 2222 --identity ~/.ssh/work_ed25519 work alice@server.example.com
sshable connect work -- uptime
sshable list
sshable remove work
```

`server authorize` is useful if you already have a public key file on the server, for example `sshable server authorize /tmp/alice.pub`. `server keygen` creates an SSH identity on the server for connections *from* that machine; it does not replace the host keys used by `sshd`. Private keys should stay on the machine where they were created. To allow a client in, install its **public** key with `copy-id` or `server authorize`.

Host entries are stored as JSON in your OS user config directory under `sshable/hosts.json` with owner-only permissions. `remove` deletes a saved entry, not its key files or the server's authorization. Keys are shared by default across saved hosts; use `--identity` when you want a separate key for a host. `--no-passphrase` is available for noninteractive key generation, but the default passphrase prompt is recommended.
