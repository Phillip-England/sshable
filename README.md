# sshable

`sshable` saves SSH connections and helps install your public key on a remote server. It uses your installed OpenSSH tools for host verification and password or key passphrase prompts.

## Install

Requires Go 1.22 or newer and OpenSSH on the client. The remote account needs an SSH server and an existing login method, usually a password.

```sh
go install .
```

## Setup

Run `sshable` for the terminal interface, or use these commands:

```sh
sshable add work alice@server.example.com
sshable copy-id work
sshable connect work
```

`add` creates an Ed25519 key pair on your computer if needed and saves the connection. `copy-id` logs into the remote account with its existing login method, usually a password, and adds your public key to `~/.ssh/authorized_keys`. `connect` uses the saved private key and does not fall back to a server password. A key passphrase, if set, unlocks the private key on your computer.

The private key stays on your computer. The public key is installed on the server account. OpenSSH manages the server's own host key; sshable does not change server SSH settings.

## Commands

```text
sshable [tui]
sshable keygen [--path PATH] [--no-passphrase]
sshable add [--port PORT] [--identity PATH] NAME USER@HOST
sshable list
sshable copy-id NAME
sshable connect NAME [-- REMOTE_COMMAND...]
sshable remove NAME
```

Saved hosts live in your OS user config directory under `sshable/hosts.json` with owner-only permissions. `remove` deletes a saved host entry, leaving key files and server access in place.
