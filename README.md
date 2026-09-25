# sshable

`sshable` is a small Go CLI for saving SSH connections and setting up public-key access. It uses your installed OpenSSH `ssh` and `ssh-keygen` programs, so password prompts, host verification, and SSH configuration work as they normally do.

Run `sshable` in a terminal to open the guided interface. It shows your saved servers, the exact key file paths for each server, and the next step for installing or testing a public key. The commands below remain available for scripts and experienced users; run `sshable help` to see them.

## Keys in plain language

`ssh-keygen` makes two files **on the client**, the computer you connect *from*. By default, sshable uses `~/.ssh/sshable/id_ed25519` for the **private key** and `~/.ssh/sshable/id_ed25519.pub` for the **public key**. The private key stays on the client. The public key is the one you can share with a server. If you choose `--identity`, sshable shows and uses that path instead.

`sshable copy-id NAME` logs into the server using an existing method, usually the server account password, and adds the public key to that account's `~/.ssh/authorized_keys`. It does not copy the private key. Afterward, `sshable connect NAME` can use the key. A **key passphrase** protects the private key on your computer; it is different from the **server account password**. The server's **host key**, which OpenSSH asks you to verify on first connection, is a third kind of key that identifies the server.

In the interface, select a server and press `t` to test a login that only offers your public key. A successful test proves key login works for that account. The interface cannot tell whether the server still allows password login for other clients.

To allow only public-key login, configure `sshd` **on the server** after a successful key test. The interface's `s` screen walks through the settings and the check to perform before closing your existing session. `sshable` does not change server authentication settings automatically.

## Install

Requires Go 1.22 or newer and OpenSSH (`ssh` and `ssh-keygen`). Install on any machine where you want to run the CLI:

```sh
go install .
```

From another directory, install with `go install sshable` only after publishing this module under an importable module path. Until then, clone this repository and run `go install .` from its root, or build a binary with `go build -o sshable .`.

The remote machine must already have a working SSH server (`sshd`) and an account you can log into. `sshable` does not install or configure `sshd`.

## First connection

On your client, run `sshable` for the guided flow or use these commands:

```sh
sshable add work alice@server.example.com
sshable copy-id work
sshable connect work
```

`add` creates an Ed25519 key at `~/.ssh/sshable/id_ed25519` if needed, then stores the connection. `ssh-keygen` asks for a passphrase when creating it. `copy-id` logs in using your current SSH authentication (usually a password the first time) and appends the public key to the remote account's `authorized_keys` if it is not already there. OpenSSH asks you to verify an unknown server's host key; check its fingerprint with your server administrator before accepting it.

If you are already logged into the server account and want to prepare its key file manually, run `sshable server init` there. This creates `~/.ssh/authorized_keys` with the expected permissions. The client flow works without installing sshable on the server when `sshd` permits login and the account can write to its home directory.

You can connect with a password without installing a key: run `sshable connect work` after `add`. If the server allows password authentication, OpenSSH will prompt for it.

## Commands

```text
sshable [tui]
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
