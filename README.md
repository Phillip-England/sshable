# sshable

`sshable` saves SSH connections and helps install your public key on a remote server. It uses your installed OpenSSH tools for host verification and password or key passphrase prompts.

## Install and launch

Requires Go 1.22 or newer and OpenSSH on the client. From this folder, run:

```sh
make install
sshable serve
```

`make install` builds the CLI with its embedded web client and installs it in Go's bin directory (`GOBIN`, or the first `GOPATH` entry's `bin` directory). Make sure that directory is on your `PATH`. To install elsewhere, run `make install BINDIR=/your/bin/directory`.

`sshable serve` opens the web client in your browser. It listens only on `127.0.0.1` and uses the same saved connections as the CLI. Leave the command running while you work; Ctrl+C stops it. Use `sshable serve --no-open --port 8080` to choose a local port without launching a browser. The HTML, JavaScript, and CSS are embedded in the executable.

Open a saved connection and use **Manage connection** to rename or delete it. Deleting a saved connection leaves its local key files and server access intact.

Use **Connect to server** on a saved connection to open an interactive SSH console near the top of its page. It uses the saved private key and SSH port. Type directly in the console, select output to copy it with **Copy selection** or your keyboard shortcut, and paste with **Paste** or your keyboard shortcut. **Hide** keeps the connection running; **Show console** returns to it. Use `exit` or **Disconnect** when finished; the console closes automatically after a successful disconnect. The CLI equivalent is `sshable connect NAME`.

For each server, the page guides you through saving a connection, creating or using a local key, installing its public key, testing key login, creating a regular sudo user when starting as root, enabling key-only SSH and Fail2ban, and auditing the final state. SSH, sudo, host fingerprint, and key passphrase prompts appear in the page's live session. Verify a new host fingerprint against your server provider before accepting it. The generated sudo password for a new account appears once in that session; record it before closing the session.

If a server no longer accepts this device's key, use **Install this device's key** while password login still works. If passwords are already disabled, paste this device's **public** key into another authorized client's page, or use your server provider console. There is no safe remote recovery path when no authorized login remains. The app does not copy private keys between devices.

To add a second client, either generate a key on that client and paste its public key into the existing client's **Authorize public key** form, or use **Invite another client** on the existing client and **Join a server** on the new one. The invitation temporarily enables password login for one random account for up to 20 minutes. Run **Enable key-only SSH and Fail2ban** from the new client after joining to remove the invitation immediately. Each client keeps its own private key and saved connection list.

Keep your server provider console available while changing SSH policy. The final audit checks the effective OpenSSH settings for root and the regular user and checks the Fail2ban `sshd` jail. It does not test every other server account or firewall rule. The guided server scripts support conventional Linux OpenSSH systems as described below.

## Headless CLI setup

Every web workflow has a CLI command, so you can set up and manage connections from a terminal without a GUI. The remote account needs an SSH server and an existing login method, usually a password. For a regular account:

```sh
sshable add work alice@server.example.com
sshable copy-id work
sshable test work
sshable secure work
sshable audit work
```

`add` creates an Ed25519 key pair on your computer if needed and saves the connection. `copy-id` logs into the remote account with its existing login method, usually a password, and adds your public key to `~/.ssh/authorized_keys`. `connect` uses the saved private key and does not fall back to a server password. A key passphrase, if set, unlocks the private key on your computer.

The private key stays on your computer. The public key is installed on the server account. OpenSSH manages the server's own host key.

If you installed this client's key under `root` by mistake, remove it using a saved non-root connection with sudo access:

```sh
sshable revoke-key --user root work
```

The command removes only the public key matching `work`'s local identity from root's `authorized_keys`; other keys remain. If you still have a saved working root connection, `sshable revoke-key rootbox` removes that connection's key from root directly. Keep another working login before removing the key you use to connect. The saved connection and local key files remain until you remove them separately.

## Secure a server after key setup

`sshable secure work` is a separate, explicit action. It first tests key login, then uses the remote account's `sudo` access to set `PermitRootLogin no`, `PasswordAuthentication no`, `KbdInteractiveAuthentication no`, and `AuthenticationMethods publickey` for the OpenSSH server. It validates the configuration, reloads SSH, and tests key login again. It saves a backup of `/etc/ssh/sshd_config` on the server and restores it if validation or reload fails. It then installs Fail2ban, enables an `sshd` jail for the saved SSH port, and verifies that the jail is running. The jail uses the systemd journal and bans an address for one hour after five failures within ten minutes. Use a non-root account with working key login and sudo access. This changes SSH login for every account on that server; it does not remove account passwords or change console login.

If your saved connection is `root@HOST`, a successful key login as root is not enough: `secure` would disable that same login. Use `provision` to create a regular sudo account, install the root connection's public key for it, verify its key login, and save a second connection:

```sh
sshable add --port PORT --identity /path/to/existing/private_key rootbox root@HOST
sshable provision rootbox work USER
sshable secure work
```

If the root connection is already saved, start with `sshable provision ROOT_NAME NEW_NAME NEW_USER`. Use your actual SSH port, key path, username, and host. If the root key's `.pub` file is missing when you add it, sshable recovers the public half from the private key. The server needs Linux user tools and a `sudo` or `wheel` group. The command generates a password for the new account and displays it once; record it for later sudo prompts. It does not change SSH server settings. Keep the root connection available until `provision` confirms the new key login. You can check saved usernames with `sshable list`.

Each client keeps its own private key. After a server is secured, another client can create its own key with `sshable add` or `sshable keygen`. Send **only its `.pub` file** to a client that already has key access, then run `sshable authorize-key work /path/to/other-client.pub` there. This appends the new public key to the saved server account's `authorized_keys` without replacing existing keys. The new client can then connect with its own private key. To give it access to a different server account, save and authorize that account separately.

### Add a client without transferring a public key

On an existing client with key and sudo access, run `sshable invite work`. It creates a random temporary username and 48-character password and prints both. The password is accepted over SSH only for that account; root and other accounts remain key-only. Share the credentials privately. The account has sudo access during onboarding and expires after 20 minutes, including if the server reboots. The server must use Linux user tools and systemd for this workflow.

On the new client, run the printed `sshable join --port PORT NEW_NAME USER@HOST TEMP_USER` command. Enter the temporary password for SSH and sudo. `join` creates a local key, installs its public half on the permanent `USER` account, tests key login, and saves that permanent connection. Then run `sshable secure NEW_NAME` on the new client. It validates key login, restores server-wide key-only SSH, and deletes the temporary account. The invitation also expires automatically if `secure` is not run in time. Do not use `add` with the temporary username: its account is intended to disappear.

The `secure` command supports conventional OpenSSH servers using `/etc/ssh/sshd_config` and a `systemctl` or `service` reload. It refuses configurations with `Match` rules or custom nested `Include` files because those can change authentication for selected users. Automatic Fail2ban setup requires systemd and an `apt-get` or `dnf` package manager. It writes `/etc/fail2ban/jail.d/zz-sshable-sshd.local` and restores its previous contents if validation or service startup fails. If Fail2ban setup fails, the SSH hardening remains in place; fix the server issue and rerun `secure`. Keep server console access available while applying SSH policy changes.

If `secure` fails, its final error names the failed step and includes the server's diagnostic. A failed initial key test leaves server settings unchanged. A failed SSH configuration check or reload triggers restoration from the backup named in the output. If the key test after reload fails, use the server console to inspect `/etc/ssh/sshd_config` and its sshable backup. A Fail2ban failure leaves SSH key-only access in place; fix the reported package, configuration, or service issue and rerun `secure`.

## Commands

```text
sshable serve [--port PORT] [--no-open]
sshable help
sshable keygen [--path PATH] [--no-passphrase]
sshable add [--port PORT] [--identity PATH] NAME USER@HOST
sshable list
sshable show-key NAME
sshable test NAME
sshable copy-id NAME
sshable authorize-key NAME PUBLIC_KEY_FILE  # use - to read a key from stdin
sshable revoke-key [--user USER] NAME
sshable secure NAME
sshable provision ROOT_NAME NEW_NAME NEW_USER
sshable invite NAME
sshable join [--port PORT] [--identity PATH] NAME USER@HOST TEMP_USER
sshable audit NAME
sshable connect NAME [-- REMOTE_COMMAND...]
sshable remove NAME
sshable rename OLD_NAME NEW_NAME
```

Saved hosts live in your OS user config directory under `sshable/hosts.json` with owner-only permissions. `show-key` prints only the public key, which you can share with another authorized client. `remove` deletes a saved host entry, leaving key files and server access in place. Running `sshable` with no arguments shows CLI help.

The embedded browser terminal uses xterm.js 6.0.0 and @xterm/addon-fit 0.11.0. Their MIT licenses are included in `web/vendor/`.
