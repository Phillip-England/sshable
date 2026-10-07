package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// This script runs as root on a conventional OpenSSH server. It prepends the
// policy so it wins over earlier global settings, including Include files.
const secureServerScript = `set -eu
login_user=$1
config=/etc/ssh/sshd_config
[ -f "$config" ] || { echo "OpenSSH server config not found: $config" >&2; exit 1; }
[ "$login_user" != root ] || { echo "Use a non-root key login before disabling root SSH access" >&2; exit 1; }
sshd=$(command -v sshd || true)
[ -n "$sshd" ] || sshd=/usr/sbin/sshd
[ -x "$sshd" ] || { echo "sshd not found" >&2; exit 1; }
if command -v flock >/dev/null 2>&1; then
  exec 9>/run/sshable-ssh.lock
  flock -x 9
fi

# An invitation is the only Match rule sshable creates. Remove that exact
# block while preparing the hardened config, then delete its account after
# the new key login has been verified by the client.
temp_user=$(sed -n 's/^# sshable temporary access begin \(sshable_[0-9a-f]*\)$/\1/p' "$config")
if [ -n "$temp_user" ]; then
  if ! printf '%s\n' "$temp_user" | grep -Eq '^sshable_[0-9a-f]{10}$' ||
     [ "$(grep -c '^# sshable temporary access begin ' "$config")" != 1 ] ||
     ! grep -qx "# sshable temporary access end $temp_user" "$config"; then
    echo "Malformed sshable invitation; review SSH configuration manually" >&2; exit 1
  fi
fi
filtered=$(mktemp /etc/ssh/sshd_config.sshable-filtered.XXXXXX)
trap 'rm -f "$filtered"' 0
if [ -n "$temp_user" ]; then
  sed "/^# sshable temporary access begin $temp_user\$/,/^# sshable temporary access end $temp_user\$/d" "$config" > "$filtered"
else
  cp "$config" "$filtered"
fi

# Match blocks can override global authentication rules for other users.
# Refuse configurations we cannot prove are server-wide from this client.
if ! awk 'tolower($1)=="include" && (NF!=2 || $2!="/etc/ssh/sshd_config.d/*.conf") { exit 1 }' "$config"; then
  echo "Custom SSH Include found; review SSH configuration manually before securing the server" >&2
  exit 1
fi
for file in "$filtered" /etc/ssh/sshd_config.d/*.conf; do
  [ -f "$file" ] || continue
  if grep -iEq '^[[:space:]]*Match[[:space:]]' "$file"; then
    echo "Match rules found; review SSH configuration manually before securing the server" >&2
    exit 1
  fi
  if [ "$file" != "$filtered" ] && grep -iEq '^[[:space:]]*Include[[:space:]]' "$file"; then
    echo "Nested SSH Include found; review SSH configuration manually before securing the server" >&2
    exit 1
  fi
done

reload_sshd() {
  if command -v systemctl >/dev/null 2>&1; then
    systemctl reload sshd 2>/dev/null && return 0
    systemctl reload ssh 2>/dev/null && return 0
  fi
  if command -v service >/dev/null 2>&1; then
    service sshd reload 2>/dev/null && return 0
    service ssh reload 2>/dev/null && return 0
  fi
  return 1
}

backup=$(mktemp /etc/ssh/sshd_config.sshable-backup.XXXXXX)
temp=$(mktemp /etc/ssh/sshd_config.sshable-new.XXXXXX)
cp -p "$config" "$backup"
cp -p "$config" "$temp"
changed=no
committed=no
cleanup() {
  rm -f "$temp"
  rm -f "$filtered"
  if [ "$changed" = yes ] && [ "$committed" != yes ]; then
    if cp -p "$backup" "$config" && reload_sshd; then
      echo "Restored SSH configuration from $backup and reloaded SSH" >&2
    else
      echo "WARNING: Could not fully restore SSH; use the server console to restore $backup to $config and reload SSH" >&2
    fi
  fi
}
trap cleanup 0
{
  managed_prefix=$(printf '%s\n' '# Managed by sshable: key-only SSH access' \
    'PermitRootLogin no' \
    'PasswordAuthentication no' \
    'KbdInteractiveAuthentication no' \
    'PubkeyAuthentication yes' \
    'AuthenticationMethods publickey')
  printf '%s\n' "$managed_prefix"
  if [ "$(head -n 6 "$filtered")" = "$managed_prefix" ]; then
    tail -n +7 "$filtered"
  else
    cat "$filtered"
  fi
} > "$temp"
mv -f "$temp" "$config"
changed=yes
"$sshd" -t -f "$config" || { echo "OpenSSH rejected the new configuration; restoring the backup" >&2; exit 1; }
effective=$("$sshd" -T -f "$config" -C "user=$login_user,host=localhost,addr=127.0.0.1") || { echo "Could not inspect effective OpenSSH settings; restoring the backup" >&2; exit 1; }
for expected in 'permitrootlogin no' 'passwordauthentication no' 'kbdinteractiveauthentication no' 'pubkeyauthentication yes' 'authenticationmethods publickey'; do
  printf '%s\n' "$effective" | grep -qx "$expected" || { echo "OpenSSH did not apply required setting '$expected'; restoring the backup" >&2; exit 1; }
done
reload_sshd || { echo "Could not reload the SSH service" >&2; exit 1; }
committed=yes
if [ -n "$temp_user" ]; then
  userdel -r "$temp_user" || { echo "SSH was secured, but could not delete temporary account $temp_user" >&2; exit 1; }
  echo "Deleted temporary account $temp_user"
fi
echo "SSH now requires public keys; root SSH login is disabled. Backup: $backup"
`

// Install Fail2ban from the server's package manager, then manage only the
// sshd jail settings owned by sshable. The journal backend works on systems
// without a separate /var/log/auth.log or /var/log/secure.
const fail2banServerScript = `set -eu
port=$1
case "$port" in
  ''|*[!0-9]*) echo "Invalid SSH port" >&2; exit 1 ;;
esac
[ "$port" -ge 1 ] && [ "$port" -le 65535 ] || { echo "Invalid SSH port" >&2; exit 1; }
command -v systemctl >/dev/null 2>&1 || { echo "Fail2ban setup requires systemd" >&2; exit 1; }
if command -v apt-get >/dev/null 2>&1; then
  apt-get update || { echo "Could not update apt package lists; check package repositories and network access" >&2; exit 1; }
  DEBIAN_FRONTEND=noninteractive apt-get install -y fail2ban python3-systemd || { echo "Could not install Fail2ban packages with apt-get" >&2; exit 1; }
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y fail2ban python3-systemd || { echo "Could not install Fail2ban packages with dnf" >&2; exit 1; }
else
  echo "Automatic Fail2ban installation supports apt-get and dnf servers" >&2
  exit 1
fi
command -v fail2ban-client >/dev/null 2>&1 || { echo "fail2ban-client is missing after installation" >&2; exit 1; }
directory=/etc/fail2ban/jail.d
config=$directory/zz-sshable-sshd.local
mkdir -p "$directory"
backup=$(mktemp "$directory/.sshable-backup.XXXXXX")
temp=$(mktemp "$directory/.sshable-new.XXXXXX")
had_config=no
if [ -f "$config" ]; then
  cp -p "$config" "$backup"
  had_config=yes
fi
committed=no
cleanup() {
  rm -f "$temp"
  restore_failed=no
  if [ "$committed" != yes ]; then
    if [ "$had_config" = yes ]; then
      if cp -p "$backup" "$config"; then echo "Restored previous Fail2ban configuration" >&2; else restore_failed=yes; echo "WARNING: Could not restore previous Fail2ban configuration from $backup" >&2; fi
    else
      if rm -f "$config"; then echo "Removed new Fail2ban configuration" >&2; else echo "WARNING: Could not remove new Fail2ban configuration $config" >&2; fi
    fi
    systemctl restart fail2ban >/dev/null 2>&1 || echo "WARNING: Could not restart Fail2ban after rollback" >&2
  fi
  if [ "$restore_failed" != yes ]; then rm -f "$backup"; fi
}
trap cleanup EXIT
cat > "$temp" <<EOF
# Managed by sshable: protect the SSH port used by this saved connection.
[sshd]
enabled = true
filter = sshd
backend = systemd
port = $port
findtime = 10m
maxretry = 5
bantime = 1h
usedns = no
EOF
chmod 644 "$temp"
mv -f "$temp" "$config"
fail2ban-client -t || { echo "Fail2ban rejected the new SSH jail configuration; restoring previous settings" >&2; exit 1; }
systemctl enable fail2ban || { echo "Could not enable Fail2ban at boot; restoring previous settings" >&2; exit 1; }
systemctl restart fail2ban || { echo "Could not start Fail2ban; check 'systemctl status fail2ban'; restoring previous settings" >&2; exit 1; }
attempt=0
until fail2ban-client status sshd >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  [ "$attempt" -lt 5 ] || { echo "Fail2ban SSH jail did not start" >&2; exit 1; }
  sleep 1
done
committed=yes
echo "Fail2ban SSH jail is active on port $port (5 failures in 10 minutes; 1 hour ban)."
`

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}

func secureSSHArgs(h host) []string {
	args := []string{"-tt", "-p", strconv.Itoa(h.Port), "-i", h.Identity, "-o", "IdentitiesOnly=yes", "-o", "ControlPath=none", "-o", "PreferredAuthentications=publickey", "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no", "--", h.User + "@" + h.Host}
	return append(args, "sudo sh -c "+shellQuote(secureServerScript)+" sh "+shellQuote(h.User))
}

func fail2banSSHArgs(h host) []string {
	args := []string{"-tt", "-p", strconv.Itoa(h.Port), "-i", h.Identity, "-o", "IdentitiesOnly=yes", "-o", "ControlPath=none", "-o", "PreferredAuthentications=publickey", "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no", "--", h.User + "@" + h.Host}
	return append(args, "sudo sh -c "+shellQuote(fail2banServerScript)+" sh "+shellQuote(strconv.Itoa(h.Port)))
}

func secureCommand(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: sshable secure NAME")
	}
	h, err := lookup(args[0])
	if err != nil {
		return err
	}
	return secureHost(h, runSSH)
}

func secureHost(h host, run func([]string, io.Reader) error) error {
	if h.User == "root" {
		return fmt.Errorf("saved connection uses root@%s; securing SSH disables root login, including key login. Run 'sshable provision ROOT_NAME NEW_NAME NEW_USER' using this saved root connection, then 'sshable secure NEW_NAME'", h.Host)
	}
	if h.Port < 1 || h.Port > 65535 {
		return errors.New("saved SSH port must be between 1 and 65535")
	}
	fmt.Println("Testing key login before changing the server...")
	if err := run(keyOnlySSHArgs(h), os.Stdin); err != nil {
		return fmt.Errorf("key login test failed; server settings were not changed: %w", err)
	}
	fmt.Println("Updating server SSH settings. You may be asked for the account's sudo password.")
	if err := run(secureSSHArgs(h), os.Stdin); err != nil {
		return fmt.Errorf("SSH security step stopped; check the server message and SSH backup before retrying: %w", err)
	}
	fmt.Println("Testing key login after the SSH service reload...")
	if err := run(keyOnlySSHArgs(h), os.Stdin); err != nil {
		return fmt.Errorf("key login failed after reload; use your server console to inspect /etc/ssh/sshd_config and its sshable backup: %w", err)
	}
	fmt.Println("Installing and configuring Fail2ban. This may download server packages.")
	if err := run(fail2banSSHArgs(h), os.Stdin); err != nil {
		return fmt.Errorf("SSH hardening succeeded, but Fail2ban setup failed; fix the server issue and rerun secure: %v", err)
	}
	return nil
}
