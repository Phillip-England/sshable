package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// The temporary account is privileged only during onboarding. Its password is
// never saved locally or passed on a command line; OpenSSH prompts for it.
const inviteServerScript = `set -eu
login_user=$1
temp_user=$2
password=$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')
[ "${#password}" -eq 48 ] || { echo "Could not generate password" >&2; exit 1; }
config=/etc/ssh/sshd_config
[ "$login_user" != root ] || { echo "A non-root key login is required" >&2; exit 1; }
[ -f "$config" ] || { echo "OpenSSH server config not found" >&2; exit 1; }
command -v systemctl >/dev/null 2>&1 || { echo "systemd is required for automatic expiry" >&2; exit 1; }
command -v flock >/dev/null 2>&1 || { echo "flock is required for safe expiry" >&2; exit 1; }
command -v useradd >/dev/null 2>&1 && command -v userdel >/dev/null 2>&1 && command -v chpasswd >/dev/null 2>&1 || { echo "Linux user management tools are required" >&2; exit 1; }
exec 9>/run/sshable-ssh.lock
flock -x 9
sshd=$(command -v sshd || true)
[ -n "$sshd" ] || sshd=/usr/sbin/sshd
[ -x "$sshd" ] || { echo "sshd not found" >&2; exit 1; }
# Only one invitation at a time. Refuse foreign Match blocks and nested Includes.
if grep -q '^# sshable temporary access begin ' "$config"; then
  echo "An invitation is already active; secure the server or wait for expiry" >&2; exit 1
fi
if ! awk 'tolower($1)=="include" && (NF!=2 || $2!="/etc/ssh/sshd_config.d/*.conf") { exit 1 }' "$config"; then
  echo "Custom SSH Include found" >&2; exit 1
fi
for file in "$config" /etc/ssh/sshd_config.d/*.conf; do
  [ -f "$file" ] || continue
  if grep -iEq '^[[:space:]]*Match[[:space:]]' "$file"; then
    echo "Match rules found; review SSH configuration manually" >&2; exit 1
  fi
  if [ "$file" != "$config" ] && grep -iEq '^[[:space:]]*Include[[:space:]]' "$file"; then
    echo "Nested SSH Include found" >&2; exit 1
  fi
done
if id "$temp_user" >/dev/null 2>&1; then
  echo "Temporary account already exists" >&2; exit 1
fi
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
backup=$(mktemp /etc/ssh/sshd_config.sshable-invite.XXXXXX)
cp -p "$config" "$backup"
expiry=/var/lib/sshable/expire-$temp_user
service=/etc/systemd/system/sshable-expire-$temp_user.service
timer=/etc/systemd/system/sshable-expire-$temp_user.timer
created=no
changed=no
committed=no
cleanup() {
  if [ "$committed" != yes ]; then
    if [ "$changed" = yes ]; then cp -p "$backup" "$config" && reload_sshd || true; fi
    if [ "$created" = yes ]; then userdel -r "$temp_user" 2>/dev/null || true; fi
    systemctl disable --now "sshable-expire-$temp_user.timer" >/dev/null 2>&1 || true
    rm -f "$expiry" "$service" "$timer"
    systemctl daemon-reload >/dev/null 2>&1 || true
  fi
  rm -f "$backup"
}
trap cleanup EXIT
useradd -m -s /bin/sh "$temp_user"
created=yes
printf '%s:%s\n' "$temp_user" "$password" | chpasswd
# sudo uses the same randomly generated password for one-time key installation.
if getent group sudo >/dev/null 2>&1; then
  usermod -aG sudo "$temp_user"
elif getent group wheel >/dev/null 2>&1; then
  usermod -aG wheel "$temp_user"
else
  echo "No sudo or wheel group found" >&2; exit 1
fi
cat >> "$config" <<EOF

# sshable temporary access begin $temp_user
Match User $temp_user
    PasswordAuthentication yes
    AuthenticationMethods password
    KbdInteractiveAuthentication no
# sshable temporary access end $temp_user
EOF
changed=yes
"$sshd" -t -f "$config"
effective=$("$sshd" -T -f "$config" -C "user=$temp_user,host=localhost,addr=127.0.0.1")
printf '%s\n' "$effective" | grep -qx 'passwordauthentication yes'
printf '%s\n' "$effective" | grep -qx 'authenticationmethods password'
normal=$("$sshd" -T -f "$config" -C "user=$login_user,host=localhost,addr=127.0.0.1")
printf '%s\n' "$normal" | grep -qx 'passwordauthentication no'
printf '%s\n' "$normal" | grep -qx 'authenticationmethods publickey'
reload_sshd || { echo "Could not reload SSH" >&2; exit 1; }

mkdir -p /var/lib/sshable
chmod 700 /var/lib/sshable
cat > "$expiry" <<EOF
#!/bin/sh
set -eu
exec 9>/run/sshable-ssh.lock
flock -x 9
usermod -L $temp_user 2>/dev/null || true
config=/etc/ssh/sshd_config
if grep -q '^# sshable temporary access begin $temp_user\$' "\$config"; then
  sed '/^# sshable temporary access begin $temp_user\$/,/^# sshable temporary access end $temp_user\$/d' "\$config" > "\$config.sshable-expiring"
  chmod --reference="\$config" "\$config.sshable-expiring"
  /usr/sbin/sshd -t -f "\$config.sshable-expiring"
  mv "\$config.sshable-expiring" "\$config"
  systemctl reload sshd 2>/dev/null || systemctl reload ssh
fi
userdel -r $temp_user 2>/dev/null || true
rm -f "$expiry"
systemctl disable --now sshable-expire-$temp_user.timer >/dev/null 2>&1 || true
rm -f "$service" "$timer"
systemctl daemon-reload
EOF
chmod 700 "$expiry"
cat > "$service" <<EOF
[Unit]
Description=Expire sshable temporary account $temp_user
[Service]
Type=oneshot
ExecStart=/bin/sh $expiry
EOF
expiry_time=$(date -u -d '+20 minutes' '+%Y-%m-%d %H:%M:%S UTC')
cat > "$timer" <<EOF
[Unit]
Description=Expire sshable temporary account $temp_user after 20 minutes
[Timer]
OnCalendar=$expiry_time
Persistent=true
Unit=sshable-expire-$temp_user.service
[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
if ! systemctl enable --now "sshable-expire-$temp_user.timer" >/dev/null; then
  rm -f "$expiry" "$service" "$timer"
  systemctl daemon-reload
  echo "Could not schedule automatic expiry" >&2
  exit 1
fi
committed=yes
echo "Temporary SSH login expires in 20 minutes."
echo "Temporary password: $password"
`

const joinInstallScript = `set -eu
target=$1
key=$2
[ "$target" != root ] || exit 1
entry=$(getent passwd "$target") || { echo "Target account does not exist" >&2; exit 1; }
home=$(printf '%s\n' "$entry" | cut -d: -f6)
group=$(id -gn "$target")
[ -n "$home" ] && [ -d "$home" ] || { echo "Target home directory is missing" >&2; exit 1; }
install -d -m 700 -o "$target" -g "$group" "$home/.ssh"
touch "$home/.ssh/authorized_keys"
chown "$target:$group" "$home/.ssh/authorized_keys"
chmod 600 "$home/.ssh/authorized_keys"
grep -qxF "$key" "$home/.ssh/authorized_keys" || printf '%s\n' "$key" >> "$home/.ssh/authorized_keys"
`

func randomInvite() (string, error) {
	b := make([]byte, 5)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "sshable_" + hex.EncodeToString(b), nil
}

func inviteCommand(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: sshable invite NAME")
	}
	h, err := lookup(args[0])
	if err != nil {
		return err
	}
	if h.User == "root" {
		return errors.New("invite requires a non-root saved account with key and sudo access")
	}
	user, err := randomInvite()
	if err != nil {
		return err
	}
	if err := runSSH(keyOnlySSHArgs(h), os.Stdin); err != nil {
		return fmt.Errorf("key login failed; invitation was not created: %w", err)
	}
	remote := "sudo sh -c " + shellQuote(inviteServerScript) + " sh " + shellQuote(h.User) + " " + shellQuote(user)
	if err := runSSH(append(keyOnlyInteractiveSSHArgs(h), remote), os.Stdin); err != nil {
		return fmt.Errorf("invitation creation failed: %w", err)
	}
	fmt.Printf("Temporary username: %s\n", user)
	fmt.Printf("On the new client, run: sshable join --port %d NEW_NAME %s@%s %s\n", h.Port, h.User, h.Host, user)
	fmt.Println("Then run: sshable secure NEW_NAME. The temporary account is deleted by secure or automatically after 20 minutes.")
	if info, err := os.Stdin.Stat(); err == nil && info.Mode()&os.ModeCharDevice != 0 {
		fmt.Print("Record the credentials, then press Enter to continue...")
		_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
	}
	return nil
}

func keyOnlyInteractiveSSHArgs(h host) []string {
	return append([]string{"-tt"}, sshArgs(h)...)
}

func joinCommand(args []string) error {
	flags := flag.NewFlagSet("join", flag.ContinueOnError)
	port := flags.Int("port", 22, "SSH port")
	identity := flags.String("identity", "", "private key path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 3 {
		return errors.New("usage: sshable join [--port PORT] [--identity PATH] NAME USER@HOST TEMP_USER")
	}
	name := flags.Arg(0)
	if !namePattern.MatchString(name) {
		return errors.New("invalid saved host name")
	}
	user, hostname, err := parseTarget(flags.Arg(1))
	if err != nil {
		return err
	}
	if user == "root" {
		return errors.New("join requires a non-root permanent account")
	}
	tempUser := flags.Arg(2)
	if !strings.HasPrefix(tempUser, "sshable_") || !userPattern.MatchString(tempUser) {
		return errors.New("invalid temporary username")
	}
	if *port < 1 || *port > 65535 {
		return errors.New("port must be between 1 and 65535")
	}
	if *identity == "" {
		*identity, err = defaultIdentity()
	} else {
		*identity, err = expandPath(*identity)
	}
	if err != nil {
		return err
	}
	c, err := loadConfig()
	if err != nil {
		return err
	}
	if _, exists := c.Hosts[name]; exists {
		return fmt.Errorf("%q already exists", name)
	}
	if err := ensureKey(*identity, false); err != nil {
		return err
	}
	pub, err := os.ReadFile(*identity + ".pub")
	if err != nil {
		return err
	}
	if !validPublicKey(pub) {
		return errors.New("public key is invalid")
	}
	h := host{User: user, Host: hostname, Port: *port, Identity: *identity}
	remote := "sudo sh -c " + shellQuote(joinInstallScript) + " sh " + shellQuote(user) + " " + shellQuote(strings.TrimSpace(string(pub)))
	sshArgs := []string{"-tt", "-p", strconv.Itoa(*port), "-o", "IdentitiesOnly=yes", "-o", "ControlPath=none", "-o", "PreferredAuthentications=password", "-o", "PubkeyAuthentication=no", "-o", "KbdInteractiveAuthentication=no", "--", tempUser + "@" + hostname, remote}
	fmt.Println("Enter the temporary password for SSH, then again if sudo asks for it.")
	if err := runSSH(sshArgs, os.Stdin); err != nil {
		return fmt.Errorf("could not install public key: %w", err)
	}
	if err := runSSH(keyOnlySSHArgs(h), os.Stdin); err != nil {
		return fmt.Errorf("key installation finished, but permanent login failed; invitation remains active: %w", err)
	}
	c.Hosts[name] = h
	if err := saveConfig(c); err != nil {
		return err
	}
	fmt.Printf("Saved %s with verified key access. Run 'sshable secure %s' now to delete the temporary account.\n", name, name)
	return nil
}
