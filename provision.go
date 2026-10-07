package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
)

// The public key and password arrive on stdin, never as process arguments.
const provisionServerScript = `set -eu
target=$1
[ "$target" != root ] || { echo "Choose a non-root account name" >&2; exit 1; }
command -v useradd >/dev/null 2>&1 && command -v usermod >/dev/null 2>&1 && command -v chpasswd >/dev/null 2>&1 && command -v sudo >/dev/null 2>&1 || { echo "Linux user tools and sudo are required" >&2; exit 1; }
if id "$target" >/dev/null 2>&1; then
  echo "Account $target already exists; choose another name or set it up manually" >&2
  exit 1
fi
if getent group sudo >/dev/null 2>&1; then
  sudo_group=sudo
elif getent group wheel >/dev/null 2>&1; then
  sudo_group=wheel
else
  echo "No sudo or wheel group found; configure sudo manually" >&2
  exit 1
fi
IFS= read -r key || { echo "Public key was not received" >&2; exit 1; }
[ -n "$key" ] || { echo "Public key is empty" >&2; exit 1; }
IFS= read -r password || { echo "Account password was not received" >&2; exit 1; }
[ "${#password}" -eq 48 ] || { echo "Could not generate an account password" >&2; exit 1; }
created=no
committed=no
cleanup() {
  if [ "$created" = yes ] && [ "$committed" != yes ]; then
    userdel -r "$target" 2>/dev/null || echo "WARNING: Could not remove incomplete account $target" >&2
  fi
}
trap cleanup EXIT
useradd -m -s /bin/sh "$target"
created=yes
printf '%s:%s\n' "$target" "$password" | chpasswd
usermod -aG "$sudo_group" "$target"
entry=$(getent passwd "$target")
home=$(printf '%s\n' "$entry" | cut -d: -f6)
group=$(id -gn "$target")
[ -n "$home" ] && [ -d "$home" ] || { echo "New account has no home directory" >&2; exit 1; }
install -d -m 700 -o "$target" -g "$group" "$home/.ssh"
printf '%s\n' "$key" > "$home/.ssh/authorized_keys"
chown "$target:$group" "$home/.ssh/authorized_keys"
chmod 600 "$home/.ssh/authorized_keys"
committed=yes
echo "Created $target with sudo group $sudo_group and installed its public key."
`

func showProvisionPassword(password string) {
	fmt.Println("New account password for sudo:", password)
	if info, err := os.Stdin.Stat(); err == nil && info.Mode()&os.ModeCharDevice != 0 {
		fmt.Print("Record the new sudo password, then press Enter to continue...")
		_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
	}
}

func provisionCommand(args []string) error {
	if len(args) != 3 {
		return errors.New("usage: sshable provision ROOT_NAME NEW_NAME NEW_USER")
	}
	rootName, newName, newUser := args[0], args[1], args[2]
	if !namePattern.MatchString(newName) || !userPattern.MatchString(newUser) || newUser == "root" || strings.HasPrefix(newUser, "sshable_") {
		return errors.New("choose a valid new connection name and a non-root username")
	}
	c, err := loadConfig()
	if err != nil {
		return err
	}
	root, ok := c.Hosts[rootName]
	if !ok {
		return fmt.Errorf("unknown host %q (run sshable list)", rootName)
	}
	if root.User != "root" {
		return fmt.Errorf("%q is saved as %s; provision requires a saved root connection", rootName, root.User)
	}
	if _, exists := c.Hosts[newName]; exists {
		return fmt.Errorf("%q already exists; choose a new connection name", newName)
	}
	if root.Port < 1 || root.Port > 65535 {
		return errors.New("saved SSH port must be between 1 and 65535")
	}
	pub, err := os.ReadFile(root.Identity + ".pub")
	if errors.Is(err, os.ErrNotExist) {
		if err := recoverPublicKey(root.Identity); err != nil {
			return err
		}
		pub, err = os.ReadFile(root.Identity + ".pub")
	}
	if err != nil {
		return fmt.Errorf("read %s.pub: %w", root.Identity, err)
	}
	if !validPublicKey(pub) {
		return fmt.Errorf("%s.pub is not a valid public key", root.Identity)
	}
	newHost := root
	newHost.User = newUser
	secret := make([]byte, 24)
	if _, err := rand.Read(secret); err != nil {
		return fmt.Errorf("generate account password: %w", err)
	}
	password := hex.EncodeToString(secret)
	fmt.Println("Step 1/3: Testing the saved root key login...")
	if err := runSSH(keyOnlySSHArgs(root), os.Stdin); err != nil {
		return fmt.Errorf("root key login failed; account was not created: %w", err)
	}
	fmt.Println("Step 2/3: Creating the non-root account and installing its public key...")
	remote := "sh -c " + shellQuote(provisionServerScript) + " sh " + shellQuote(newUser)
	if err := runSSH(append(sshArgs(root), remote), strings.NewReader(strings.TrimSpace(string(pub))+"\n"+password+"\n")); err != nil {
		return fmt.Errorf("could not create non-root account: %w", err)
	}
	fmt.Println("Step 3/3: Testing the new account with the saved key...")
	if err := runSSH(keyOnlySSHArgs(newHost), os.Stdin); err != nil {
		showProvisionPassword(password)
		return fmt.Errorf("account was created, but key login as %s failed; check its authorized_keys from your root session, then save it with 'sshable add --port %d --identity %s NEW_NAME %s@%s' and test before securing SSH: %w", newUser, root.Port, shellQuote(root.Identity), newUser, root.Host, err)
	}
	c.Hosts[newName] = newHost
	if err := saveConfig(c); err != nil {
		showProvisionPassword(password)
		return fmt.Errorf("new account works, but saving its connection failed: %w", err)
	}
	fmt.Printf("Saved %s (%s@%s). Next: sshable secure %s\n", newName, newUser, root.Host, newName)
	showProvisionPassword(password)
	return nil
}
