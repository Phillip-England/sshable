package main

import (
	"errors"
	"fmt"
	"os"
)

const auditServerScript = `set -eu
login_user=$1
sshd=$(command -v sshd || true)
[ -n "$sshd" ] || sshd=/usr/sbin/sshd
[ -x "$sshd" ] || { echo "sshd was not found" >&2; exit 1; }
"$sshd" -t
for user in "$login_user" root; do
  effective=$("$sshd" -T -C "user=$user,host=localhost,addr=127.0.0.1")
  for expected in 'permitrootlogin no' 'passwordauthentication no' 'kbdinteractiveauthentication no' 'pubkeyauthentication yes' 'authenticationmethods publickey'; do
    printf '%s\n' "$effective" | grep -qx "$expected" || { echo "Unexpected SSH policy for $user: $expected is missing" >&2; exit 1; }
  done
done
echo 'SSH policy: root disabled; public key required; password and keyboard-interactive disabled.'
command -v fail2ban-client >/dev/null 2>&1 || { echo "Fail2ban is not installed" >&2; exit 1; }
fail2ban-client status sshd || { echo "Fail2ban sshd jail is not active" >&2; exit 1; }
echo 'Fail2ban sshd jail: active.'
`

func auditCommand(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: sshable audit NAME")
	}
	h, err := lookup(args[0])
	if err != nil {
		return err
	}
	if h.User == "root" {
		return errors.New("audit needs a saved non-root connection")
	}
	fmt.Println("Checking fresh public-key login...")
	if err := runSSH(keyOnlySSHArgs(h), os.Stdin); err != nil {
		return fmt.Errorf("key login is not working: %w", err)
	}
	fmt.Println("Checking effective SSH policy and Fail2ban. Sudo may ask for the account password...")
	sshCommand := append(keyOnlyInteractiveSSHArgs(h), "sudo sh -c "+shellQuote(auditServerScript)+" sh "+shellQuote(h.User))
	return runSSH(sshCommand, os.Stdin)
}
