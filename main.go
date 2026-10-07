package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type host struct {
	User     string `json:"user"`
	Host     string `json:"host"`
	Port     int    `json:"port"`
	Identity string `json:"identity"`
}

type config struct {
	Hosts map[string]host `json:"hosts"`
}

var namePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]*$`)
var userPattern = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]*[$]?$`)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "sshable:", err)
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			os.Exit(exit.ExitCode())
		}
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		usage()
		return nil
	}
	switch args[0] {
	case "help", "-h", "--help":
		usage()
	case "serve", "web":
		return serveCommand(args[1:])
	case "keygen":
		return keygenCommand(args[1:])
	case "add":
		return addCommand(args[1:])
	case "list":
		return listCommand(args[1:])
	case "show-key":
		return showKeyCommand(args[1:])
	case "test":
		return testCommand(args[1:])
	case "remove":
		return removeCommand(args[1:])
	case "rename":
		return renameCommand(args[1:])
	case "connect":
		return connectCommand(args[1:])
	case "copy-id":
		return copyIDCommand(args[1:])
	case "authorize-key":
		return authorizeKeyCommand(args[1:])
	case "revoke-key":
		return revokeKeyCommand(args[1:])
	case "secure":
		return secureCommand(args[1:])
	case "provision":
		return provisionCommand(args[1:])
	case "invite":
		return inviteCommand(args[1:])
	case "join":
		return joinCommand(args[1:])
	case "audit":
		return auditCommand(args[1:])
	default:
		return fmt.Errorf("unknown command %q (run sshable help)", args[0])
	}
	return nil
}

func usage() {
	fmt.Print(`sshable sets up and uses SSH key connections.

Usage:
  sshable serve [--port PORT] [--no-open]  Serve the local web client
  sshable                  Show this help
  sshable keygen [--path PATH] [--no-passphrase]
  sshable add [--port PORT] [--identity PATH] NAME USER@HOST
  sshable list
  sshable show-key NAME     Print this connection's public key
  sshable test NAME         Test key-only SSH login
  sshable copy-id NAME       Install your public key (may ask for server password)
  sshable authorize-key NAME PUBLIC_KEY_FILE  Add another client's public key (- reads stdin)
  sshable revoke-key [--user USER] NAME  Remove this client's key from a server account
  sshable secure NAME        Require SSH keys, block root SSH, and set up Fail2ban
  sshable provision ROOT_NAME NEW_NAME NEW_USER
                             Create a non-root sudo account using a saved root key
  sshable invite NAME        Create a 20-minute password login for a new client
  sshable join [--port PORT] [--identity PATH] NAME USER@HOST TEMP_USER
                             Install this client's key using the invitation
  sshable audit NAME         Verify key login, SSH policy, and Fail2ban
  sshable connect NAME [-- REMOTE_COMMAND...]
  sshable remove NAME
  sshable rename OLD_NAME NEW_NAME

Setup:
  1. sshable add mybox alice@example.com
  2. sshable copy-id mybox
  3. sshable connect mybox
  4. sshable secure mybox

If only root key access exists:
  1. sshable add rootbox root@example.com
  2. sshable provision rootbox mybox alice
  3. sshable secure mybox

OpenSSH handles host verification and prompts for the server password during
public-key installation. Connections after setup use the saved key only.
`)
}

func configPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "sshable", "hosts.json"), nil
}

func defaultIdentity() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".ssh", "sshable", "id_ed25519"), nil
}

func expandPath(path string) (string, error) {
	if path == "" {
		return "", errors.New("path cannot be empty")
	}
	if path == "~" || strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		path = filepath.Join(home, strings.TrimPrefix(path, "~/"))
	}
	return filepath.Abs(path)
}

func loadConfig() (config, error) {
	c := config{Hosts: make(map[string]host)}
	path, err := configPath()
	if err != nil {
		return c, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(data, &c); err != nil {
		return c, fmt.Errorf("read %s: %w", path, err)
	}
	if c.Hosts == nil {
		c.Hosts = make(map[string]host)
	}
	return c, nil
}

func saveConfig(c config) error {
	path, err := configPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	f, err := os.CreateTemp(filepath.Dir(path), ".hosts-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := f.Chmod(0600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

func parseTarget(target string) (string, string, error) {
	user, hostname, ok := strings.Cut(target, "@")
	if !ok || !userPattern.MatchString(user) || hostname == "" || strings.ContainsAny(hostname, " \t\r\n@") || strings.HasPrefix(hostname, "-") {
		return "", "", errors.New("target must be USER@HOST")
	}
	// Brackets are used only for IPv6 literals, as in user@[::1].
	if strings.HasPrefix(hostname, "[") {
		if !strings.HasSuffix(hostname, "]") {
			return "", "", errors.New("invalid bracketed host")
		}
		hostname = strings.TrimSuffix(strings.TrimPrefix(hostname, "["), "]")
	}
	if hostname == "" || strings.ContainsAny(hostname, "[]") {
		return "", "", errors.New("invalid host")
	}
	return user, hostname, nil
}

func ensureKey(path string, noPassphrase bool) error {
	if _, err := os.Stat(path); err == nil {
		if _, err := os.Stat(path + ".pub"); err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return err
			}
			return recoverPublicKey(path)
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if _, err := os.Stat(path + ".pub"); err == nil {
		return fmt.Errorf("%s.pub already exists", path)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	args := []string{"-t", "ed25519", "-f", path, "-C", "sshable"}
	if noPassphrase {
		args = append(args, "-N", "")
	}
	cmd := exec.Command("ssh-keygen", args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("ssh-keygen: %w", err)
	}
	fmt.Println("Key ready:", path)
	return nil
}

func recoverPublicKey(path string) error {
	cmd := exec.Command("ssh-keygen", "-y", "-f", path)
	cmd.Stdin, cmd.Stderr = os.Stdin, os.Stderr
	pub, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("recover public key for %s: %w", path, err)
	}
	if !validPublicKey(pub) {
		return fmt.Errorf("ssh-keygen returned an invalid public key for %s", path)
	}
	f, err := os.OpenFile(path+".pub", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return fmt.Errorf("save recovered public key: %w", err)
	}
	if _, err := f.Write(pub); err != nil {
		f.Close()
		os.Remove(path + ".pub")
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Println("Recovered public key:", path+".pub")
	return nil
}

func keygenCommand(args []string) error {
	flags := flag.NewFlagSet("keygen", flag.ContinueOnError)
	path := flags.String("path", "", "private key path")
	noPassphrase := flags.Bool("no-passphrase", false, "create an unencrypted key")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("usage: sshable keygen [--path PATH] [--no-passphrase]")
	}
	var err error
	if *path == "" {
		*path, err = defaultIdentity()
	} else {
		*path, err = expandPath(*path)
	}
	if err != nil {
		return err
	}
	return ensureKey(*path, *noPassphrase)
}

func addCommand(args []string) error {
	flags := flag.NewFlagSet("add", flag.ContinueOnError)
	port := flags.Int("port", 22, "SSH port")
	identity := flags.String("identity", "", "private key path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 2 {
		return errors.New("usage: sshable add [--port PORT] [--identity PATH] NAME USER@HOST")
	}
	name := flags.Arg(0)
	if !namePattern.MatchString(name) {
		return errors.New("name must contain only letters, digits, dots, underscores, and hyphens")
	}
	if *port < 1 || *port > 65535 {
		return errors.New("port must be between 1 and 65535")
	}
	user, hostname, err := parseTarget(flags.Arg(1))
	if err != nil {
		return err
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
		return fmt.Errorf("%q already exists; remove it first", name)
	}
	if err := ensureKey(*identity, false); err != nil {
		return err
	}
	c.Hosts[name] = host{User: user, Host: hostname, Port: *port, Identity: *identity}
	if err := saveConfig(c); err != nil {
		return err
	}
	fmt.Printf("Saved %s (%s@%s:%d). Run 'sshable copy-id %s' to install your public key.\n", name, user, hostname, *port, name)
	return nil
}

func listCommand(args []string) error {
	if len(args) != 0 {
		return errors.New("usage: sshable list")
	}
	c, err := loadConfig()
	if err != nil {
		return err
	}
	if len(c.Hosts) == 0 {
		fmt.Println("No saved hosts. Add one with: sshable add NAME USER@HOST")
		return nil
	}
	for _, name := range sortedNames(c.Hosts) {
		h := c.Hosts[name]
		fmt.Printf("%-20s %s@%s:%d  %s\n", name, h.User, h.Host, h.Port, h.Identity)
	}
	return nil
}

func showKeyCommand(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: sshable show-key NAME")
	}
	h, err := lookup(args[0])
	if err != nil {
		return err
	}
	pub, err := os.ReadFile(h.Identity + ".pub")
	if err != nil {
		return fmt.Errorf("read public key: %w", err)
	}
	if !validPublicKey(pub) {
		return errors.New("public key is invalid")
	}
	fmt.Println(strings.TrimSpace(string(pub)))
	return nil
}

func testCommand(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: sshable test NAME")
	}
	h, err := lookup(args[0])
	if err != nil {
		return err
	}
	if err := runSSH(keyOnlySSHArgs(h), os.Stdin); err != nil {
		return err
	}
	fmt.Println("Key-only login works for", args[0])
	return nil
}

func sortedNames(hosts map[string]host) []string {
	names := make([]string, 0, len(hosts))
	for name := range hosts {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func removeCommand(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: sshable remove NAME")
	}
	c, err := loadConfig()
	if err != nil {
		return err
	}
	if _, ok := c.Hosts[args[0]]; !ok {
		return fmt.Errorf("unknown host %q", args[0])
	}
	delete(c.Hosts, args[0])
	if err := saveConfig(c); err != nil {
		return err
	}
	fmt.Println("Removed", args[0])
	return nil
}

func renameCommand(args []string) error {
	if len(args) != 2 {
		return errors.New("usage: sshable rename OLD_NAME NEW_NAME")
	}
	if err := renameHost(args[0], args[1]); err != nil {
		return err
	}
	fmt.Printf("Renamed %s to %s\n", args[0], args[1])
	return nil
}

func renameHost(oldName, newName string) error {
	if !namePattern.MatchString(newName) {
		return errors.New("new name must start with a letter or digit and use only letters, digits, dots, _ or -")
	}
	c, err := loadConfig()
	if err != nil {
		return err
	}
	h, ok := c.Hosts[oldName]
	if !ok {
		return fmt.Errorf("unknown host %q", oldName)
	}
	if oldName == newName {
		return nil
	}
	if _, exists := c.Hosts[newName]; exists {
		return fmt.Errorf("connection %q already exists", newName)
	}
	c.Hosts[newName] = h
	delete(c.Hosts, oldName)
	if err := saveConfig(c); err != nil {
		return err
	}
	return nil
}

func lookup(name string) (host, error) {
	c, err := loadConfig()
	if err != nil {
		return host{}, err
	}
	h, ok := c.Hosts[name]
	if !ok {
		return host{}, fmt.Errorf("unknown host %q (run sshable list)", name)
	}
	return h, nil
}

func sshArgs(h host) []string {
	return []string{"-p", strconv.Itoa(h.Port), "-i", h.Identity, "-o", "IdentitiesOnly=yes", "-o", "ControlPath=none", "-o", "PreferredAuthentications=publickey", "-o", "PasswordAuthentication=no", "-o", "KbdInteractiveAuthentication=no", "--", h.User + "@" + h.Host}
}

func keyOnlySSHArgs(h host) []string { return append(sshArgs(h), "true") }

func runSSH(args []string, stdin io.Reader) error {
	cmd := exec.Command("ssh", args...)
	var diagnostics tailBuffer
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, os.Stdout, io.MultiWriter(os.Stderr, &diagnostics)
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			message := strings.TrimSpace(diagnostics.String())
			return sshFailure{exit: exit, diagnostics: message}
		}
		return fmt.Errorf("ssh: %w", err)
	}
	return nil
}

type sshFailure struct {
	exit        *exec.ExitError
	diagnostics string
}

func (e sshFailure) Error() string {
	if e.diagnostics != "" {
		return fmt.Sprintf("SSH exited with status %d: %s", e.exit.ExitCode(), e.diagnostics)
	}
	return fmt.Sprintf("SSH exited with status %d without error details from SSH or the server", e.exit.ExitCode())
}

func (e sshFailure) Unwrap() error { return e.exit }

// Keep recent diagnostics for errors without buffering an unbounded SSH session.
type tailBuffer struct{ bytes.Buffer }

func (b *tailBuffer) Write(p []byte) (int, error) {
	const limit = 4096
	n := len(p)
	if n >= limit {
		b.Reset()
		_, _ = b.Buffer.Write(p[n-limit:])
		return n, nil
	}
	if b.Len()+n > limit {
		old := append([]byte(nil), b.Bytes()[b.Len()+n-limit:]...)
		b.Reset()
		_, _ = b.Buffer.Write(old)
	}
	_, _ = b.Buffer.Write(p)
	return n, nil
}

func connectCommand(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: sshable connect NAME [-- REMOTE_COMMAND...]")
	}
	h, err := lookup(args[0])
	if err != nil {
		return err
	}
	sshArgs := sshArgs(h)
	if len(args) > 1 {
		if args[1] != "--" {
			return errors.New("put remote command arguments after --")
		}
		sshArgs = append(sshArgs, args[2:]...)
	}
	return runSSH(sshArgs, os.Stdin)
}

const installKeyScript = `umask 077
mkdir -p "$HOME/.ssh" || exit 1
chmod 700 "$HOME/.ssh" || exit 1
touch "$HOME/.ssh/authorized_keys" || exit 1
chmod 600 "$HOME/.ssh/authorized_keys" || exit 1
IFS= read -r key || exit 1
grep -qxF "$key" "$HOME/.ssh/authorized_keys" || printf '%s\n' "$key" >> "$HOME/.ssh/authorized_keys"`

func validPublicKey(data []byte) bool {
	line := strings.TrimSpace(string(data))
	fields := strings.Fields(line)
	if len(fields) < 2 || strings.ContainsAny(line, "\r\n") {
		return false
	}
	keyType := fields[0]
	if !strings.HasPrefix(keyType, "ssh-") && !strings.HasPrefix(keyType, "ecdsa-") && !strings.HasPrefix(keyType, "sk-") {
		return false
	}
	blob, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil || len(blob) < 4 {
		return false
	}
	typeLength := int(binary.BigEndian.Uint32(blob[:4]))
	return typeLength == len(keyType) && len(blob) > 4+typeLength && string(blob[4:4+typeLength]) == keyType
}

func copyIDCommand(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: sshable copy-id NAME")
	}
	h, err := lookup(args[0])
	if err != nil {
		return err
	}
	pub, err := os.ReadFile(h.Identity + ".pub")
	if err != nil {
		return fmt.Errorf("read public key: %w", err)
	}
	if !validPublicKey(pub) {
		return errors.New("public key is invalid")
	}
	sshArgs := append(passwordSetupSSHArgs(h), installKeyScript)
	if err := runSSH(sshArgs, strings.NewReader(strings.TrimSpace(string(pub))+"\n")); err != nil {
		return err
	}
	fmt.Println("Public key installed on", args[0])
	return nil
}

func authorizeKeyCommand(args []string) error {
	if len(args) != 2 {
		return errors.New("usage: sshable authorize-key NAME PUBLIC_KEY_FILE (use - for stdin)")
	}
	h, err := lookup(args[0])
	if err != nil {
		return err
	}
	var pub []byte
	if args[1] == "-" {
		pub, err = io.ReadAll(io.LimitReader(os.Stdin, (16<<10)+1))
		if len(pub) > 16<<10 {
			return errors.New("public key input is too large")
		}
	} else {
		var path string
		path, err = expandPath(args[1])
		if err != nil {
			return err
		}
		pub, err = os.ReadFile(path)
	}
	if err != nil {
		return fmt.Errorf("read public key: %w", err)
	}
	if !validPublicKey(pub) {
		return errors.New("public key is invalid")
	}
	if err := runSSH(append(sshArgs(h), installKeyScript), strings.NewReader(strings.TrimSpace(string(pub))+"\n")); err != nil {
		return err
	}
	fmt.Println("Public key authorized on", args[0])
	return nil
}

// Remove this client's public key from the chosen server account. The SSH
// session stays open long enough to finish even when it uses the revoked key.
const revokeKeyScript = `set -eu
target_user=$1
key_type=$2
key_blob=$3
[ -n "$key_type" ] && [ -n "$key_blob" ] || { echo "Missing public key" >&2; exit 1; }
entry=$(getent passwd "$target_user") || { echo "Server account not found: $target_user" >&2; exit 1; }
home=$(printf '%s\n' "$entry" | cut -d: -f6)
[ -n "$home" ] || { echo "Server account has no home directory: $target_user" >&2; exit 1; }
file=$home/.ssh/authorized_keys
if [ ! -e "$file" ]; then
  echo "Public key is already absent from $file"
  exit 0
fi
[ -f "$file" ] && [ ! -L "$file" ] || { echo "Expected a regular authorized_keys file: $file" >&2; exit 1; }
temp=$(mktemp "$home/.ssh/.authorized_keys.sshable.XXXXXX")
trap 'rm -f "$temp"' EXIT
cp -p "$file" "$temp"
if awk -v type="$key_type" -v blob="$key_blob" '
  { found=0; if ($1 !~ /^#/) for (i=1; i<NF; i++) if ($i==type && $(i+1)==blob) found=1; if (!found) print; else removed=1 }
  END { if (!removed) exit 3 }
' "$file" > "$temp"; then
  mv -f "$temp" "$file"
  echo "Removed public key from $file"
else
  status=$?
  [ "$status" -eq 3 ] || { echo "Could not edit $file" >&2; exit "$status"; }
  echo "Public key is already absent from $file"
fi`

func revokeKeyCommand(args []string) error {
	flags := flag.NewFlagSet("revoke-key", flag.ContinueOnError)
	user := flags.String("user", "", "server account whose authorized_keys should be edited")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 1 {
		return errors.New("usage: sshable revoke-key [--user USER] NAME")
	}
	h, err := lookup(flags.Arg(0))
	if err != nil {
		return err
	}
	target := *user
	if target == "" {
		target = h.User
	}
	if !userPattern.MatchString(target) {
		return errors.New("server username is invalid")
	}
	pub, err := os.ReadFile(h.Identity + ".pub")
	if err != nil {
		return fmt.Errorf("read public key: %w", err)
	}
	if !validPublicKey(pub) {
		return errors.New("public key is invalid")
	}
	fields := strings.Fields(string(pub))
	remote := "sh -c " + shellQuote(revokeKeyScript) + " sh " + shellQuote(target) + " " + shellQuote(fields[0]) + " " + shellQuote(fields[1])
	sshOptions := sshArgs(h)
	if h.User != "root" && target != h.User {
		remote = "sudo " + remote
		sshOptions = append([]string{"-tt"}, sshOptions...)
	}
	if err := runSSH(append(sshOptions, remote), os.Stdin); err != nil {
		return fmt.Errorf("remove public key from %s@%s: %w", target, h.Host, err)
	}
	return nil
}

// Setup permits the server's existing login method so the public key can be installed.
func passwordSetupSSHArgs(h host) []string {
	return []string{"-p", strconv.Itoa(h.Port), "-i", h.Identity, "-o", "IdentitiesOnly=yes", "-o", "ControlPath=none", "--", h.User + "@" + h.Host}
}
