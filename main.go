package main

import (
	"bufio"
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
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			os.Exit(exit.ExitCode())
		}
		fmt.Fprintln(os.Stderr, "sshable:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return tuiCommand()
	}
	switch args[0] {
	case "help", "-h", "--help":
		usage()
	case "tui":
		return tuiCommand()
	case "keygen":
		return keygenCommand(args[1:])
	case "add":
		return addCommand(args[1:])
	case "list":
		return listCommand(args[1:])
	case "remove":
		return removeCommand(args[1:])
	case "connect":
		return connectCommand(args[1:])
	case "copy-id":
		return copyIDCommand(args[1:])
	case "server":
		return serverCommand(args[1:])
	default:
		return fmt.Errorf("unknown command %q (run sshable help)", args[0])
	}
	return nil
}

func usage() {
	fmt.Print(`sshable makes everyday SSH connections easier.

Usage:
  sshable                  Open the guided terminal interface
  sshable tui              Open the guided terminal interface
  sshable keygen [--path PATH] [--no-passphrase]
  sshable add [--port PORT] [--identity PATH] NAME USER@HOST
  sshable list
  sshable connect NAME [-- REMOTE_COMMAND...]
  sshable copy-id NAME
  sshable remove NAME
  sshable server init
  sshable server authorize PUBLIC_KEY_FILE
  sshable server keygen [--path PATH] [--no-passphrase]

Typical setup:
  On the client: sshable add mybox alice@example.com
  On the client: sshable copy-id mybox
  On the client: sshable connect mybox

OpenSSH handles password prompts and host-key verification. An SSH server
(sshd) must already be running on the remote machine.
Run 'sshable server init' on the server only if you need to prepare that
account's authorized_keys file manually.
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
			return fmt.Errorf("%s exists but its public key is missing", path)
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
	fmt.Printf("Saved %s (%s@%s:%d). Run 'sshable copy-id %s' to install your public key, or 'sshable connect %s' to use password authentication.\n", name, user, hostname, *port, name, name)
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
	return []string{"-p", strconv.Itoa(h.Port), "-i", h.Identity, "-o", "IdentitiesOnly=yes", "--", h.User + "@" + h.Host}
}

func runSSH(args []string, stdin io.Reader) error {
	cmd := exec.Command("ssh", args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return exit
		}
		return fmt.Errorf("ssh: %w", err)
	}
	return nil
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
	sshArgs := append(sshArgs(h), installKeyScript)
	if err := runSSH(sshArgs, strings.NewReader(strings.TrimSpace(string(pub))+"\n")); err != nil {
		return err
	}
	fmt.Println("Public key installed on", args[0])
	return nil
}

func serverCommand(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: sshable server init|authorize|keygen")
	}
	switch args[0] {
	case "init":
		if len(args) != 1 {
			return errors.New("usage: sshable server init")
		}
		path, err := authorizedKeysPath()
		if err != nil {
			return err
		}
		if err := prepareAuthorizedKeys(path); err != nil {
			return err
		}
		fmt.Println("SSH account prepared:", path)
		return nil
	case "authorize":
		if len(args) != 2 {
			return errors.New("usage: sshable server authorize PUBLIC_KEY_FILE")
		}
		return authorizeKey(args[1])
	case "keygen":
		return keygenCommand(args[1:])
	default:
		return errors.New("usage: sshable server init|authorize|keygen")
	}
}

func authorizedKeysPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".ssh", "authorized_keys"), nil
}

func prepareAuthorizedKeys(path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Chmod(path, 0600)
}

func authorizeKey(path string) error {
	path, err := expandPath(path)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !validPublicKey(data) {
		return errors.New("public key must be a single OpenSSH public-key line")
	}
	dest, err := authorizedKeysPath()
	if err != nil {
		return err
	}
	if err := prepareAuthorizedKeys(dest); err != nil {
		return err
	}
	key := strings.TrimSpace(string(data))
	f, err := os.OpenFile(dest, os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) == key {
			fmt.Println("Key already authorized")
			return nil
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if info.Size() > 0 {
		if _, err := f.Seek(-1, io.SeekEnd); err != nil {
			return err
		}
		last := make([]byte, 1)
		if _, err := f.Read(last); err != nil {
			return err
		}
		if last[0] != '\n' {
			if _, err := f.WriteAt([]byte("\n"), info.Size()); err != nil {
				return err
			}
		}
	}
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(f, key); err != nil {
		return err
	}
	fmt.Println("Authorized key from", path)
	return nil
}
