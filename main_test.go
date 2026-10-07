package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func testPublicKey() string {
	keyType := "ssh-ed25519"
	blob := make([]byte, 4+len(keyType)+32)
	binary.BigEndian.PutUint32(blob[:4], uint32(len(keyType)))
	copy(blob[4:], keyType)
	return keyType + " " + base64.StdEncoding.EncodeToString(blob) + " test@sshable"
}

func TestParseTarget(t *testing.T) {
	user, host, err := parseTarget("alice@[::1]")
	if err != nil || user != "alice" || host != "::1" {
		t.Fatalf("IPv6 target: user=%q host=%q err=%v", user, host, err)
	}
	for _, target := range []string{"no-at-sign", "-o@host", "alice@-oProxyCommand=bad", "alice@host\nother", "alice@[broken"} {
		if _, _, err := parseTarget(target); err == nil {
			t.Errorf("accepted invalid target %q", target)
		}
	}
}

func TestValidPublicKey(t *testing.T) {
	key := testPublicKey()
	if !validPublicKey([]byte(key + "\n")) {
		t.Fatal("rejected public key")
	}
	for _, bad := range []string{"ssh-ed25519 !!!", key + "\nextra", "ssh-rsa " + strings.Fields(key)[1]} {
		if validPublicKey([]byte(bad)) {
			t.Errorf("accepted invalid public key %q", bad)
		}
	}
}

func TestEnsureKeyRecoversMissingPublicHalf(t *testing.T) {
	key := filepath.Join(t.TempDir(), "existing-key")
	cmd := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("create test key: %v: %s", err, out)
	}
	if err := os.Remove(key + ".pub"); err != nil {
		t.Fatal(err)
	}
	if err := ensureKey(key, false); err != nil {
		t.Fatal(err)
	}
	pub, err := os.ReadFile(key + ".pub")
	if err != nil || !validPublicKey(pub) {
		t.Fatalf("public key was not recovered: %v", err)
	}
}

func TestRemoteInstallKeyScript(t *testing.T) {
	home := t.TempDir()
	key := testPublicKey()
	for i := 0; i < 2; i++ {
		cmd := exec.Command("sh", "-c", installKeyScript)
		cmd.Env = append(os.Environ(), "HOME="+home)
		cmd.Stdin = strings.NewReader(key + "\n")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("run %d: %v: %s", i, err, out)
		}
	}
	data, err := os.ReadFile(filepath.Join(home, ".ssh", "authorized_keys"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, []byte(key+"\n")) {
		t.Fatalf("authorized_keys = %q", data)
	}
}

func TestRemoteRevokeKeyScript(t *testing.T) {
	home := t.TempDir()
	sshDir := filepath.Join(home, ".ssh")
	if err := os.Mkdir(sshDir, 0700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(sshDir, "authorized_keys")
	key := testPublicKey()
	fields := strings.Fields(key)
	other := "ssh-ed25519 AAAAother another@client"
	comment := "# " + fields[0] + " " + fields[1] + " is documented here"
	content := comment + "\n" + other + "\n" + "from=\"192.0.2.1\" " + fields[0] + " " + fields[1] + " changed-comment\n" + other + "\n"
	if err := os.WriteFile(file, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	getent := "#!/bin/sh\nprintf 'root:x:0:0::%s:/bin/sh\\n' \"$TEST_ACCOUNT_HOME\"\n"
	if err := os.WriteFile(filepath.Join(bin, "getent"), []byte(getent), 0700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		cmd := exec.Command("sh", "-c", revokeKeyScript, "sh", "root", fields[0], fields[1])
		cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "TEST_ACCOUNT_HOME="+home)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("run %d: %v: %s", i, err, out)
		}
	}
	got, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if want := comment + "\n" + other + "\n" + other + "\n"; string(got) != want {
		t.Fatalf("authorized_keys = %q, want %q", got, want)
	}
	info, err := os.Stat(file)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("authorized_keys permissions changed: %v, %v", info, err)
	}
}

func TestConnectionUsesKeyOnly(t *testing.T) {
	h := host{User: "alice", Host: "example.com", Port: 2222, Identity: "/tmp/key"}
	args := strings.Join(sshArgs(h), " ")
	for _, want := range []string{"PreferredAuthentications=publickey", "PasswordAuthentication=no", "KbdInteractiveAuthentication=no", "IdentitiesOnly=yes", "ControlPath=none"} {
		if !strings.Contains(args, want) {
			t.Errorf("connection omitted %q", want)
		}
	}
	setup := strings.Join(passwordSetupSSHArgs(h), " ")
	if strings.Contains(setup, "PasswordAuthentication=no") || strings.Contains(setup, "KbdInteractiveAuthentication=no") {
		t.Fatal("setup disabled server password login")
	}
}

func TestHeadlessCLICommands(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	identity := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(identity+".pub", []byte(testPublicKey()+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := saveConfig(config{Hosts: map[string]host{"work": {User: "alice", Host: "example.com", Port: 2222, Identity: identity}}}); err != nil {
		t.Fatal(err)
	}
	readOutput := func(action func() error) string {
		t.Helper()
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		old := os.Stdout
		os.Stdout = writer
		defer func() { os.Stdout = old }()
		if err := action(); err != nil {
			t.Fatal(err)
		}
		writer.Close()
		output, err := io.ReadAll(reader)
		reader.Close()
		if err != nil {
			t.Fatal(err)
		}
		return string(output)
	}
	if got := readOutput(func() error { return run(nil) }); !strings.Contains(got, "sshable serve") || strings.Contains(got, "tui") {
		t.Fatalf("unexpected default help: %q", got)
	}
	if err := run([]string{"tui"}); err == nil {
		t.Fatal("TUI command is still available")
	}
	if got := readOutput(func() error { return showKeyCommand([]string{"work"}) }); got != testPublicKey()+"\n" {
		t.Fatalf("public key output: %q", got)
	}
	if err := showKeyCommand([]string{"missing"}); err == nil {
		t.Fatal("missing connection was accepted")
	}
	bin := t.TempDir()
	argsFile := filepath.Join(t.TempDir(), "ssh-args")
	if err := os.WriteFile(filepath.Join(bin, "ssh"), []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$SSHABLE_TEST_ARGS\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	t.Setenv("SSHABLE_TEST_ARGS", argsFile)
	readOutput(func() error { return testCommand([]string{"work"}) })
	args, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(args), "PreferredAuthentications=publickey\n") || !strings.HasSuffix(string(args), "--\nalice@example.com\ntrue\n") {
		t.Fatalf("key-only test used unexpected SSH arguments: %q", args)
	}
	keyFile := filepath.Join(t.TempDir(), "authorized-key-input")
	if err := os.WriteFile(filepath.Join(bin, "ssh"), []byte("#!/bin/sh\ncat > \"$SSHABLE_TEST_KEY\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSHABLE_TEST_KEY", keyFile)
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.WriteString(testPublicKey() + "\n"); err != nil {
		t.Fatal(err)
	}
	writer.Close()
	oldStdin := os.Stdin
	os.Stdin = reader
	defer func() { os.Stdin = oldStdin; reader.Close() }()
	readOutput(func() error { return authorizeKeyCommand([]string{"work", "-"}) })
	installedKey, err := os.ReadFile(keyFile)
	if err != nil || string(installedKey) != testPublicKey()+"\n" {
		t.Fatalf("stdin public key was not sent to SSH: %q, %v", installedKey, err)
	}
}

func TestRenameConnectionPreservesDetailsAndRejectsCollision(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	original := host{User: "alice", Host: "example.com", Port: 2222, Identity: "/tmp/existing-key"}
	other := host{User: "bob", Host: "other.example.com", Port: 22, Identity: "/tmp/other-key"}
	if err := saveConfig(config{Hosts: map[string]host{"old": original, "taken": other}}); err != nil {
		t.Fatal(err)
	}
	for _, newName := range []string{"taken", "bad name", "-bad"} {
		if err := renameHost("old", newName); err == nil {
			t.Errorf("renamed to invalid or occupied name %q", newName)
		}
	}
	if err := renameHost("old", "new"); err != nil {
		t.Fatal(err)
	}
	c, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := c.Hosts["old"]; exists || c.Hosts["new"] != original || c.Hosts["taken"] != other {
		t.Fatalf("rename changed saved connections: %+v", c.Hosts)
	}
}

func TestRunSSHIncludesRemoteFailureAndExitCode(t *testing.T) {
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "ssh"), []byte("#!/bin/sh\necho 'OpenSSH rejected the new configuration' >&2\nexit 7\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	err := runSSH([]string{"example.com"}, strings.NewReader(""))
	if err == nil || !strings.Contains(err.Error(), "OpenSSH rejected the new configuration") {
		t.Fatalf("missing remote cause: %v", err)
	}
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 7 {
		t.Fatalf("lost SSH exit code: %v", err)
	}
}
