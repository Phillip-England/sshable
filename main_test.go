package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
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
