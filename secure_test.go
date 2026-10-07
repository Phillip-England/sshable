package main

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestSecureHostChecksKeyBeforeChangingServer(t *testing.T) {
	h := host{User: "alice", Host: "server.example.com", Port: 22, Identity: "/tmp/key"}
	calls := 0
	err := secureHost(h, func(args []string, _ io.Reader) error {
		calls++
		if strings.Contains(strings.Join(args, " "), "sudo") {
			t.Fatal("attempted to change server before successful key login")
		}
		return errors.New("key unavailable")
	})
	if err == nil || calls != 1 {
		t.Fatalf("got error %v after %d SSH calls", err, calls)
	}
}

func TestSecureHostRejectsRootBeforeChangingServer(t *testing.T) {
	h := host{User: "root", Host: "server.example.com", Port: 2222, Identity: "/tmp/existing key"}
	err := secureHost(h, func([]string, io.Reader) error {
		t.Fatal("SSH ran for a root connection")
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "root@server.example.com") || !strings.Contains(err.Error(), "sshable provision ROOT_NAME NEW_NAME NEW_USER") {
		t.Fatalf("missing actionable root login error: %v", err)
	}
}

func TestSecureHostSequence(t *testing.T) {
	h := host{User: "alice", Host: "server.example.com", Port: 2222, Identity: "/tmp/key"}
	var calls [][]string
	if err := secureHost(h, func(args []string, _ io.Reader) error {
		calls = append(calls, args)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 4 || !slices.Equal(calls[0], calls[2]) || !strings.Contains(calls[1][len(calls[1])-1], "sudo sh -c") {
		t.Fatalf("unexpected SSH sequence: %v", calls)
	}
	if !slices.Contains(calls[1], "-tt") || !slices.Contains(calls[1], "PasswordAuthentication=no") {
		t.Fatal("remote change did not require key login and an interactive sudo terminal")
	}
	if !strings.Contains(calls[3][len(calls[3])-1], "fail2ban-client status sshd") || !strings.HasSuffix(calls[3][len(calls[3])-1], " sh '2222'") {
		t.Fatal("Fail2ban setup did not follow the SSH reload test and use the saved port")
	}
}

func TestSecureServerScriptSyntax(t *testing.T) {
	for _, script := range []string{secureServerScript, fail2banServerScript} {
		cmd := exec.Command("sh", "-n")
		cmd.Stdin = strings.NewReader(script)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("invalid remote shell script: %v: %s", err, out)
		}
	}
}

func TestFail2banServerScriptConfigAndRollback(t *testing.T) {
	for _, fail := range []bool{false, true} {
		name := "success"
		if fail {
			name = "validation failure"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			jailDir := filepath.Join(root, "jail.d")
			binDir := filepath.Join(root, "bin")
			for _, dir := range []string{jailDir, binDir} {
				if err := os.MkdirAll(dir, 0700); err != nil {
					t.Fatal(err)
				}
			}
			config := filepath.Join(jailDir, "zz-sshable-sshd.local")
			if err := os.WriteFile(config, []byte("old configuration\n"), 0600); err != nil {
				t.Fatal(err)
			}
			client := "#!/bin/sh\nexit 0\n"
			if fail {
				client = "#!/bin/sh\n[ \"$1\" != -t ]\n"
			}
			for name, script := range map[string]string{
				"apt-get":         "#!/bin/sh\nexit 0\n",
				"systemctl":       "#!/bin/sh\nexit 0\n",
				"fail2ban-client": client,
			} {
				if err := os.WriteFile(filepath.Join(binDir, name), []byte(script), 0700); err != nil {
					t.Fatal(err)
				}
			}
			script := strings.ReplaceAll(fail2banServerScript, "/etc/fail2ban/jail.d", jailDir)
			cmd := exec.Command("sh", "-c", script, "sh", "2222")
			cmd.Env = append(os.Environ(), "PATH="+binDir+":"+os.Getenv("PATH"))
			out, err := cmd.CombinedOutput()
			if fail != (err != nil) {
				t.Fatalf("unexpected result: %v: %s", err, out)
			}
			data, err := os.ReadFile(config)
			if err != nil {
				t.Fatal(err)
			}
			if fail {
				if string(data) != "old configuration\n" {
					t.Fatalf("config not restored: %s", data)
				}
				if !strings.Contains(string(out), "Fail2ban rejected the new SSH jail configuration") || !strings.Contains(string(out), "Restored previous Fail2ban configuration") {
					t.Fatalf("failure did not explain validation and rollback: %s", out)
				}
			} else if !strings.Contains(string(data), "port = 2222\n") || !strings.Contains(string(data), "backend = systemd\n") || !strings.Contains(string(data), "maxretry = 5\n") {
				t.Fatalf("unexpected jail configuration: %s", data)
			}
		})
	}
}

func TestSecureServerScriptAppliesAndRestores(t *testing.T) {
	for _, failValidation := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "validation failure"}[failValidation], func(t *testing.T) {
			root := t.TempDir()
			sshDir := filepath.Join(root, "ssh")
			binDir := filepath.Join(root, "bin")
			if err := os.MkdirAll(sshDir, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(binDir, 0700); err != nil {
				t.Fatal(err)
			}
			configPath := filepath.Join(sshDir, "sshd_config")
			original := []byte("PasswordAuthentication yes\n")
			if err := os.WriteFile(configPath, original, 0600); err != nil {
				t.Fatal(err)
			}
			sshd := "#!/bin/sh\ncase \"$1\" in\n-t) exit 0;;\n-T) printf '%s\\n' 'permitrootlogin no' 'passwordauthentication no' 'kbdinteractiveauthentication no' 'pubkeyauthentication yes' 'authenticationmethods publickey';;\nesac\n"
			if failValidation {
				sshd = "#!/bin/sh\nexit 1\n"
			}
			if err := os.WriteFile(filepath.Join(binDir, "sshd"), []byte(sshd), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(binDir, "systemctl"), []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
				t.Fatal(err)
			}
			script := strings.ReplaceAll(secureServerScript, "/etc/ssh/", sshDir+"/")
			script = strings.ReplaceAll(script, "/run/sshable-ssh.lock", filepath.Join(root, "lock"))
			cmd := exec.Command("sh", "-c", script, "sh", "alice")
			cmd.Env = append(os.Environ(), "PATH="+binDir+":"+os.Getenv("PATH"))
			out, err := cmd.CombinedOutput()
			if failValidation != (err != nil) {
				t.Fatalf("unexpected result: %v: %s", err, out)
			}
			data, err := os.ReadFile(configPath)
			if err != nil {
				t.Fatal(err)
			}
			if failValidation {
				if string(data) != string(original) {
					t.Fatalf("failed validation did not restore original config: %s", data)
				}
				if !strings.Contains(string(out), "OpenSSH rejected the new configuration") || !strings.Contains(string(out), "Restored SSH configuration") {
					t.Fatalf("failure did not explain validation and rollback: %s", out)
				}
			} else if !strings.HasPrefix(string(data), "# Managed by sshable: key-only SSH access\nPermitRootLogin no\nPasswordAuthentication no\n") {
				t.Fatalf("security settings not prepended: %s", data)
			} else {
				again := exec.Command("sh", "-c", script, "sh", "alice")
				again.Env = cmd.Env
				if out, err := again.CombinedOutput(); err != nil {
					t.Fatalf("second secure failed: %v: %s", err, out)
				}
				data, err := os.ReadFile(configPath)
				if err != nil {
					t.Fatal(err)
				}
				if strings.Count(string(data), "# Managed by sshable: key-only SSH access") != 1 {
					t.Fatalf("second secure duplicated managed policy: %s", data)
				}
			}
		})
	}
}

func TestSecureServerScriptRemovesInvitation(t *testing.T) {
	root := t.TempDir()
	sshDir := filepath.Join(root, "ssh")
	binDir := filepath.Join(root, "bin")
	for _, dir := range []string{sshDir, binDir} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	configPath := filepath.Join(sshDir, "sshd_config")
	invitation := "# Managed by sshable: key-only SSH access\nPasswordAuthentication no\nAuthenticationMethods publickey\n# sshable temporary access begin sshable_0123456789\nMatch User sshable_0123456789\n    PasswordAuthentication yes\n    AuthenticationMethods password\n    KbdInteractiveAuthentication no\n# sshable temporary access end sshable_0123456789\n"
	if err := os.WriteFile(configPath, []byte(invitation), 0600); err != nil {
		t.Fatal(err)
	}
	sshd := "#!/bin/sh\ncase \"$1\" in\n-t) exit 0;;\n-T) printf '%s\\n' 'permitrootlogin no' 'passwordauthentication no' 'kbdinteractiveauthentication no' 'pubkeyauthentication yes' 'authenticationmethods publickey';;\nesac\n"
	for name, script := range map[string]string{
		"sshd":      sshd,
		"systemctl": "#!/bin/sh\nexit 0\n",
		"userdel":   "#!/bin/sh\nprintf '%s\\n' \"$2\" > " + filepath.Join(root, "deleted") + "\n",
	} {
		if err := os.WriteFile(filepath.Join(binDir, name), []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
	}
	script := strings.ReplaceAll(secureServerScript, "/etc/ssh/", sshDir+"/")
	script = strings.ReplaceAll(script, "/run/sshable-ssh.lock", filepath.Join(root, "lock"))
	cmd := exec.Command("sh", "-c", script, "sh", "alice")
	cmd.Env = append(os.Environ(), "PATH="+binDir+":"+os.Getenv("PATH"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("secure failed: %v: %s", err, out)
	}
	config, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(config), "temporary access") || strings.Contains(string(config), "Match User") {
		t.Fatalf("invitation remains in SSH config: %s", config)
	}
	deleted, err := os.ReadFile(filepath.Join(root, "deleted"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(deleted)) != "sshable_0123456789" {
		t.Fatalf("deleted wrong account: %q", deleted)
	}
}
