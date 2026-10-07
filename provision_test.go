package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestProvisionServerScriptCreatesKeyAccountAndRollsBack(t *testing.T) {
	for _, failPassword := range []bool{false, true} {
		name := "success"
		if failPassword {
			name = "password failure"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			bin := filepath.Join(root, "bin")
			home := filepath.Join(root, "new-home")
			if err := os.Mkdir(bin, 0700); err != nil {
				t.Fatal(err)
			}
			stubs := map[string]string{
				"useradd":  "mkdir -p \"$TEST_HOME\"",
				"usermod":  "exit 0",
				"userdel":  "touch \"$TEST_ROOT/deleted\"",
				"chpasswd": "cat > \"$TEST_ROOT/password-input\"",
				"sudo":     "exit 0",
				"getent":   "case \"$1\" in group) [ \"$2\" = sudo ];; passwd) printf 'alice:x:1000:1000::%s:/bin/sh\\n' \"$TEST_HOME\";; esac",
				"id":       "[ \"$1\" = -gn ] && { echo alice; exit 0; }; exit 1",
				"install":  "for value do directory=$value; done; mkdir -p \"$directory\"",
				"chown":    "exit 0",
			}
			if failPassword {
				stubs["chpasswd"] = "exit 1"
			}
			for command, body := range stubs {
				if err := os.WriteFile(filepath.Join(bin, command), []byte("#!/bin/sh\n"+body+"\n"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command("sh", "-c", provisionServerScript, "sh", "alice")
			cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "TEST_HOME="+home, "TEST_ROOT="+root)
			cmd.Stdin = strings.NewReader(testPublicKey() + "\n" + strings.Repeat("a", 48) + "\n")
			out, err := cmd.CombinedOutput()
			if (err != nil) != failPassword {
				t.Fatalf("unexpected result: %v: %s", err, out)
			}
			if strings.Contains(string(out), strings.Repeat("a", 48)) {
				t.Fatal("account password leaked to output")
			}
			if failPassword {
				if _, err := os.Stat(filepath.Join(root, "deleted")); err != nil {
					t.Fatal("incomplete account was not removed")
				}
				return
			}
			key, err := os.ReadFile(filepath.Join(home, ".ssh", "authorized_keys"))
			if err != nil || string(key) != testPublicKey()+"\n" {
				t.Fatalf("wrong installed key: %q, %v", key, err)
			}
			passwordInput, err := os.ReadFile(filepath.Join(root, "password-input"))
			if err != nil || string(passwordInput) != "alice:"+strings.Repeat("a", 48)+"\n" {
				t.Fatalf("wrong password input: %q, %v", passwordInput, err)
			}
		})
	}
}

func TestProvisionServerScriptSyntax(t *testing.T) {
	cmd := exec.Command("sh", "-n")
	cmd.Stdin = strings.NewReader(provisionServerScript)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("invalid shell script: %v: %s", err, out)
	}
}

func TestProvisionSavesOnlyAfterNewKeyLogin(t *testing.T) {
	for _, failNewLogin := range []bool{false, true} {
		name := "verified"
		if failNewLogin {
			name = "new login fails"
		}
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			t.Setenv("HOME", root)
			t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
			bin := filepath.Join(root, "bin")
			if err := os.Mkdir(bin, 0700); err != nil {
				t.Fatal(err)
			}
			keyPath := filepath.Join(root, "id_ed25519")
			if err := os.WriteFile(keyPath+".pub", []byte(testPublicKey()+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := saveConfig(config{Hosts: map[string]host{"rootbox": {User: "root", Host: "example.com", Port: 2222, Identity: keyPath}}}); err != nil {
				t.Fatal(err)
			}
			ssh := "#!/bin/sh\nprintf '%s\\n' call >> \"$TEST_ROOT/calls\"\nfor arg do last=$arg; done\ncase \"$last\" in *'sh -c '*) cat > \"$TEST_ROOT/provision-input\";; esac\n"
			if failNewLogin {
				ssh += "case \"$last\" in 'true') case \"$*\" in *alice@example.com*) exit 1;; esac;; esac\n"
			}
			if err := os.WriteFile(filepath.Join(bin, "ssh"), []byte(ssh), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
			t.Setenv("TEST_ROOT", root)
			err := provisionCommand([]string{"rootbox", "work", "alice"})
			if (err != nil) != failNewLogin {
				t.Fatalf("unexpected result: %v", err)
			}
			calls, err := os.ReadFile(filepath.Join(root, "calls"))
			if err != nil || strings.Count(string(calls), "call\n") != 3 {
				t.Fatalf("expected root test, creation, and new login test: %q, %v", calls, err)
			}
			input, err := os.ReadFile(filepath.Join(root, "provision-input"))
			if err != nil || !strings.HasPrefix(string(input), testPublicKey()+"\n") || len(strings.TrimSpace(string(input))) < len(testPublicKey())+48 {
				t.Fatalf("public key or password missing from provision input: %v", err)
			}
			c, err := loadConfig()
			if err != nil {
				t.Fatal(err)
			}
			_, saved := c.Hosts["work"]
			if saved == failNewLogin {
				t.Fatalf("saved=%v after new login failure=%v", saved, failNewLogin)
			}
		})
	}
}
