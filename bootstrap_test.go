package main

import (
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

func TestBootstrapScriptSyntaxAndAccountName(t *testing.T) {
	for name, script := range map[string]string{"invite": inviteServerScript, "join": joinInstallScript} {
		t.Run(name, func(t *testing.T) {
			cmd := exec.Command("sh", "-n")
			cmd.Stdin = strings.NewReader(script)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("invalid shell script: %v: %s", err, out)
			}
		})
	}
	for i := 0; i < 20; i++ {
		user, err := randomInvite()
		if err != nil {
			t.Fatal(err)
		}
		if !regexp.MustCompile(`^sshable_[0-9a-f]{10}$`).MatchString(user) {
			t.Fatalf("unexpected temporary username %q", user)
		}
	}
}
