package main

import (
	"slices"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestKeyOnlySSHArgs(t *testing.T) {
	h := host{User: "alice", Host: "server.example.com", Port: 2222, Identity: "/tmp/client-key"}
	args := keyOnlySSHArgs(h)
	for _, want := range []string{
		"PreferredAuthentications=publickey",
		"PasswordAuthentication=no",
		"KbdInteractiveAuthentication=no",
		"IdentitiesOnly=yes",
	} {
		if !slices.Contains(args, want) {
			t.Errorf("key-only test omitted %s", want)
		}
	}
	if got := strings.Join(args[len(args)-3:], " "); got != "-- alice@server.example.com true" {
		t.Errorf("unexpected test target: %s", got)
	}
}

func TestHostViewExplainsKeyLocations(t *testing.T) {
	m := tuiModel{
		screen: hostScreen,
		name:   "work",
		hosts: config{Hosts: map[string]host{
			"work": {User: "alice", Host: "example.com", Port: 22, Identity: "/tmp/work-key"},
		}},
	}
	view := m.View()
	for _, want := range []string{"PRIVATE key on this computer", "/tmp/work-key.pub", "~/.ssh/authorized_keys", "status    unknown"} {
		if !strings.Contains(view, want) {
			t.Errorf("host view omitted %q", want)
		}
	}
}

func TestAddFormRejectsInvalidTargetBeforeRunningCommand(t *testing.T) {
	m := tuiModel{screen: addScreen, field: 3, fields: [4]string{"work", "bad target", "22", ""}}
	updated, cmd := m.updateAdd(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd != nil {
		t.Fatal("invalid target launched a command")
	}
	if !strings.Contains(updated.(tuiModel).err, "USER@HOST") {
		t.Fatal("invalid target was not explained")
	}
}
