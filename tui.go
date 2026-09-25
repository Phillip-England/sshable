package main

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

type screen int

const (
	homeScreen screen = iota
	addScreen
	hostScreen
	keysScreen
	serverScreen
	removeScreen
)

type actionFinished struct {
	name string
	err  error
}

type tuiModel struct {
	screen   screen
	origin   screen
	hosts    config
	names    []string
	selected int
	name     string
	fields   [4]string
	field    int
	status   string
	err      string
}

func tuiCommand() error {
	info, err := os.Stdin.Stat()
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeCharDevice == 0 {
		return fmt.Errorf("the terminal interface needs an interactive terminal (run 'sshable help' for commands)")
	}
	m := tuiModel{}
	if err := m.reload(); err != nil {
		return err
	}
	_, err = tea.NewProgram(m, tea.WithAltScreen()).Run()
	return err
}

func (m *tuiModel) reload() error {
	c, err := loadConfig()
	if err != nil {
		return err
	}
	m.hosts = c
	m.names = sortedNames(c.Hosts)
	if len(m.names) == 0 {
		m.selected = 0
	} else if m.selected >= len(m.names) {
		m.selected = len(m.names) - 1
	}
	return nil
}

func (m tuiModel) Init() tea.Cmd { return nil }

func (m tuiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case actionFinished:
		if msg.err != nil {
			m.err = fmt.Sprintf("%s failed: %v", msg.name, msg.err)
			m.status = ""
		} else {
			m.status = msg.name + " finished."
			if msg.name == "Key login test" {
				m.status = "Key login worked without a server password."
			}
			m.err = ""
		}
		if err := m.reload(); err != nil {
			m.err = err.Error()
		}
		if m.screen == addScreen && msg.err == nil {
			m.screen = homeScreen
			for i, name := range m.names {
				if name == strings.TrimSpace(m.fields[0]) {
					m.selected = i
					break
				}
			}
			m.status = "Server saved. Press Enter, then p to install its public key or c to connect with a password."
		}
		return m, nil
	case tea.KeyMsg:
		key := msg.String()
		if key == "ctrl+c" {
			return m, tea.Quit
		}
		if m.screen == addScreen {
			return m.updateAdd(msg)
		}
		if key == "esc" || key == "b" {
			switch m.screen {
			case keysScreen, serverScreen:
				m.screen = m.origin
			case removeScreen:
				m.screen = hostScreen
			default:
				m.screen = homeScreen
			}
			m.err = ""
			return m, nil
		}
		switch m.screen {
		case homeScreen:
			switch key {
			case "q":
				return m, tea.Quit
			case "up", "k":
				if m.selected > 0 {
					m.selected--
				}
			case "down", "j":
				if m.selected+1 < len(m.names) {
					m.selected++
				}
			case "enter":
				if len(m.names) > 0 {
					m.name = m.names[m.selected]
					m.screen = hostScreen
				}
			case "a":
				m.fields = [4]string{"", "", "22", ""}
				m.field = 0
				m.screen = addScreen
				m.err = ""
			case "?":
				m.origin = homeScreen
				m.screen = keysScreen
			case "s":
				m.origin = homeScreen
				m.screen = serverScreen
			}
		case hostScreen:
			h, ok := m.hosts.Hosts[m.name]
			if !ok {
				m.screen = homeScreen
				break
			}
			switch key {
			case "c":
				return m, externalAction("Connection", "ssh", sshArgs(h)...)
			case "p":
				return m, externalAction("Public key installation", os.Args[0], "copy-id", m.name)
			case "t":
				return m, externalAction("Key login test", "ssh", keyOnlySSHArgs(h)...)
			case "d":
				m.screen = removeScreen
			case "?":
				m.origin = hostScreen
				m.screen = keysScreen
			case "s":
				m.origin = hostScreen
				m.screen = serverScreen
			}
		case keysScreen:
			if key == "g" {
				return m, externalAction("Key generation", os.Args[0], "keygen")
			}
		case removeScreen:
			if key == "y" {
				if err := removeHost(m.name); err != nil {
					m.err = err.Error()
				} else {
					m.status = "Removed saved host " + m.name + ". Its keys and server access were not changed."
					m.err = ""
					m.screen = homeScreen
					if err := m.reload(); err != nil {
						m.err = err.Error()
					}
				}
			} else if key == "n" {
				m.screen = hostScreen
			}
		}
		return m, nil
	}
	return m, nil
}

func (m tuiModel) updateAdd(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc":
		m.screen = homeScreen
		m.err = ""
	case "tab", "down":
		m.field = (m.field + 1) % len(m.fields)
	case "shift+tab", "up":
		m.field = (m.field + len(m.fields) - 1) % len(m.fields)
	case "enter":
		if m.field < len(m.fields)-1 {
			m.field++
			return m, nil
		}
		name := strings.TrimSpace(m.fields[0])
		target := strings.TrimSpace(m.fields[1])
		port := strings.TrimSpace(m.fields[2])
		identity := strings.TrimSpace(m.fields[3])
		if !namePattern.MatchString(name) {
			m.err = "Name must start with a letter or digit and use letters, digits, dots, _ or -."
			return m, nil
		}
		if _, _, err := parseTarget(target); err != nil {
			m.err = "Enter the server as USER@HOST, for example alice@server.example.com."
			return m, nil
		}
		portNumber, err := strconv.Atoi(port)
		if err != nil || portNumber < 1 || portNumber > 65535 {
			m.err = "Port must be a number from 1 to 65535."
			return m, nil
		}
		if _, exists := m.hosts.Hosts[name]; exists {
			m.err = "That name is already saved. Choose another."
			return m, nil
		}
		args := []string{"add", "--port", port}
		if identity != "" {
			args = append(args, "--identity", identity)
		}
		args = append(args, name, target)
		m.err = ""
		return m, externalAction("Add host", os.Args[0], args...)
	case "backspace", "ctrl+h":
		value := []rune(m.fields[m.field])
		if len(value) > 0 {
			m.fields[m.field] = string(value[:len(value)-1])
		}
	default:
		if msg.Type == tea.KeyRunes {
			m.fields[m.field] += string(msg.Runes)
		}
	}
	return m, nil
}

func externalAction(label, executable string, args ...string) tea.Cmd {
	cmd := exec.Command(executable, args...)
	return tea.ExecProcess(cmd, func(err error) tea.Msg { return actionFinished{name: label, err: err} })
}

func keyOnlySSHArgs(h host) []string {
	return []string{
		"-p", strconv.Itoa(h.Port), "-i", h.Identity,
		"-o", "IdentitiesOnly=yes",
		"-o", "PreferredAuthentications=publickey",
		"-o", "PasswordAuthentication=no",
		"-o", "KbdInteractiveAuthentication=no",
		"--", h.User + "@" + h.Host, "true",
	}
}

func removeHost(name string) error {
	c, err := loadConfig()
	if err != nil {
		return err
	}
	if _, ok := c.Hosts[name]; !ok {
		return fmt.Errorf("unknown host %q", name)
	}
	delete(c.Hosts, name)
	return saveConfig(c)
}

func fileState(path string) string {
	if _, err := os.Stat(path); err == nil {
		return "present"
	}
	return "missing"
}

func (m tuiModel) View() string {
	var b strings.Builder
	b.WriteString("SSHABLE  ·  SSH connections and keys\n")
	b.WriteString(strings.Repeat("─", 49) + "\n\n")
	switch m.screen {
	case homeScreen:
		b.WriteString("Saved connections\n\n")
		if len(m.names) == 0 {
			b.WriteString("  No servers saved yet. Press a to add one.\n")
		}
		for i, name := range m.names {
			marker := "  "
			if i == m.selected {
				marker = "› "
			}
			h := m.hosts.Hosts[name]
			fmt.Fprintf(&b, "%s%s  %s@%s:%d\n", marker, name, h.User, h.Host, h.Port)
		}
		b.WriteString("\nEnter details  ·  a add server  ·  ? understand keys\n")
		b.WriteString("s key-only server guide  ·  q quit\n")
	case addScreen:
		b.WriteString("Add a server\n")
		b.WriteString("This saves an address and creates a key pair on THIS computer.\n")
		b.WriteString("It does not install the public key on the server yet.\n\n")
		labels := []string{"Name (your nickname)", "Login (USER@HOST)", "SSH port", "Private key path (blank = shared default)"}
		for i, label := range labels {
			marker := "  "
			if i == m.field {
				marker = "› "
			}
			value := m.fields[i]
			if i == m.field {
				value += "▌"
			}
			fmt.Fprintf(&b, "%s%s\n    %s\n\n", marker, label, value)
		}
		defaultPath, _ := defaultIdentity()
		fmt.Fprintf(&b, "Default key: %s\n", defaultPath)
		b.WriteString("Tab next field  ·  Enter next/save  ·  Esc cancel\n")
	case hostScreen:
		h := m.hosts.Hosts[m.name]
		fmt.Fprintf(&b, "%s  ·  %s@%s:%d\n\n", m.name, h.User, h.Host, h.Port)
		fmt.Fprintf(&b, "PRIVATE key on this computer  %s (%s)\n", h.Identity, fileState(h.Identity))
		fmt.Fprintf(&b, "PUBLIC key on this computer   %s (%s)\n", h.Identity+".pub", fileState(h.Identity+".pub"))
		b.WriteString("PUBLIC key on server          ~/.ssh/authorized_keys\n")
		b.WriteString("Server installation status    unknown until you try a login\n\n")
		b.WriteString("p install public key (may ask for server password)\n")
		b.WriteString("t test key login (will not use a server password)\n")
		b.WriteString("c connect  ·  d remove saved server\n")
		b.WriteString("? understand keys  ·  s key-only guide  ·  b back\n")
	case keysScreen:
		defaultPath, _ := defaultIdentity()
		b.WriteString("How SSH keys work\n\n")
		b.WriteString("ssh-keygen creates TWO files on the client:\n")
		fmt.Fprintf(&b, "  Private: %s\n", defaultPath)
		fmt.Fprintf(&b, "  Public:  %s.pub\n\n", defaultPath)
		b.WriteString("The private key stays here. Never copy it to the server.\n")
		b.WriteString("'copy-id' sends the public key to the server account's\n")
		b.WriteString("~/.ssh/authorized_keys. You first log in with an existing\n")
		b.WriteString("method, usually the server account password.\n\n")
		b.WriteString("The KEY PASSPHRASE unlocks your local private key.\n")
		b.WriteString("The SERVER PASSWORD logs into the remote account.\n")
		b.WriteString("The server's HOST KEY is another key: it proves server identity.\n\n")
		b.WriteString("g create the default client key  ·  b back\n")
	case serverScreen:
		b.WriteString("Allow only key login on a server\n\n")
		b.WriteString("1. Install your public key from the client with 'copy-id'.\n")
		b.WriteString("2. Use 't' on the saved host to prove key login works.\n")
		b.WriteString("3. Keep an existing server session open while changing sshd.\n")
		b.WriteString("4. An administrator sets these in the server's sshd_config:\n\n")
		b.WriteString("     PubkeyAuthentication yes\n")
		b.WriteString("     AuthenticationMethods publickey\n")
		b.WriteString("     PasswordAuthentication no\n")
		b.WriteString("     KbdInteractiveAuthentication no\n\n")
		b.WriteString("5. Check the effective config with sshd -T, validate with\n")
		b.WriteString("   sshd -t, reload sshd, and test a NEW session before closing\n")
		b.WriteString("   the old one. Server commands vary by operating system.\n\n")
		b.WriteString("This setting lives on the SERVER, not in sshable.\n")
		b.WriteString("b back\n")
	case removeScreen:
		fmt.Fprintf(&b, "Remove saved server %q?\n\n", m.name)
		b.WriteString("This removes its address from sshable. It does not delete\n")
		b.WriteString("the key files or remove access from the server.\n\n")
		b.WriteString("y remove  ·  n cancel  ·  b back\n")
	}
	if m.err != "" {
		fmt.Fprintf(&b, "\nError: %s\n", m.err)
	}
	if m.status != "" {
		fmt.Fprintf(&b, "\n%s\n", m.status)
	}
	return b.String()
}
