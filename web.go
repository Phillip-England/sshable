package main

import (
	"crypto/rand"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/creack/pty"
)

//go:embed web/index.html web/app.js web/style.css web/vendor/xterm.js web/vendor/xterm.css web/vendor/addon-fit.js
var webFiles embed.FS

type webSession struct {
	id           string
	action       string
	name         string
	newName      string
	output       string
	outputBase   int64
	running      bool
	success      bool
	started      time.Time
	terminal     *os.File
	cmd          *exec.Cmd
	disconnected bool
}

type webApp struct {
	mu      sync.Mutex
	token   string
	session *webSession
	self    string
}

type actionRequest struct {
	Action    string `json:"action"`
	Name      string `json:"name"`
	Target    string `json:"target"`
	Port      int    `json:"port"`
	Identity  string `json:"identity"`
	NewName   string `json:"newName"`
	NewUser   string `json:"newUser"`
	TempUser  string `json:"tempUser"`
	PublicKey string `json:"publicKey"`
}

type hostView struct {
	Name string `json:"name"`
	host
	PublicKey  string `json:"publicKey"`
	KeyPresent bool   `json:"keyPresent"`
}

func serveCommand(args []string) error {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	port := flags.Int("port", 0, "local HTTP port (0 chooses an available port)")
	noOpen := flags.Bool("no-open", false, "do not open a browser automatically")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *port < 0 || *port > 65535 {
		return errors.New("usage: sshable serve [--port PORT] [--no-open]")
	}
	listener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(*port)))
	if err != nil {
		return err
	}
	defer listener.Close()
	app, err := newWebApp()
	if err != nil {
		return err
	}
	url := "http://" + listener.Addr().String()
	fmt.Println("sshable local web app:", url)
	fmt.Println("Close it with Ctrl+C. This page is available only on this computer.")
	if !*noOpen {
		openBrowser(url)
	}
	return http.Serve(listener, app.routes())
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}

func newWebApp() (*webApp, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	return &webApp{token: hex.EncodeToString(secret), self: self}, nil
}

func (a *webApp) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", a.page)
	mux.HandleFunc("GET /app.js", a.asset)
	mux.HandleFunc("GET /style.css", a.asset)
	mux.HandleFunc("GET /vendor/xterm.js", a.asset)
	mux.HandleFunc("GET /vendor/xterm.css", a.asset)
	mux.HandleFunc("GET /vendor/addon-fit.js", a.asset)
	mux.HandleFunc("GET /api/state", a.state)
	mux.HandleFunc("GET /api/session", a.sessionState)
	mux.HandleFunc("POST /api/action", a.action)
	mux.HandleFunc("POST /api/input", a.input)
	mux.HandleFunc("POST /api/resize", a.resize)
	mux.HandleFunc("POST /api/disconnect", a.disconnect)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !localRequest(r) {
			http.Error(w, "Local address required", http.StatusForbidden)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		mux.ServeHTTP(w, r)
	})
}

func (a *webApp) asset(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/")
	if name != "app.js" && name != "style.css" && name != "vendor/xterm.js" && name != "vendor/xterm.css" && name != "vendor/addon-fit.js" {
		http.NotFound(w, r)
		return
	}
	if strings.HasSuffix(name, ".js") {
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	} else {
		w.Header().Set("Content-Type", "text/css; charset=utf-8")
	}
	data, err := webFiles.ReadFile("web/" + name)
	if err != nil {
		http.Error(w, "Missing asset", 500)
		return
	}
	_, _ = w.Write(data)
}

func localRequest(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.Host)
	if err != nil || (host != "127.0.0.1" && host != "localhost") {
		return false
	}
	if r.Method == http.MethodPost {
		origin := r.Header.Get("Origin")
		if origin != "" && origin != "http://"+r.Host {
			return false
		}
	}
	return true
}

func (a *webApp) page(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data, _ := webFiles.ReadFile("web/index.html")
	_, _ = w.Write(data)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (a *webApp) state(w http.ResponseWriter, r *http.Request) {
	c, err := loadConfig()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	views := make([]hostView, 0, len(c.Hosts))
	for _, name := range sortedNames(c.Hosts) {
		h := c.Hosts[name]
		v := hostView{Name: name, host: h}
		if _, err := os.Stat(h.Identity); err == nil {
			v.KeyPresent = true
		}
		if pub, err := os.ReadFile(h.Identity + ".pub"); err == nil && validPublicKey(pub) {
			v.PublicKey = strings.TrimSpace(string(pub))
		}
		views = append(views, v)
	}
	writeJSON(w, map[string]any{"token": a.token, "hosts": views})
}

func (a *webApp) sessionState(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.session == nil {
		writeJSON(w, map[string]any{"session": nil})
		return
	}
	s := a.session
	if s.action == "connect" && r.URL.Query().Has("offset") {
		offset, err := strconv.ParseInt(r.URL.Query().Get("offset"), 10, 64)
		if err != nil || offset < 0 {
			http.Error(w, "Invalid output offset", 400)
			return
		}
		end := s.outputBase + int64(len(s.output))
		reset := offset < s.outputBase || offset > end
		if reset {
			offset = s.outputBase
		}
		chunk := s.output[offset-s.outputBase:]
		writeJSON(w, map[string]any{"session": map[string]any{"id": s.id, "action": s.action, "name": s.name, "newName": s.newName, "chunk": base64.StdEncoding.EncodeToString([]byte(chunk)), "offset": end, "reset": reset, "running": s.running, "success": s.success, "started": s.started}})
		return
	}
	writeJSON(w, map[string]any{"session": map[string]any{"id": s.id, "action": s.action, "name": s.name, "newName": s.newName, "output": s.output, "running": s.running, "success": s.success, "started": s.started}})
}

func (a *webApp) authorized(r *http.Request) bool {
	return r.Header.Get("X-Sshable-Token") == a.token && r.Header.Get("Content-Type") == "application/json"
}

func (a *webApp) action(w http.ResponseWriter, r *http.Request) {
	if !a.authorized(r) {
		http.Error(w, "Invalid local request", http.StatusForbidden)
		return
	}
	var req actionRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		http.Error(w, "Invalid request", 400)
		return
	}
	args, tempPath, err := prepareWebAction(req)
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.session != nil && a.session.running {
		if tempPath != "" {
			_ = os.Remove(tempPath)
		}
		http.Error(w, "Finish the current action first", 409)
		return
	}
	idBytes := make([]byte, 12)
	if _, err := rand.Read(idBytes); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	cmd := exec.Command(a.self, args...)
	if req.Action == "connect" {
		h, lookupErr := lookup(req.Name)
		if lookupErr != nil {
			http.Error(w, lookupErr.Error(), 400)
			return
		}
		cmd = exec.Command("ssh", sshArgs(h)...)
		cmd.Env = append(os.Environ(), "TERM=xterm-256color")
	}
	var terminal *os.File
	if req.Action == "connect" {
		terminal, err = pty.StartWithSize(cmd, &pty.Winsize{Rows: 30, Cols: 100})
	} else {
		terminal, err = pty.Start(cmd)
	}
	if err != nil {
		if tempPath != "" {
			_ = os.Remove(tempPath)
		}
		http.Error(w, err.Error(), 500)
		return
	}
	s := &webSession{id: hex.EncodeToString(idBytes), action: req.Action, name: req.Name, newName: req.NewName, running: true, started: time.Now(), terminal: terminal, cmd: cmd}
	a.session = s
	go a.capture(s, cmd, tempPath)
	writeJSON(w, map[string]string{"id": s.id})
}

func (a *webApp) capture(s *webSession, cmd *exec.Cmd, tempPath string) {
	defer func() {
		if tempPath != "" {
			_ = os.Remove(tempPath)
		}
	}()
	buf := make([]byte, 4096)
	terminal := s.terminal
	for {
		n, err := terminal.Read(buf)
		if n > 0 {
			a.mu.Lock()
			s.output += string(buf[:n])
			if len(s.output) > 128<<10 {
				if s.action == "connect" {
					removed := len(s.output) - (96 << 10)
					s.output = s.output[removed:]
					s.outputBase += int64(removed)
				} else {
					s.output = "[Earlier output omitted]\n" + s.output[len(s.output)-(96<<10):]
				}
			}
			a.mu.Unlock()
		}
		if err != nil {
			break
		}
	}
	err := cmd.Wait()
	_ = terminal.Close()
	a.mu.Lock()
	if s.disconnected {
		s.output += "\nDisconnected.\n"
		s.success = true
	} else if err != nil {
		s.output += "\nAction failed: " + err.Error() + "\n"
	} else {
		if s.action == "connect" {
			s.output += "\nConnection closed.\n"
		} else {
			s.output += "\nAction completed.\n"
		}
		s.success = true
	}
	s.running = false
	s.terminal = nil
	a.mu.Unlock()
}

func (a *webApp) input(w http.ResponseWriter, r *http.Request) {
	if !a.authorized(r) {
		http.Error(w, "Invalid local request", 403)
		return
	}
	var body struct {
		ID     string `json:"id"`
		Line   string `json:"line"`
		Data   string `json:"data"`
		Binary string `json:"binary"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body); err != nil {
		http.Error(w, "Invalid input", 400)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.session == nil || a.session.id != body.ID || !a.session.running || a.session.terminal == nil {
		http.Error(w, "Session is no longer running", 409)
		return
	}
	var input []byte
	if a.session.action == "connect" {
		if body.Binary != "" {
			var err error
			input, err = base64.StdEncoding.DecodeString(body.Binary)
			if err != nil {
				http.Error(w, "Invalid terminal input", 400)
				return
			}
		} else {
			input = []byte(body.Data)
		}
		if len(input) == 0 || len(input) > 16<<10 {
			http.Error(w, "Terminal input must be 1–16384 bytes", 400)
			return
		}
	} else {
		if strings.ContainsAny(body.Line, "\r\n\x00") {
			http.Error(w, "Enter one line at a time", 400)
			return
		}
		input = []byte(body.Line + "\n")
	}
	if _, err := a.session.terminal.Write(input); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (a *webApp) resize(w http.ResponseWriter, r *http.Request) {
	if !a.authorized(r) {
		http.Error(w, "Invalid local request", 403)
		return
	}
	var body struct {
		ID   string `json:"id"`
		Cols uint16 `json:"cols"`
		Rows uint16 `json:"rows"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&body); err != nil || body.Cols < 20 || body.Cols > 500 || body.Rows < 5 || body.Rows > 300 {
		http.Error(w, "Invalid terminal size", 400)
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.session == nil || a.session.id != body.ID || a.session.action != "connect" || !a.session.running || a.session.terminal == nil {
		http.Error(w, "Session is no longer running", 409)
		return
	}
	if err := pty.Setsize(a.session.terminal, &pty.Winsize{Cols: body.Cols, Rows: body.Rows}); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (a *webApp) disconnect(w http.ResponseWriter, r *http.Request) {
	if !a.authorized(r) {
		http.Error(w, "Invalid local request", 403)
		return
	}
	var body struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&body); err != nil {
		http.Error(w, "Invalid request", 400)
		return
	}
	a.mu.Lock()
	if a.session == nil || a.session.id != body.ID || a.session.action != "connect" || !a.session.running {
		a.mu.Unlock()
		http.Error(w, "Session is no longer running", 409)
		return
	}
	s := a.session
	s.disconnected = true
	terminal := s.terminal
	cmd := s.cmd
	a.mu.Unlock()
	_ = terminal.Close()
	_ = cmd.Process.Kill()
	writeJSON(w, map[string]bool{"ok": true})
}

func prepareWebAction(r actionRequest) ([]string, string, error) {
	if r.Action == "add" || r.Action == "join" {
		if !namePattern.MatchString(r.Name) {
			return nil, "", errors.New("Choose a valid connection name")
		}
		if _, _, err := parseTarget(r.Target); err != nil {
			return nil, "", err
		}
		if r.Port < 1 || r.Port > 65535 {
			return nil, "", errors.New("Port must be 1–65535")
		}
		args := []string{r.Action, "--port", strconv.Itoa(r.Port)}
		if r.Identity != "" {
			args = append(args, "--identity", r.Identity)
		}
		args = append(args, r.Name, r.Target)
		if r.Action == "join" {
			if !strings.HasPrefix(r.TempUser, "sshable_") || !userPattern.MatchString(r.TempUser) {
				return nil, "", errors.New("Invalid temporary username")
			}
			args = append(args, r.TempUser)
		}
		return args, "", nil
	}
	if !namePattern.MatchString(r.Name) {
		return nil, "", errors.New("Select a saved connection")
	}
	if _, err := lookup(r.Name); err != nil {
		return nil, "", err
	}
	switch r.Action {
	case "connect":
		return []string{"connect", r.Name}, "", nil
	case "copy-id", "secure", "invite", "audit", "remove":
		return []string{r.Action, r.Name}, "", nil
	case "rename":
		if !namePattern.MatchString(r.NewName) {
			return nil, "", errors.New("Choose a valid new connection name")
		}
		return []string{"rename", r.Name, r.NewName}, "", nil
	case "keycheck":
		return []string{"test", r.Name}, "", nil
	case "provision":
		if !namePattern.MatchString(r.NewName) || !userPattern.MatchString(r.NewUser) || r.NewUser == "root" {
			return nil, "", errors.New("Choose a valid new name and non-root user")
		}
		return []string{"provision", r.Name, r.NewName, r.NewUser}, "", nil
	case "revoke-root":
		return []string{"revoke-key", "--user", "root", r.Name}, "", nil
	case "authorize":
		pub := strings.TrimSpace(r.PublicKey)
		if !validPublicKey([]byte(pub)) {
			return nil, "", errors.New("Paste one valid public key line")
		}
		f, err := os.CreateTemp("", "sshable-public-*.pub")
		if err != nil {
			return nil, "", err
		}
		if err := f.Chmod(0600); err != nil {
			f.Close()
			os.Remove(f.Name())
			return nil, "", err
		}
		if _, err := io.WriteString(f, pub+"\n"); err != nil {
			f.Close()
			os.Remove(f.Name())
			return nil, "", err
		}
		if err := f.Close(); err != nil {
			os.Remove(f.Name())
			return nil, "", err
		}
		return []string{"authorize-key", r.Name, f.Name()}, f.Name(), nil
	}
	return nil, "", errors.New("Unknown action")
}
