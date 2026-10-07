package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWebServesLocalAssetsAndRejectsUntrustedActions(t *testing.T) {
	app, err := newWebApp()
	if err != nil {
		t.Fatal(err)
	}
	handler := app.routes()
	for _, path := range []string{"/", "/app.js", "/style.css", "/vendor/xterm.js", "/vendor/xterm.css", "/vendor/addon-fit.js"} {
		req := httptest.NewRequest("GET", "http://127.0.0.1:4000"+path, nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		if response.Code != 200 || response.Body.Len() == 0 {
			t.Fatalf("%s: status %d, body %q", path, response.Code, response.Body.String())
		}
	}
	request := httptest.NewRequest("POST", "http://127.0.0.1:4000/api/action", strings.NewReader(`{"action":"remove","name":"test"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("request without token: %d", response.Code)
	}
	request = httptest.NewRequest("POST", "http://127.0.0.1:4000/api/action", strings.NewReader(`{"action":"remove","name":"test"}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Sshable-Token", app.token)
	request.Header.Set("Origin", "http://evil.example")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("foreign origin: %d", response.Code)
	}
}

func TestWebHostViewAndPublicKeyValidation(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	identity := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(identity, []byte("private placeholder"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(identity+".pub", []byte(testPublicKey()+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := saveConfig(config{Hosts: map[string]host{"work": {User: "alice", Host: "example.com", Port: 22, Identity: identity}}}); err != nil {
		t.Fatal(err)
	}
	app, err := newWebApp()
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "http://127.0.0.1:4000/api/state", nil)
	response := httptest.NewRecorder()
	app.routes().ServeHTTP(response, req)
	if response.Code != 200 {
		t.Fatal(response.Body.String())
	}
	var got struct {
		Hosts []struct {
			Name       string `json:"name"`
			User       string `json:"user"`
			PublicKey  string `json:"publicKey"`
			KeyPresent bool   `json:"keyPresent"`
		} `json:"hosts"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Hosts) != 1 || got.Hosts[0].Name != "work" || got.Hosts[0].User != "alice" || !got.Hosts[0].KeyPresent || got.Hosts[0].PublicKey != testPublicKey() {
		t.Fatalf("bad host view: %+v", got.Hosts)
	}
	if _, _, err := prepareWebAction(actionRequest{Action: "authorize", Name: "work", PublicKey: "not a key"}); err == nil {
		t.Fatal("accepted invalid public key")
	}
	args, _, err := prepareWebAction(actionRequest{Action: "rename", Name: "work", NewName: "new-work"})
	if err != nil || strings.Join(args, " ") != "rename work new-work" {
		t.Fatalf("rename action: args=%v err=%v", args, err)
	}
	if _, _, err := prepareWebAction(actionRequest{Action: "rename", Name: "work", NewName: "bad name"}); err == nil {
		t.Fatal("accepted invalid new name")
	}
	args, _, err = prepareWebAction(actionRequest{Action: "remove", Name: "work"})
	if err != nil || strings.Join(args, " ") != "remove work" {
		t.Fatalf("remove action: args=%v err=%v", args, err)
	}
	args, _, err = prepareWebAction(actionRequest{Action: "keycheck", Name: "work"})
	if err != nil || strings.Join(args, " ") != "test work" {
		t.Fatalf("key check action: args=%v err=%v", args, err)
	}
	args, _, err = prepareWebAction(actionRequest{Action: "connect", Name: "work"})
	if err != nil || strings.Join(args, " ") != "connect work" {
		t.Fatalf("connect action: args=%v err=%v", args, err)
	}
}

func TestWebConnectInteractiveInputAndDisconnect(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	if err := saveConfig(config{Hosts: map[string]host{"work": {User: "alice", Host: "example.com", Port: 2222, Identity: "/tmp/sshable-test-key"}}}); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	sshPath := filepath.Join(bin, "ssh")
	if err := os.WriteFile(sshPath, []byte("#!/bin/sh\nstty raw -echo\nprintf 'READY é\\r\\n'\ninput=$(dd bs=1 count=6 2>/dev/null)\nprintf 'GOT:%s\\r\\n' \"$input\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	app, err := newWebApp()
	if err != nil {
		t.Fatal(err)
	}
	handler := app.routes()
	post := func(path, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest("POST", "http://127.0.0.1:4000"+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Sshable-Token", app.token)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		return response
	}
	getSession := func() struct {
		Session struct {
			ID      string `json:"id"`
			Output  string `json:"output"`
			Running bool   `json:"running"`
			Success bool   `json:"success"`
		} `json:"session"`
	} {
		t.Helper()
		req := httptest.NewRequest("GET", "http://127.0.0.1:4000/api/session", nil)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, req)
		var result struct {
			Session struct {
				ID      string `json:"id"`
				Output  string `json:"output"`
				Running bool   `json:"running"`
				Success bool   `json:"success"`
			} `json:"session"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	start := post("/api/action", `{"action":"connect","name":"work"}`)
	if start.Code != 200 {
		t.Fatalf("start connection: %d %s", start.Code, start.Body.String())
	}
	var started struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(start.Body.Bytes(), &started); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		app.mu.Lock()
		if app.session != nil && app.session.running {
			_ = app.session.terminal.Close()
			_ = app.session.cmd.Process.Kill()
		}
		app.mu.Unlock()
	})
	if response := post("/api/resize", `{"id":"`+started.ID+`","cols":90,"rows":25}`); response.Code != 200 {
		t.Fatalf("resize connection: %d %s", response.Code, response.Body.String())
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && !strings.Contains(getSession().Session.Output, "READY") {
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(getSession().Session.Output, "READY") {
		t.Fatal("SSH process did not start")
	}
	if response := post("/api/input", `{"id":"`+started.ID+`","data":"héllo"}`); response.Code != 200 {
		t.Fatalf("send input: %d %s", response.Code, response.Body.String())
	}
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		current := getSession().Session
		if !current.Running {
			if !current.Success || !strings.Contains(current.Output, "GOT:héllo") {
				t.Fatalf("interactive session failed: %+v", current)
			}
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if getSession().Session.Running {
		t.Fatal("interactive session did not finish")
	}
	streamReq := httptest.NewRequest("GET", "http://127.0.0.1:4000/api/session?offset=0", nil)
	streamResponse := httptest.NewRecorder()
	handler.ServeHTTP(streamResponse, streamReq)
	var stream struct {
		Session struct {
			Chunk  string `json:"chunk"`
			Offset int64  `json:"offset"`
		} `json:"session"`
	}
	if err := json.Unmarshal(streamResponse.Body.Bytes(), &stream); err != nil {
		t.Fatal(err)
	}
	chunk, err := base64.StdEncoding.DecodeString(stream.Session.Chunk)
	if err != nil || !strings.Contains(string(chunk), "GOT:héllo") || !strings.Contains(string(chunk), "READY é") || stream.Session.Offset != int64(len(chunk)) {
		t.Fatalf("incremental terminal output: %q, offset %d, error %v", chunk, stream.Session.Offset, err)
	}
	if err := os.WriteFile(sshPath, []byte("#!/bin/sh\nstty raw -echo\nexec cat >/dev/null\n"), 0700); err != nil {
		t.Fatal(err)
	}
	start = post("/api/action", `{"action":"connect","name":"work"}`)
	if start.Code != 200 {
		t.Fatalf("start second connection: %d %s", start.Code, start.Body.String())
	}
	if err := json.Unmarshal(start.Body.Bytes(), &started); err != nil {
		t.Fatal(err)
	}
	if response := post("/api/disconnect", `{"id":"`+started.ID+`"}`); response.Code != 200 {
		t.Fatalf("disconnect: %d %s", response.Code, response.Body.String())
	}
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && getSession().Session.Running {
		time.Sleep(20 * time.Millisecond)
	}
	current := getSession().Session
	if current.Running || !current.Success || !strings.Contains(current.Output, "Disconnected.") {
		t.Fatalf("disconnect did not stop SSH: %+v", current)
	}
}

func TestServeRejectsInvalidPort(t *testing.T) {
	if err := serveCommand([]string{"--port", "65536", "--no-open"}); err == nil || !strings.Contains(err.Error(), "sshable serve") {
		t.Fatalf("unexpected serve validation: %v", err)
	}
}
