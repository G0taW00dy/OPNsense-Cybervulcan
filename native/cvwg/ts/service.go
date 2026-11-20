package ts

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/G0taW00dy/opnsense-cybervulcan/native/cvwg/forward"
)

// Service is the engine plus its loopback forwarder, as driven by the app
// through the cvts_* exports. Methods take and return JSON. The zero value
// is ready to use and safe for concurrent use: Start, Down and Logout run one
// at a time, and Status never waits for them (so a UI polling Status does
// not freeze while the engine shuts down).
type Service struct {
	op sync.Mutex // serialises Start / Down / Logout

	mu  sync.Mutex // guards the fields below (held only briefly)
	eng *Engine
	fwd *forward.Forwarder
	cfg Config
}

func errJSON(err error) string {
	b, _ := json.Marshal(map[string]string{"error": err.Error()})
	return string(b)
}

func statusJSON(st Status) string {
	b, err := json.Marshal(st)
	if err != nil {
		return `{"error":"internal: json"}`
	}
	return string(b)
}

// same: equal settings, token included (a new token needs a new forwarder).
func (c *Config) same(o *Config) bool {
	return c.StateDir == o.StateDir && c.Hostname == o.Hostname && c.Target == o.Target &&
		c.Token == o.Token && c.ControlURL == o.ControlURL
}

// Start (re)starts the engine with cfgJSON (see Config) and returns the
// Status as JSON (state, authUrl, port, ...) or {"error": "..."}. A start
// with the same settings as the running engine keeps it and only reports.
func (s *Service) Start(cfgJSON string) string {
	var cfg Config
	if err := json.Unmarshal([]byte(cfgJSON), &cfg); err != nil {
		return errJSON(errors.New("bad Tailscale settings"))
	}
	if err := cfg.Validate(); err != nil {
		return errJSON(err)
	}
	s.op.Lock()
	defer s.op.Unlock()

	s.mu.Lock()
	keep := s.eng != nil && s.cfg.same(&cfg)
	s.mu.Unlock()
	if !keep {
		s.stop()
		eng, err := NewEngine(cfg.Options())
		if err != nil {
			return errJSON(err)
		}
		token, _ := forward.ParseToken(cfg.Token) // validated above
		target := cfg.Target
		fwd, err := forward.Start(token, func(ctx context.Context) (net.Conn, error) {
			return eng.DialContext(ctx, "tcp", target)
		}, eng.SetLastError)
		if err != nil {
			eng.Close()
			return errJSON(errors.New("cannot open the loopback port: " + err.Error()))
		}
		eng.Start()
		s.mu.Lock()
		s.eng, s.fwd, s.cfg = eng, fwd, cfg
		s.mu.Unlock()
	}
	return statusJSON(s.status(cfg.WaitMs))
}

// status reports, optionally waiting up to waitMs for a settled state.
func (s *Service) status(waitMs int) Status {
	s.mu.Lock()
	eng, fwd, target := s.eng, s.fwd, s.cfg.Target
	s.mu.Unlock()
	if eng == nil {
		return Status{State: StateStopped}
	}
	var st Status
	if waitMs > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(waitMs)*time.Millisecond)
		st = eng.AwaitSettled(ctx, target)
		cancel()
	} else {
		st = eng.Status(context.Background(), target)
	}
	st.Port = fwd.Port()
	return st
}

// Status returns the Status as JSON ({"up":false,"state":"stopped"} when down).
func (s *Service) Status() string { return statusJSON(s.status(0)) }

// stop detaches and shuts down the current engine (caller holds s.op).
func (s *Service) stop() *Engine {
	s.mu.Lock()
	eng, fwd := s.eng, s.fwd
	s.eng, s.fwd, s.cfg = nil, nil, Config{}
	s.mu.Unlock()
	if fwd != nil {
		fwd.Close()
	}
	return eng
}

// Down stops the engine and the forwarder; the login is kept.
func (s *Service) Down() {
	s.op.Lock()
	defer s.op.Unlock()
	if eng := s.stop(); eng != nil {
		eng.Close()
	}
}

// Logout signs out (best effort), stops and deletes the saved login.
// cfgJSON may carry {"stateDir": "..."} for when the engine is not running.
// Returns {"ok":true} or {"error":"..."}.
func (s *Service) Logout(cfgJSON string) string {
	var cfg Config
	if cfgJSON != "" {
		if err := json.Unmarshal([]byte(cfgJSON), &cfg); err != nil {
			return errJSON(errors.New("bad Tailscale settings"))
		}
	}
	s.op.Lock()
	defer s.op.Unlock()
	s.mu.Lock()
	dir := cfg.StateDir
	if dir == "" {
		dir = s.cfg.StateDir
	}
	s.mu.Unlock()
	var err error
	if eng := s.stop(); eng != nil {
		err = eng.Logout(context.Background())
	}
	if dir == "" {
		return errJSON(errors.New("state folder is missing"))
	}
	if err2 := RemoveState(dir); err2 != nil {
		return errJSON(err2)
	}
	if err != nil {
		return errJSON(err)
	}
	return `{"ok":true}`
}
