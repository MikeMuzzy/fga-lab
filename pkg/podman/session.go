package podman

import "sync"

// SessionStore maps podman exec session ids to their parent container ids.
//
// Podman's /exec/{sid}/start carries no container id, so the proxy records
// the mapping when the session is created and replays it as a contextual
// tuple at check time. In-memory is appropriate: sessions do not outlive
// either process.
type SessionStore struct {
	mu sync.RWMutex
	m  map[string]string
}

func NewSessionStore() *SessionStore {
	return &SessionStore{m: make(map[string]string)}
}

func (s *SessionStore) Put(sessionID, containerID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[sessionID] = containerID
}

func (s *SessionStore) Get(sessionID string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.m[sessionID]
	return id, ok
}

// Forget drops a session, called when its container is deleted or on TTL
// sweep, so ids cannot be reused against a stale mapping.
func (s *SessionStore) Forget(sessionID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, sessionID)
}
