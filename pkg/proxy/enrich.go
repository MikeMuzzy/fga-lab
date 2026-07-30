package proxy

import (
	"fmt"
	"net/http"

	"podmanproxy/internal/authz"
	"podmanproxy/internal/podman"
)

// Enricher derives request-scoped facts (contextual tuples) for a subject.
// Enrichers run once per request, and their output applies to every check in
// the batch and to list filtering, so checks and lists evaluate against the
// same world.
type Enricher interface {
	Facts(r *http.Request, sub authz.Subject) ([]authz.Tuple, error)
}

// GroupEnricher asserts the subject's OS group membership from peer creds.
// The OS group database is the system of record; FGA sees a read-through
// view per request rather than a synced copy that can go stale.
type GroupEnricher struct{}

func (GroupEnricher) Facts(_ *http.Request, sub authz.Subject) ([]authz.Tuple, error) {
	// Primary GID from SO_PEERCRED. For supplementary groups, resolve via
	// the user database (user.LookupId + GroupIds) and emit one fact each,
	// cached per uid with a short TTL since this runs on every request.
	return []authz.Tuple{authz.GroupMembership(sub, sub.GID)}, nil
}

// ExecEnricher joins /exec/{sid}/... requests to their parent container via
// the session store, so exec_session#can_start resolves through the
// container's can_exec.
type ExecEnricher struct{ Sessions *podman.SessionStore }

func (e ExecEnricher) Facts(r *http.Request, _ authz.Subject) ([]authz.Tuple, error) {
	sid := r.PathValue("sid")
	if sid == "" {
		return nil, nil // not an exec-session route
	}
	cid, ok := e.Sessions.Get(sid)
	if !ok {
		// Unknown session: assert no join, so the check denies. Returning an
		// error here would leak session-id validity through 503 versus 403.
		return nil, nil
	}
	return []authz.Tuple{authz.ExecSessionContainer(sid, cid)}, nil
}

// RunEnrichers collects facts from all enrichers, failing closed on error:
// proceeding with fewer facts would change authorization inputs invisibly.
func RunEnrichers(es []Enricher, r *http.Request, sub authz.Subject) ([]authz.Tuple, error) {
	var facts []authz.Tuple
	for _, e := range es {
		f, err := e.Facts(r, sub)
		if err != nil {
			return nil, fmt.Errorf("enricher %T: %w", e, err)
		}
		facts = append(facts, f...)
	}
	return facts, nil
}
