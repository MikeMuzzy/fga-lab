package authz

import (
	"fmt"
	"log/slog"
)

// Tuple is a request-scoped fact asserted by the proxy at check time, never
// persisted. Fields are unexported: facts can only be minted through the
// constructors below, so no caller can assert an arbitrary relationship.
//
// Discipline rule: contextual tuples are for facts whose system of record is
// legitimately outside FGA (the OS group database, the proxy's session
// store). Facts FGA owns — ownership, shares, grants — are persisted tuples.
// Deliberately, no constructor here can assert owner/shared/grant relations.
type Tuple struct {
	user     string
	relation string
	object   string
}

// Accessors for adapters translating to wire types.
func (t Tuple) User() string     { return t.user }
func (t Tuple) Relation() string { return t.relation }
func (t Tuple) Object() string   { return t.object }

func (t Tuple) String() string {
	return fmt.Sprintf("%s %s %s", t.user, t.relation, t.object)
}

func (t Tuple) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("user", t.user),
		slog.String("relation", t.relation),
		slog.String("object", t.object),
	)
}

// GroupMembership asserts OS group membership at check time, sourced from
// the host's group database instead of tuples synced into FGA.
func GroupMembership(sub Subject, gid uint32) Tuple {
	return Tuple{
		user:     sub.String(),
		relation: "member",
		object:   fmt.Sprintf("group:gid-%d", gid),
	}
}

// ExecSessionContainer joins a podman exec session to its parent container,
// sourced from the proxy's session store. exec_session#can_start then
// resolves through the container's can_exec.
func ExecSessionContainer(sessionID, containerID string) Tuple {
	return Tuple{
		user:     "container:" + containerID,
		relation: "container",
		object:   "exec_session:" + sessionID,
	}
}

// FactShape is a (type, relation) pair a constructor above can assert.
// Adapters validate these against the deployed model at startup, so shape
// drift is a failed deploy rather than per-request 400s from the server.
type FactShape struct{ ObjType, Relation string }

// FactShapes enumerates every shape the constructors can produce.
func FactShapes() []FactShape {
	return []FactShape{
		{"group", "member"},
		{"exec_session", "container"},
	}
}
