package proxy

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strconv"

	"podmanproxy/internal/podman"
)

// modifyResponse runs the post-forward hooks. Each is a no-op unless its
// route opted in via a context marker, so streaming endpoints (logs, attach,
// events, exec streams) are never buffered.
func (s *Server) modifyResponse(resp *http.Response) error {
	if err := filterList(resp); err != nil {
		return err
	}
	if err := s.recordExecSession(resp); err != nil {
		return err
	}
	return s.recordOwnership(resp)
}

// filterList intersects podman's list response with the subject's visible
// set. User-supplied filters are never passed through and trusted.
func filterList(resp *http.Response) error {
	ids, ok := visibleIDsFrom(resp.Request.Context())
	if !ok || resp.StatusCode != http.StatusOK {
		return nil
	}
	var items []map[string]json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
		return err
	}
	resp.Body.Close()

	kept := items[:0]
	for _, it := range items {
		var id string
		_ = json.Unmarshal(it["Id"], &id)
		if ids[id] {
			kept = append(kept, it)
		}
	}
	return replaceBody(resp, kept)
}

// recordExecSession captures sid -> container from exec-create responses so
// ExecEnricher can assert the join on subsequent requests.
func (s *Server) recordExecSession(resp *http.Response) error {
	cid, ok := execParentFrom(resp.Request.Context())
	if !ok || resp.StatusCode != http.StatusCreated {
		return nil
	}
	created, err := peekCreated(resp)
	if err != nil || created.ID == "" {
		return err
	}
	s.sessions.Put(created.ID, cid)
	return nil
}

// recordOwnership writes owner tuples after a successful create.
//
// Synchronous on purpose: failing the request beats an orphaned, unowned
// resource. A tuple-write failure surfaces as 502 after the resource exists,
// which is visible and alertable; a reconciler sweeping for resources
// without owner tuples is the recovery path.
func (s *Server) recordOwnership(resp *http.Response) error {
	own, ok := ownershipFrom(resp.Request.Context())
	if !ok || resp.StatusCode != http.StatusCreated {
		return nil
	}
	created, err := peekCreated(resp)
	if err != nil || created.ID == "" {
		return err
	}
	ctx := resp.Request.Context()
	if err := s.tuples.WriteOwnership(ctx, own.subject, own.objType, created.ID); err != nil {
		return err
	}
	s.audit.Grant(ctx, requestIDFrom(ctx), own.subject.String(), "owner",
		own.objType+":"+created.ID)
	return nil
}

// peekCreated reads the created-resource id and restores the body.
func peekCreated(resp *http.Response) (podman.CreatedResource, error) {
	var created podman.CreatedResource
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return created, err
	}
	resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(body))

	if err := json.Unmarshal(body, &created); err != nil {
		return created, nil // non-JSON create response: nothing to record
	}
	return created, nil
}

func replaceBody(resp *http.Response, v any) error {
	buf, err := json.Marshal(v)
	if err != nil {
		return err
	}
	resp.Body = io.NopCloser(bytes.NewReader(buf))
	resp.ContentLength = int64(len(buf))
	resp.Header.Set("Content-Length", strconv.Itoa(len(buf)))
	return nil
}
