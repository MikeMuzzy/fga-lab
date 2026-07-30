// Package podman holds the backend transport and the narrow subset of the
// Podman API surface the proxy inspects.
package podman

// The spec types below are hand-defined rather than imported from
// github.com/containers/podman/v5 on purpose: that module drags buildah,
// containers/storage and containers/image into a security-critical binary,
// inflating audit surface, build time and CVE noise for the dozen fields we
// actually read.
//
// Mirrors the libpod v5 API. When bumping the supported Podman version,
// re-record testdata/ payloads and run the compat tests.

// CreateSpec is the subset of the container-create body used for
// authorization decisions.
type CreateSpec struct {
	Image    string            `json:"image"`
	Volumes  []NamedVolume     `json:"volumes"`
	Networks map[string]any    `json:"Networks"`
	Mounts   []Mount           `json:"mounts"`
	Labels   map[string]string `json:"labels"`
}

// NamedVolume is a podman-managed volume mount.
type NamedVolume struct {
	Name string `json:"Name"`
	Dest string `json:"Dest"`
}

// Mount is an OCI mount; Type "bind" exposes a host path to the container
// and is therefore authorized against host#can_mount_src.
type Mount struct {
	Type        string   `json:"Type"`
	Source      string   `json:"Source"`
	Destination string   `json:"Destination"`
	Options     []string `json:"Options"`
}

// BindMounts returns only the bind-type mounts, which are the ones that
// require a host path grant.
func (s CreateSpec) BindMounts() []Mount {
	var out []Mount
	for _, m := range s.Mounts {
		if m.Type == "bind" {
			out = append(out, m)
		}
	}
	return out
}

// CreatedResource is the common shape of create responses.
type CreatedResource struct {
	ID string `json:"Id"`
}
