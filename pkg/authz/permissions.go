package authz

// CanRecursiveList authorizes recursively listing (and, for the mount
// proxy, bind-mounting) a path under a filesystem object. The check must be
// bound with a Context carrying "requested_path" for the model's
// path_matches condition to evaluate.
//var CanRecursiveList = Permission{objType: "filesystem", relation: "can_recursive_list"}

// The catalog mirrors podman-authz.fga 1:1. ValidateModel refuses to boot if
// any pair here is absent from the deployed model, turning drift into a
// failed deploy instead of a runtime 403 mystery.
var (
	HostCreate     = Permission{"host", "can_create"}
	HostViewInfo   = Permission{"host", "can_view_info"}
	HostViewEvents = Permission{"host", "can_view_events"}
	HostPrune      = Permission{"host", "can_prune"}

	ContainerView    = Permission{"container", "can_view"}
	ContainerOperate = Permission{"container", "can_operate"}
	ContainerExec    = Permission{"container", "can_exec"}
	ContainerUpdate  = Permission{"container", "can_update"}
	ContainerDelete  = Permission{"container", "can_delete"}

	CanMount = Permission{"filesystem", "can_mount"}

	PodView    = Permission{"pod", "can_view"}
	PodOperate = Permission{"pod", "can_operate"}
	PodDelete  = Permission{"pod", "can_delete"}

	ImageUse    = Permission{"image", "can_use"}
	ImagePush   = Permission{"image", "can_push"}
	ImageDelete = Permission{"image", "can_delete"}

	VolumeMount  = Permission{"volume", "can_mount"}
	VolumeDelete = Permission{"volume", "can_delete"}

	NetworkConnect = Permission{"network", "can_connect"}
	NetworkDelete  = Permission{"network", "can_delete"}

	SecretUse    = Permission{"secret", "can_use"}
	SecretDelete = Permission{"secret", "can_delete"}
)

// all feeds ValidateModel. Append when adding entries above (or generate this
// file from the DSL with go:generate once the model stabilizes).
var all = []Permission{
	HostCreate, HostViewInfo, HostViewEvents, HostPrune,
	ContainerView, ContainerOperate, ContainerExec, ContainerUpdate, ContainerDelete,
	PodView, PodOperate, PodDelete,
	ImageUse, ImagePush, ImageDelete,
	VolumeMount, VolumeDelete,
	NetworkConnect, NetworkDelete,
	SecretUse, SecretDelete,
}
