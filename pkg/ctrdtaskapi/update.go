package ctrdtaskapi

import (
	"github.com/containerd/typeurl"
)

func init() {
	typeurl.Register(&StringPayload{}, "github.com/Microsoft/hcsshim/pkg/ctrdtaskapi", "StringPayload")
}

type StringPayload struct {
	// Payload can be used by ContainerD to pass any non-resource specific
	// information as part of shim task Update request.
	Payload string `json:"payload,omitempty"`
	// Annotations hold arbitrary additional information that can be used to
	// (e.g.) provide more context about Payload.
	Annotations map[string]string `json:"annotations,omitempty"`
}
