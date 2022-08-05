package securitypolicy

import (
	"github.com/containerd/typeurl"
)

func init() {
	typeurl.Register(&PolicyFragment{}, "github.com/Microsoft/hcsshim/pkg/securitypolicy", "PolicyFragment")
}

type PolicyFragment struct {
	Fragment    string            `json:"fragment,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}
