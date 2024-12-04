package injectable

import (
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type ApplyConfiguration interface {
	GetName() *string
}

type Injectable interface {
	GroupVersionKind() schema.GroupVersionKind
	InjectCA(obj *unstructured.Unstructured, caBundle []byte) (ApplyConfiguration, error)
}
