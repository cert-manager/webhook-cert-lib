package injectable

import (
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	admissionregistrationv1ac "k8s.io/client-go/applyconfigurations/admissionregistration/v1"
)

type ValidatingWebhookCaBundleInject struct {
}

var _ Injectable = &ValidatingWebhookCaBundleInject{}

func (i *ValidatingWebhookCaBundleInject) GroupVersionKind() schema.GroupVersionKind {
	return schema.GroupVersionKind{
		Group:   "admissionregistration.k8s.io",
		Version: "v1",
		Kind:    "ValidatingWebhookConfiguration",
	}
}

func (i *ValidatingWebhookCaBundleInject) InjectCA(obj *unstructured.Unstructured, caBundle []byte) (ApplyConfiguration, error) {
	// TODO: Can we generalize this function for any resource based on a JSON path?

	ac := admissionregistrationv1ac.ValidatingWebhookConfiguration(obj.GetName())

	webhooks, _, err := unstructured.NestedSlice(obj.Object, "webhooks")
	if err != nil {
		return nil, err
	}
	for _, w := range webhooks {
		name, _, err := unstructured.NestedString(w.(map[string]any), "name")
		if err != nil {
			return nil, err
		}
		ac.WithWebhooks(
			admissionregistrationv1ac.ValidatingWebhook().
				WithName(name).
				WithClientConfig(admissionregistrationv1ac.WebhookClientConfig().
					WithCABundle(caBundle...),
				),
		)
	}

	return ac, nil
}
