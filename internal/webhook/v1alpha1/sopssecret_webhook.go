/*
Copyright 2026 maeshinshin.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha1

import (
	"context"
	"fmt"

	authzv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	sopsv1alpha1 "github.com/maeshinshin/sops-secret-operator/api/v1alpha1"
)

// +kubebuilder:rbac:groups=authorization.k8s.io,resources=subjectaccessreviews,verbs=create

// TODO(user): change verbs to "verbs=create;update;delete" if you want to enable deletion validation.
// NOTE: If you want to customise the 'path', use the flags '--defaulting-path' or '--validation-path'.
// +kubebuilder:webhook:path=/validate-sops-maesh-dev-v1alpha1-sopssecret,mutating=false,failurePolicy=fail,sideEffects=None,groups=sops.maesh.dev,resources=sopssecrets,verbs=create;update,versions=v1alpha1,name=vsopssecret-v1alpha1.kb.io,admissionReviewVersions=v1

type SopsSecretCustomValidator struct {
	KubeClient kubernetes.Interface
}

var _ admission.Validator[*sopsv1alpha1.SopsSecret] = &SopsSecretCustomValidator{}

func (v *SopsSecretCustomValidator) ValidateCreate(ctx context.Context, obj *sopsv1alpha1.SopsSecret) (admission.Warnings, error) {
	return v.validateSecretRefs(ctx, obj)
}

func (v *SopsSecretCustomValidator) ValidateUpdate(ctx context.Context, _, newObj *sopsv1alpha1.SopsSecret) (admission.Warnings, error) {
	return v.validateSecretRefs(ctx, newObj)
}

func (v *SopsSecretCustomValidator) ValidateDelete(ctx context.Context, _ *sopsv1alpha1.SopsSecret) (admission.Warnings, error) {
	return nil, nil
}

func (v *SopsSecretCustomValidator) validateSecretRefs(ctx context.Context, obj *sopsv1alpha1.SopsSecret) (admission.Warnings, error) {
	refs := secretRefs(obj)
	if len(refs) == 0 {
		return nil, nil
	}

	req, err := admission.RequestFromContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("extracting admission request: %w", err)
	}

	for _, ref := range refs {
		ns := obj.Namespace
		if ref.Namespace != nil {
			ns = *ref.Namespace
		}

		sar := &authzv1.SubjectAccessReview{
			Spec: authzv1.SubjectAccessReviewSpec{
				ResourceAttributes: &authzv1.ResourceAttributes{
					Namespace: ns,
					Verb:      "get",
					Resource:  "secrets",
					Name:      ref.Name,
				},
				User:   req.UserInfo.Username,
				Groups: req.UserInfo.Groups,
			},
		}

		result, err := v.KubeClient.AuthorizationV1().SubjectAccessReviews().Create(ctx, sar, metav1.CreateOptions{})
		if err != nil {
			return nil, fmt.Errorf("checking access for secret %s/%s: %w", ns, ref.Name, err)
		}
		if !result.Status.Allowed {
			return nil, fmt.Errorf("user %q is not authorized to get secret %q in namespace %q", req.UserInfo.Username, ref.Name, ns)
		}
	}

	return nil, nil
}

func secretRefs(obj *sopsv1alpha1.SopsSecret) []sopsv1alpha1.SecretKeySelector {
	var refs []sopsv1alpha1.SecretKeySelector
	if pgp := obj.Spec.Decryption.PGP; pgp != nil {
		refs = append(refs, pgp.KeyRef)
		if pgp.PassphraseRef != nil {
			refs = append(refs, *pgp.PassphraseRef)
		}
	}
	return refs
}

// SetupSopsSecretWebhookWithManager registers the webhook for SopsSecret in the manager.
func SetupSopsSecretWebhookWithManager(mgr ctrl.Manager) error {
	kubeClient, err := kubernetes.NewForConfig(mgr.GetConfig())
	if err != nil {
		return err
	}
	return ctrl.NewWebhookManagedBy(mgr, &sopsv1alpha1.SopsSecret{}).
		WithValidator(&SopsSecretCustomValidator{KubeClient: kubeClient}).
		Complete()
}
