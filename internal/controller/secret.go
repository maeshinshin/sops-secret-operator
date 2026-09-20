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

package controller

import (
	"context"
	"encoding/base64"
	"fmt"
	"maps"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"

	sopsv1alpha1 "github.com/maeshinshin/sops-secret-operator/api/v1alpha1"
	"github.com/maeshinshin/sops-secret-operator/internal/decryption"
)

func (r *SopsSecretReconciler) applySecret(ctx context.Context, ss *sopsv1alpha1.SopsSecret, decrypted *decryption.Decrypted) error {
	logger := loggerForSopsSecret(ctx, ss)

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ss.Name,
			Namespace: ss.Namespace,
		},
	}

	op, err := controllerutil.CreateOrUpdate(ctx, r.Client, secret, func() error {
		if ss.DeletionPolicy != sopsv1alpha1.DeletionPolicyRetain {
			if err := controllerutil.SetControllerReference(ss, secret, r.Scheme); err != nil {
				return fmt.Errorf("setting controller reference: %w", err)
			}
		}

		secret.Type = ss.Type
		if secret.Type == "" {
			secret.Type = corev1.SecretTypeOpaque
		}
		if ss.Immutable != nil {
			secret.Immutable = ss.Immutable
		}

		secret.Data = make(map[string][]byte, len(decrypted.Data))
		secret.StringData = make(map[string]string, len(decrypted.StringData))

		for k, v := range decrypted.Data {
			b, err := base64.StdEncoding.DecodeString(v)
			if err != nil {
				return fmt.Errorf("decoding base64 data for key %q: %w", k, err)
			}
			secret.Data[k] = b
		}

		maps.Copy(secret.StringData, decrypted.StringData)

		return nil
	})

	if err != nil {
		return fmt.Errorf("creating or updating secret: %w", err)
	}

	logger.Info("secret applied", "operation", string(op))

	return nil
}

func (r *SopsSecretReconciler) fetchSecretData(ctx context.Context, ns string, ref *sopsv1alpha1.SecretKeySelector) ([]byte, error) {
	logger := log.FromContext(ctx).WithValues(
		"secret", types.NamespacedName{Namespace: ns, Name: ref.Name},
		"key", ref.Key,
	)

	secret := &corev1.Secret{}
	key := types.NamespacedName{Namespace: ns, Name: ref.Name}
	if err := r.Get(ctx, key, secret); err != nil {
		logger.Error(err, "fetching secret")
		return nil, fmt.Errorf("getting secret %s/%s: %w", ns, ref.Name, err)
	}

	data, ok := secret.Data[ref.Key]
	if !ok {
		logger.Error(nil, "fetching key from secret")
		return nil, fmt.Errorf("key %q not found in secret %s/%s", ref.Key, ns, ref.Name)
	}

	logger.V(1).Info("fetched secret data", "byteLength", len(data))
	return data, nil
}
