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
	"fmt"

	sopsv1alpha1 "github.com/maeshinshin/sops-secret-operator/api/v1alpha1"
	"github.com/maeshinshin/sops-secret-operator/internal/decryption"
)

func (r *SopsSecretReconciler) newDecryptor(ctx context.Context, ss *sopsv1alpha1.SopsSecret) (decryption.Decryptor, error) {
	dec := ss.Spec.Decryption
	switch {
	case dec.PGP != nil:
		key, passphrase, err := r.loadPGPCredentials(ctx, ss)
		if err != nil {
			return nil, fmt.Errorf("loading PGP credentials: %w", err)
		}
		return decryption.New(sopsv1alpha1.ProviderPGP, key, passphrase)
	default:
		loggerForSopsSecret(ctx, ss).V(1).Info("decryption source not configured")
		return nil, fmt.Errorf("no decryption source configured for SopsSecret %s/%s", ss.Namespace, ss.Name)
	}
}

func (r *SopsSecretReconciler) loadPGPCredentials(ctx context.Context, ss *sopsv1alpha1.SopsSecret) (key, passphrase []byte, err error) {
	pgp := ss.Spec.Decryption.PGP
	if pgp == nil {
		return nil, nil, nil
	}
	if key, err = r.loadSecretKeyData(ctx, ss.Namespace, &pgp.KeyRef); err != nil {
		return
	}
	if passphrase, err = r.loadSecretKeyData(ctx, ss.Namespace, pgp.PassphraseRef); err != nil {
		return
	}
	loggerForSopsSecret(ctx, ss).V(1).Info("loaded PGP credentials", "keyLength", len(key), "passphraseLength", len(passphrase))
	return
}

func (r *SopsSecretReconciler) loadSecretKeyData(ctx context.Context, defaultNS string, ref *sopsv1alpha1.SecretKeySelector) ([]byte, error) {
	if ref == nil {
		return nil, nil
	}
	ns := defaultNS
	if ref.Namespace != nil {
		ns = *ref.Namespace
	}
	return r.fetchSecretData(ctx, ns, ref)
}
