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

package decryption

import (
	"context"
	"errors"
	"fmt"

	sopsv1alpha1 "github.com/maeshinshin/sops-secret-operator/api/v1alpha1"
)

// Decrypted holds the plaintext result of SOPS decryption.
type Decrypted struct {
	Data       map[string]string
	StringData map[string]string
}

// Decryptor decrypts a SOPS-encrypted envelope.
type Decryptor interface {
	// Provider returns the cryptographic provider name.
	Provider() sopsv1alpha1.Provider

	// Decrypt decrypts the SOPS envelope.
	Decrypt(ctx context.Context, sopsRaw []byte,
		data, stringData map[string]string) (*Decrypted, error)
}

// ErrUnsupported indicates the provider is not implemented.
var ErrUnsupported = errors.New("unsupported decryption provider")

// ErrNoMatch indicates no recipient in the SOPS envelope matched the key.
type ErrNoMatch struct {
	Provider sopsv1alpha1.Provider
	Reason   string
}

func (e *ErrNoMatch) Error() string {
	return fmt.Sprintf("%s: %s", e.Provider, e.Reason)
}

// New returns the Decryptor for the given provider.
func New(provider sopsv1alpha1.Provider, key, passphrase []byte) (Decryptor, error) {
	switch provider {
	case sopsv1alpha1.ProviderPGP:
		return NewPGP(key, passphrase)
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupported, provider)
	}
}
