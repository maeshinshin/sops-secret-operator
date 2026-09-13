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
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/getsops/sops/v3/aes"
)

// Meta holds fields common to all SOPS metadata envelopes.
type Meta struct {
	EncryptedRegex string    `json:"encrypted_regex,omitempty"`
	LastModified   time.Time `json:"lastmodified"`
	MAC            string    `json:"mac"`
	Version        string    `json:"version"`
}

// PGPRecipient represents one PGP recipient entry.
type PGPRecipient struct {
	CreatedAt time.Time `json:"created_at"`
	Enc       string    `json:"enc"`
	FP        string    `json:"fp"`
}

// MetaWithPGP extends Meta with PGP-specific recipient info.
type MetaWithPGP struct {
	Meta
	PGP []PGPRecipient `json:"pgp,omitempty"`
}

// ParseMeta parses the common SOPS metadata.
func ParseMeta(raw []byte) (*Meta, error) {
	var m Meta
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("parse sops metadata: %w", err)
	}
	return &m, nil
}

// ParseMetaWithPGP parses common metadata plus PGP recipients.
func ParseMetaWithPGP(raw []byte) (*MetaWithPGP, error) {
	var m MetaWithPGP
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("parse sops metadata: %w", err)
	}
	if len(m.PGP) == 0 {
		return nil, fmt.Errorf("sops metadata has no pgp recipients")
	}
	return &m, nil
}

// FindPGPRecipient returns the encrypted data key for the matching fingerprint.
// Returns "" if not found. Fingerprint comparison is case- and whitespace-insensitive.
func (m *MetaWithPGP) FindPGPRecipient(fingerprint string) string {
	if m == nil {
		return ""
	}
	if fingerprint == "" {
		return ""
	}
	target := normalizeFP(fingerprint)
	for _, r := range m.PGP {
		if normalizeFP(r.FP) == target {
			return r.Enc
		}
	}
	return ""
}

func normalizeFP(fp string) string {
	var b strings.Builder
	b.Grow(len(fp))
	for _, r := range fp {
		if !unicode.IsSpace(r) {
			b.WriteRune(r)
		}
	}
	return strings.ToUpper(b.String())
}

// DecryptMap decrypts a map of ENC[...] values using the data key.
// `top` is the AAD prefix (typically "data" or "stringData").
func DecryptMap(cipher aes.Cipher, dek []byte, entries map[string]string, top string) (map[string]string, error) {
	if len(entries) == 0 {
		return nil, nil
	}
	out := make(map[string]string, len(entries))
	for k, v := range entries {
		if !strings.HasPrefix(v, "ENC[") {
			out[k] = v
			continue
		}
		aad := top + ":" + k + ":"
		pt, err := cipher.Decrypt(v, dek, aad)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", k, err)
		}
		s, ok := pt.(string)
		if !ok {
			return nil, fmt.Errorf("%s: unexpected plaintext type %T", k, pt)
		}
		out[k] = s
	}
	return out, nil
}
