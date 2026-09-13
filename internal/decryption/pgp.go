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
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/getsops/sops/v3/aes"

	sopsv1alpha1 "github.com/maeshinshin/sops-secret-operator/api/v1alpha1"
)

// PGP decrypts SOPS data using a PGP private key.
type PGP struct {
	entity      *openpgp.Entity
	keyRequires bool
}

// KeyInfo describes properties of the loaded PGP private key.
type KeyInfo struct {
	Fingerprint        string
	RequiresPassphrase bool
	UserID             string
}

// NewPGP loads and unlocks an armored PGP private key.
func NewPGP(armoredKey, passphrase []byte) (*PGP, error) {
	if len(armoredKey) == 0 {
		return nil, errors.New("armored PGP key is empty")
	}
	entity, requires, err := loadPrivateKey(armoredKey, passphrase)
	if err != nil {
		return nil, fmt.Errorf("load PGP private key: %w", err)
	}
	return &PGP{entity: entity, keyRequires: requires}, nil
}

func (d *PGP) Provider() sopsv1alpha1.Provider {
	return sopsv1alpha1.ProviderPGP
}

func (d *PGP) KeyInfo() KeyInfo {
	if d == nil || d.entity == nil {
		return KeyInfo{}
	}
	var userID string
	for _, id := range d.entity.Identities {
		if id != nil {
			userID = id.Name
			break
		}
	}
	return KeyInfo{
		Fingerprint:        d.fingerprint(),
		RequiresPassphrase: d.keyRequires,
		UserID:             userID,
	}
}

func (d *PGP) RequiresPassphrase() bool {
	if d == nil {
		return false
	}
	return d.keyRequires
}

func (d *PGP) Decrypt(ctx context.Context, sopsRaw []byte,
	data, stringData map[string]string) (*Decrypted, error) {

	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("context: %w", err)
	}

	meta, err := ParseMetaWithPGP(sopsRaw)
	if err != nil {
		return nil, err
	}

	ours := d.fingerprint()
	encKey := meta.FindPGPRecipient(ours)
	if encKey == "" {
		return nil, &ErrNoMatch{
			Provider: d.Provider(),
			Reason:   fmt.Sprintf("fingerprint %s not in sops metadata", ours),
		}
	}

	dataKey, err := d.unlockDataKey(encKey)
	if err != nil {
		return nil, fmt.Errorf("unlock data key: %w", err)
	}

	cipher := aes.NewCipher()
	out := &Decrypted{}
	if out.Data, err = DecryptMap(cipher, dataKey, data, "data"); err != nil {
		return nil, fmt.Errorf("decrypt data: %w", err)
	}
	if out.StringData, err = DecryptMap(cipher, dataKey, stringData, "stringData"); err != nil {
		return nil, fmt.Errorf("decrypt stringData: %w", err)
	}
	return out, nil
}

func (d *PGP) fingerprint() string {
	if d.entity == nil || d.entity.PrimaryKey == nil {
		return ""
	}
	return fmt.Sprintf("%X", d.entity.PrimaryKey.Fingerprint)
}

func (d *PGP) unlockDataKey(encKey string) ([]byte, error) {
	block, err := armor.Decode(bytes.NewReader([]byte(encKey)))
	if err != nil {
		return nil, fmt.Errorf("armor decode: %w", err)
	}
	md, err := openpgp.ReadMessage(block.Body, openpgp.EntityList{d.entity}, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("read PGP message: %w", err)
	}
	pt, err := io.ReadAll(md.UnverifiedBody)
	if err != nil {
		return nil, fmt.Errorf("read plaintext: %w", err)
	}
	if len(pt) == 0 {
		return nil, errors.New("decrypted data key is empty")
	}
	return pt, nil
}

func loadPrivateKey(armored, passphrase []byte) (*openpgp.Entity, bool, error) {
	block, err := armor.Decode(bytes.NewReader(armored))
	if err != nil {
		return nil, false, fmt.Errorf("decode armor: %w", err)
	}
	entities, err := openpgp.ReadKeyRing(block.Body)
	if err != nil {
		return nil, false, fmt.Errorf("read armored key: %w", err)
	}
	if len(entities) == 0 {
		return nil, false, errors.New("no PGP keys in armored block")
	}
	entity := entities[0]

	if entity.PrivateKey == nil {
		return nil, false, errors.New("armored block has no private key")
	}
	requiresPassphrase := entity.PrivateKey.Encrypted
	for _, subkey := range entity.Subkeys {
		if subkey.PrivateKey != nil && subkey.PrivateKey.Encrypted {
			requiresPassphrase = true
		}
	}
	if requiresPassphrase {
		if len(passphrase) == 0 {
			return nil, true, errors.New("passphrase required: private key is passphrase-protected")
		}
		if err := entity.PrivateKey.Decrypt(passphrase); err != nil {
			return nil, true, fmt.Errorf("passphrase is incorrect: %w", err)
		}
	}
	for _, subkey := range entity.Subkeys {
		if subkey.PrivateKey == nil || !subkey.PrivateKey.Encrypted {
			continue
		}
		if len(passphrase) == 0 {
			return nil, true, fmt.Errorf("passphrase required for subkey %s", subkey.PublicKey.KeyIdString())
		}
		if err := subkey.PrivateKey.Decrypt(passphrase); err != nil {
			return nil, true, fmt.Errorf("passphrase is incorrect for subkey %s: %w", subkey.PublicKey.KeyIdString(), err)
		}
	}
	return entity, requiresPassphrase, nil
}
