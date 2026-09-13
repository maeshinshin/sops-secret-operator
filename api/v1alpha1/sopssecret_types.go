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
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

type DeletionPolicy string

type Provider string

const (
	ConditionTypeReady        = "Ready"
	ConditionTypeKeyAvailable = "KeyAvailable"
	ConditionTypeSecretSynced = "SecretSynced"

	DeletionPolicyDelete DeletionPolicy = "Delete"
	DeletionPolicyRetain DeletionPolicy = "Retain"

	ReasonReconciled           = "Reconciled"
	ReasonDecryptError         = "DecryptError"
	ReasonApplyFailed          = "ApplyFailed"
	ReasonMissingKey           = "MissingKey"
	ReasonProviderNotSupported = "ProviderNotSupported"

	ProviderPGP   Provider = "pgp"
	ProviderAge   Provider = "age"
	ProviderKMS   Provider = "kms"
	ProviderVault Provider = "vault"

	DefaultPGPKeyName = "pgp.key"
)

type SecretKeySelector struct {
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// +optional
	Namespace *string `json:"namespace,omitempty"`

	// +kubebuilder:validation:Required
	Key string `json:"key"`
}

type PGPConfig struct {
	// +kubebuilder:validation:Required
	KeyRef SecretKeySelector `json:"keyRef"`

	PassphraseRef *SecretKeySelector `json:"passphraseRef,omitempty"`
}

// +kubebuilder:validation:MaxProperties=1
// +kubebuilder:validation:MinProperties=1
type DecryptionSource struct {
	PGP *PGPConfig `json:"pgp,omitempty"`

	// Age *AgeConfig `json:"age,omitempty"`

	// KMS *KMSConfig `json:"kms,omitempty"`

	// Vault *VaultConfig `json:"vault,omitempty"`
}

// SopsSecretSpec defines the desired state of SopsSecret
type SopsSecretSpec struct {
	// +kubebuilder:validation:Required
	Decryption DecryptionSource `json:"decryption"`
}

// SopsSecretStatus defines the observed state of SopsSecret.
type SopsSecretStatus struct {
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// +optional
	Provider Provider `json:"provider,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Namespace",type="string",JSONPath=".metadata.namespace",priority=1
// +kubebuilder:printcolumn:name="Provider",type="string",JSONPath=".status.provider",priority=1
// +kubebuilder:printcolumn:name="Key",type=string,JSONPath=`.status.conditions[?(@.type=="KeyAvailable")].status`,priority=1
// +kubebuilder:printcolumn:name="Secret",type=string,JSONPath=`.status.conditions[?(@.type=="SecretSynced")].status`,priority=1
// +kubebuilder:printcolumn:name="OnDelete",type="string",JSONPath=".deletionPolicy",priority=1
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Status",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].reason`
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// SopsSecret is the Schema for the sopssecrets API
type SopsSecret struct {
	metav1.TypeMeta `json:",inline"`

	// metadata is the standard object metadata
	// +optional
	metav1.ObjectMeta `json:"metadata,omitzero"`

	// spec defines the decryption source and other configuration for the SopsSecret
	// +required
	Spec SopsSecretSpec `json:"spec"`

	Data       map[string]string `json:"data,omitempty"`
	StringData map[string]string `json:"stringData,omitempty"`
	Immutable  *bool             `json:"immutable,omitempty"`

	// +kubebuilder:default=Opaque
	Type corev1.SecretType `json:"type,omitempty"`

	// +kubebuilder:validation:Enum=Delete;Retain
	// +kubebuilder:default=Delete
	DeletionPolicy DeletionPolicy `json:"deletionPolicy,omitempty"`

	// +kubebuilder:pruning:PreserveUnknownFields
	// +kubebuilder:validation:Schemaless
	// +optional
	Sops *apiextensionsv1.JSON `json:"sops,omitempty"`

	// status defines the observed state of SopsSecret
	// +optional
	Status SopsSecretStatus `json:"status,omitzero"`
}

// +kubebuilder:object:root=true

// SopsSecretList contains a list of SopsSecret
type SopsSecretList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitzero"`
	Items           []SopsSecret `json:"items"`
}

func init() {
	SchemeBuilder.Register(func(s *runtime.Scheme) error {
		s.AddKnownTypes(SchemeGroupVersion, &SopsSecret{}, &SopsSecretList{})
		return nil
	})
}
