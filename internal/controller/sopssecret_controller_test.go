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
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	sopsv1alpha1 "github.com/maeshinshin/sops-secret-operator/api/v1alpha1"
)

var _ = Describe("SopsSecret Controller", func() {
	const (
		pgpKeyName    = "test-pgp-key"
		resourceName  = "test-sopssecret"
		namespaceName = "default"
	)

	namespacedName := newNamespacedName(resourceName, namespaceName)

	newPGPKey := func(data string) *corev1.Secret {
		return &corev1.Secret{
			ObjectMeta: newObjectMeta(pgpKeyName, namespaceName),
			Data:       map[string][]byte{"pgp.asc": []byte(data)},
		}
	}

	newSopsSecret := func() *sopsv1alpha1.SopsSecret {
		return &sopsv1alpha1.SopsSecret{
			ObjectMeta: newObjectMeta(resourceName, namespaceName),
			Spec: sopsv1alpha1.SopsSecretSpec{
				Decryption: sopsv1alpha1.DecryptionSource{
					PGP: &sopsv1alpha1.PGPConfig{
						KeyRef: sopsv1alpha1.SecretKeySelector{
							Name: pgpKeyName,
							Key:  "pgp.asc",
						},
					},
				},
			},
		}
	}

	newSopsSecretWithPolicy := func(policy sopsv1alpha1.DeletionPolicy) *sopsv1alpha1.SopsSecret {
		ss := newSopsSecret()
		ss.DeletionPolicy = policy
		return ss
	}

	Context("When PGP key Secret is missing", func() {
		var sopssecret *sopsv1alpha1.SopsSecret

		BeforeEach(func() {
			sopssecret = newSopsSecret()
			Expect(k8sClient.Create(ctx, sopssecret)).To(Succeed())
		})

		AfterEach(func() { cleanupResource(sopssecret) })

		It("should set KeyAvailable condition to False with DecryptError reason", func() {
			Eventually(func() *metav1.Condition {
				updated := &sopsv1alpha1.SopsSecret{}
				if err := k8sClient.Get(ctx, namespacedName, updated); err != nil {
					return nil
				}
				return findConditionFor(updated.Status.Conditions, sopsv1alpha1.ConditionTypeKeyAvailable)
			}, 10*time.Second).Should(SatisfyAll(
				Not(BeNil()),
				HaveField("Status", Equal(metav1.ConditionFalse)),
				HaveField("Reason", Equal(sopsv1alpha1.ReasonDecryptError)),
			))
		})

		It("should not create the target Secret", func() {
			Consistently(func() bool {
				target := &corev1.Secret{}
				err := k8sClient.Get(ctx, namespacedName, target)
				return errors.IsNotFound(err)
			}, 3*time.Second).Should(BeTrue())
		})
	})

	Context("When PGP key Secret contains invalid data", func() {
		var pgpKey *corev1.Secret
		var sopssecret *sopsv1alpha1.SopsSecret

		BeforeEach(func() {
			pgpKey = newPGPKey("invalid-pgp-key-data")
			Expect(k8sClient.Create(ctx, pgpKey)).To(Succeed())

			sopssecret = newSopsSecret()
			Expect(k8sClient.Create(ctx, sopssecret)).To(Succeed())
		})

		AfterEach(func() {
			cleanupResource(sopssecret)
			cleanupResource(pgpKey)
		})

		It("should set KeyAvailable condition to False with DecryptError reason", func() {
			Eventually(func() *metav1.Condition {
				updated := &sopsv1alpha1.SopsSecret{}
				if err := k8sClient.Get(ctx, namespacedName, updated); err != nil {
					return nil
				}
				return findConditionFor(updated.Status.Conditions, sopsv1alpha1.ConditionTypeKeyAvailable)
			}, 10*time.Second).Should(SatisfyAll(
				Not(BeNil()),
				HaveField("Status", Equal(metav1.ConditionFalse)),
				HaveField("Reason", Equal(sopsv1alpha1.ReasonDecryptError)),
			))
		})

		It("should not create the target Secret on decrypt failure", func() {
			Consistently(func() bool {
				target := &corev1.Secret{}
				err := k8sClient.Get(ctx, namespacedName, target)
				return errors.IsNotFound(err)
			}, 3*time.Second).Should(BeTrue())
		})
	})

	Context("When DeletionPolicy=Delete (default) is set with valid key", func() {
		var pgpKey *corev1.Secret
		var sopssecret *sopsv1alpha1.SopsSecret

		BeforeEach(func() {
			pgpKey = newPGPKey("invalid-pgp-key-data")
			Expect(k8sClient.Create(ctx, pgpKey)).To(Succeed())

			sopssecret = newSopsSecretWithPolicy(sopsv1alpha1.DeletionPolicyDelete)
			Expect(k8sClient.Create(ctx, sopssecret)).To(Succeed())
		})

		AfterEach(func() {
			cleanupResource(sopssecret)
			cleanupResource(pgpKey)
		})

		It("should eventually remove owner references on the target Secret (deletion path)", func() {
			Consistently(func() bool {
				target := &corev1.Secret{}
				err := k8sClient.Get(ctx, namespacedName, target)
				if err != nil {
					return true
				}
				return len(target.OwnerReferences) == 0
			}, 3*time.Second).Should(BeTrue())
		})
	})

	Context("When DeletionPolicy=Retain is set", func() {
		var sopssecret *sopsv1alpha1.SopsSecret

		BeforeEach(func() {
			sopssecret = newSopsSecretWithPolicy(sopsv1alpha1.DeletionPolicyRetain)
			Expect(k8sClient.Create(ctx, sopssecret)).To(Succeed())
		})

		AfterEach(func() { cleanupResource(sopssecret) })

		It("should accept the Retain policy on the CR", func() {
			updated := &sopsv1alpha1.SopsSecret{}
			Expect(k8sClient.Get(ctx, namespacedName, updated)).To(Succeed())
			Expect(updated.DeletionPolicy).To(Equal(sopsv1alpha1.DeletionPolicyRetain))
		})
	})

	Context("When PGP key and sops data are valid", func() {
		var pgpKey *corev1.Secret
		var sopssecret *sopsv1alpha1.SopsSecret

		BeforeEach(func() {
			keyData, err := os.ReadFile(filepath.Join("..", "decryption", "testdata", "test-key.asc"))
			Expect(err).NotTo(HaveOccurred())
			pgpKey = newPGPKey(string(keyData))
			Expect(k8sClient.Create(ctx, pgpKey)).To(Succeed())

			raw, err := os.ReadFile(filepath.Join("..", "decryption", "testdata", "encrypted-data-only.json.sops"))
			Expect(err).NotTo(HaveOccurred())
			var envelope struct {
				Sops json.RawMessage   `json:"sops"`
				Data map[string]string `json:"data"`
			}
			Expect(json.Unmarshal(raw, &envelope)).To(Succeed())

			sopssecret = newSopsSecret()
			sopssecret.Sops = &apiextensionsv1.JSON{Raw: envelope.Sops}
			sopssecret.Data = envelope.Data
			Expect(k8sClient.Create(ctx, sopssecret)).To(Succeed())
		})

		AfterEach(func() {
			cleanupResource(sopssecret)
			cleanupResource(pgpKey)
		})

		It("should create the target Secret with decrypted Data", func() {
			target := &corev1.Secret{}
			Eventually(func() map[string][]byte {
				_ = k8sClient.Get(ctx, namespacedName, target)
				return target.Data
			}, 10*time.Second).Should(SatisfyAll(
				HaveKeyWithValue("config1", []byte("value1")),
				HaveKeyWithValue("config2", []byte("value2")),
				HaveKeyWithValue("config3", []byte("value3")),
			))
		})

		It("should set OwnerReference on the target Secret", func() {
			target := &corev1.Secret{}
			Eventually(func() []metav1.OwnerReference {
				_ = k8sClient.Get(ctx, namespacedName, target)
				return target.OwnerReferences
			}, 10*time.Second).Should(HaveLen(1))
			Expect(target.OwnerReferences[0].Kind).To(Equal("SopsSecret"))
			Expect(target.OwnerReferences[0].Name).To(Equal(resourceName))
		})

		It("should set all Conditions to True", func() {
			for _, condType := range []string{
				sopsv1alpha1.ConditionTypeKeyAvailable,
				sopsv1alpha1.ConditionTypeSecretSynced,
				sopsv1alpha1.ConditionTypeReady,
			} {
				Eventually(func() *metav1.Condition {
					updated := &sopsv1alpha1.SopsSecret{}
					if err := k8sClient.Get(ctx, namespacedName, updated); err != nil {
						return nil
					}
					return findConditionFor(updated.Status.Conditions, condType)
				}, 10*time.Second).Should(SatisfyAll(
					Not(BeNil()),
					HaveField("Status", Equal(metav1.ConditionTrue)),
				))
			}
		})
	})

	Context("When PGP key is valid but sops data is encrypted for a different key", func() {
		var pgpKey *corev1.Secret
		var sopssecret *sopsv1alpha1.SopsSecret

		BeforeEach(func() {
			keyData, err := os.ReadFile(filepath.Join("..", "decryption", "testdata", "test-key.asc"))
			Expect(err).NotTo(HaveOccurred())
			pgpKey = newPGPKey(string(keyData))
			Expect(k8sClient.Create(ctx, pgpKey)).To(Succeed())

			raw, err := os.ReadFile(filepath.Join("..", "decryption", "testdata", "encrypted-other-key.json.sops"))
			Expect(err).NotTo(HaveOccurred())
			var envelope struct {
				Sops json.RawMessage   `json:"sops"`
				Data map[string]string `json:"data"`
			}
			Expect(json.Unmarshal(raw, &envelope)).To(Succeed())

			sopssecret = newSopsSecret()
			sopssecret.Sops = &apiextensionsv1.JSON{Raw: envelope.Sops}
			sopssecret.Data = envelope.Data
			Expect(k8sClient.Create(ctx, sopssecret)).To(Succeed())
		})

		AfterEach(func() {
			cleanupResource(sopssecret)
			cleanupResource(pgpKey)
		})

		It("should set KeyAvailable=True (key loaded) and SecretSynced=False", func() {
			Eventually(func() *metav1.Condition {
				updated := &sopsv1alpha1.SopsSecret{}
				if err := k8sClient.Get(ctx, namespacedName, updated); err != nil {
					return nil
				}
				return findConditionFor(updated.Status.Conditions, sopsv1alpha1.ConditionTypeKeyAvailable)
			}, 10*time.Second).Should(SatisfyAll(
				Not(BeNil()),
				HaveField("Status", Equal(metav1.ConditionTrue)),
			))

			Eventually(func() *metav1.Condition {
				updated := &sopsv1alpha1.SopsSecret{}
				if err := k8sClient.Get(ctx, namespacedName, updated); err != nil {
					return nil
				}
				return findConditionFor(updated.Status.Conditions, sopsv1alpha1.ConditionTypeSecretSynced)
			}, 10*time.Second).Should(SatisfyAll(
				Not(BeNil()),
				HaveField("Status", Equal(metav1.ConditionFalse)),
				HaveField("Reason", Equal(sopsv1alpha1.ReasonDecryptError)),
			))
		})

		It("should set Ready condition to False", func() {
			Eventually(func() *metav1.Condition {
				updated := &sopsv1alpha1.SopsSecret{}
				if err := k8sClient.Get(ctx, namespacedName, updated); err != nil {
					return nil
				}
				return findConditionFor(updated.Status.Conditions, sopsv1alpha1.ConditionTypeReady)
			}, 10*time.Second).Should(SatisfyAll(
				Not(BeNil()),
				HaveField("Status", Equal(metav1.ConditionFalse)),
			))
		})
	})

	Context("When DeletionPolicy=Retain SopsSecret is deleted", func() {
		var pgpKey *corev1.Secret
		var sopssecret *sopsv1alpha1.SopsSecret
		var target *corev1.Secret
		retainName := "test-sopssecret-retain"
		retainNS := newNamespacedName(retainName, namespaceName)

		BeforeEach(func() {
			keyData, err := os.ReadFile(filepath.Join("..", "decryption", "testdata", "test-key.asc"))
			Expect(err).NotTo(HaveOccurred())
			pgpKey = &corev1.Secret{
				ObjectMeta: newObjectMeta("test-pgp-key-retain", namespaceName),
				Data:       map[string][]byte{"pgp.asc": keyData},
			}
			Expect(k8sClient.Create(ctx, pgpKey)).To(Succeed())

			raw, err := os.ReadFile(filepath.Join("..", "decryption", "testdata", "encrypted-data-only.json.sops"))
			Expect(err).NotTo(HaveOccurred())
			var envelope struct {
				Sops json.RawMessage   `json:"sops"`
				Data map[string]string `json:"data"`
			}
			Expect(json.Unmarshal(raw, &envelope)).To(Succeed())

			sopssecret = &sopsv1alpha1.SopsSecret{
				ObjectMeta: newObjectMeta(retainName, namespaceName),
				Spec: sopsv1alpha1.SopsSecretSpec{
					Decryption: sopsv1alpha1.DecryptionSource{
						PGP: &sopsv1alpha1.PGPConfig{
							KeyRef: sopsv1alpha1.SecretKeySelector{
								Name: "test-pgp-key-retain",
								Key:  "pgp.asc",
							},
						},
					},
				},
				Sops:           &apiextensionsv1.JSON{Raw: envelope.Sops},
				Data:           envelope.Data,
				DeletionPolicy: sopsv1alpha1.DeletionPolicyRetain,
			}
			Expect(k8sClient.Create(ctx, sopssecret)).To(Succeed())

			target = &corev1.Secret{}
			Eventually(func() error {
				return k8sClient.Get(ctx, retainNS, target)
			}, 10*time.Second).Should(Succeed())
		})

		AfterEach(func() {
			cleanupResource(target)
			cleanupResource(sopssecret)
			cleanupResource(pgpKey)
		})

		It("should not set OwnerReference on the target Secret", func() {
			Expect(target.OwnerReferences).To(BeEmpty())
		})

		It("should retain the target Secret after SopsSecret deletion", func() {
			Eventually(func() error {
				return k8sClient.Delete(ctx, sopssecret)
			}, 5*time.Second).Should(Succeed())

			Consistently(func() error {
				got := &corev1.Secret{}
				return k8sClient.Get(ctx, retainNS, got)
			}, 3*time.Second).Should(Succeed())
		})
	})

	Context("When DeletionPolicy=Delete (default) SopsSecret is deleted", func() {
		var pgpKey *corev1.Secret
		var sopssecret *sopsv1alpha1.SopsSecret
		deleteName := "test-sopssecret-delete"
		deleteNS := newNamespacedName(deleteName, namespaceName)

		BeforeEach(func() {
			keyData, err := os.ReadFile(filepath.Join("..", "decryption", "testdata", "test-key.asc"))
			Expect(err).NotTo(HaveOccurred())
			pgpKey = &corev1.Secret{
				ObjectMeta: newObjectMeta("test-pgp-key-delete", namespaceName),
				Data:       map[string][]byte{"pgp.asc": keyData},
			}
			Expect(k8sClient.Create(ctx, pgpKey)).To(Succeed())

			raw, err := os.ReadFile(filepath.Join("..", "decryption", "testdata", "encrypted-data-only.json.sops"))
			Expect(err).NotTo(HaveOccurred())
			var envelope struct {
				Sops json.RawMessage   `json:"sops"`
				Data map[string]string `json:"data"`
			}
			Expect(json.Unmarshal(raw, &envelope)).To(Succeed())

			sopssecret = &sopsv1alpha1.SopsSecret{
				ObjectMeta: newObjectMeta(deleteName, namespaceName),
				Spec: sopsv1alpha1.SopsSecretSpec{
					Decryption: sopsv1alpha1.DecryptionSource{
						PGP: &sopsv1alpha1.PGPConfig{
							KeyRef: sopsv1alpha1.SecretKeySelector{
								Name: "test-pgp-key-delete",
								Key:  "pgp.asc",
							},
						},
					},
				},
				Sops: &apiextensionsv1.JSON{Raw: envelope.Sops},
				Data: envelope.Data,
			}
			Expect(k8sClient.Create(ctx, sopssecret)).To(Succeed())

			Eventually(func() error {
				target := &corev1.Secret{}
				return k8sClient.Get(ctx, deleteNS, target)
			}, 10*time.Second).Should(Succeed())
		})

		AfterEach(func() {
			cleanupResource(sopssecret)
			cleanupResource(pgpKey)
		})

		It("should set OwnerReference on the target Secret for cascade deletion", func() {
			target := &corev1.Secret{}
			Expect(k8sClient.Get(ctx, deleteNS, target)).To(Succeed())
			Expect(target.OwnerReferences).To(HaveLen(1))
			Expect(target.OwnerReferences[0].Kind).To(Equal("SopsSecret"))
			Expect(target.OwnerReferences[0].Name).To(Equal(deleteName))
			Expect(target.OwnerReferences[0].UID).To(Equal(sopssecret.UID))
		})
	})
})
