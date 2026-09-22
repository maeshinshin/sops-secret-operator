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

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	sopsv1alpha1 "github.com/maeshinshin/sops-secret-operator/api/v1alpha1"
)

var _ = Describe("SopsSecret Webhook Authorization", func() {
	const (
		ns         = "default"
		secretName = "test-secret"
	)

	var (
		validator *SopsSecretCustomValidator
		secret    *corev1.Secret
	)

	BeforeEach(func() {
		kubeClient, err := kubernetes.NewForConfig(cfg)
		Expect(err).NotTo(HaveOccurred())
		validator = &SopsSecretCustomValidator{KubeClient: kubeClient}

		secret = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: ns},
			Data:       map[string][]byte{"key": []byte("value")},
		}
		Expect(k8sClient.Create(ctx, secret)).To(Succeed())
	})

	AfterEach(func() {
		Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, secret))).To(Succeed())
		Expect(k8sClient.DeleteAllOf(ctx, &rbacv1.RoleBinding{}, client.InNamespace(ns))).To(Succeed())
		Expect(k8sClient.DeleteAllOf(ctx, &rbacv1.Role{}, client.InNamespace(ns))).To(Succeed())
	})

	grant := func(user string, resourceNames ...string) {
		role := &rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{Name: "allow-" + user, Namespace: ns},
			Rules: []rbacv1.PolicyRule{{
				APIGroups:     []string{""},
				Resources:     []string{secretsResource},
				ResourceNames: resourceNames,
				Verbs:         []string{getVerb},
			}},
		}
		Expect(k8sClient.Create(ctx, role)).To(Succeed())

		binding := &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "allow-" + user, Namespace: ns},
			Subjects:   []rbacv1.Subject{{Kind: "User", Name: user, APIGroup: rbacAPIGroup}},
			RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: role.Name, APIGroup: rbacAPIGroup},
		}
		Expect(k8sClient.Create(ctx, binding)).To(Succeed())
	}

	withUser := func(user string) context.Context {
		req := admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
			UserInfo: authenticationv1.UserInfo{Username: user, Groups: []string{"system:authenticated"}},
		}}
		return admission.NewContextWithRequest(context.Background(), req)
	}

	sopsSecretWithKeyRef := func() *sopsv1alpha1.SopsSecret {
		return &sopsv1alpha1.SopsSecret{
			ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: ns},
			Spec: sopsv1alpha1.SopsSecretSpec{
				Decryption: sopsv1alpha1.DecryptionSource{
					PGP: &sopsv1alpha1.PGPConfig{
						KeyRef: sopsv1alpha1.SecretKeySelector{Name: secretName, Key: "key"},
					},
				},
			},
		}
	}

	It("allows the requestor to reference a Secret they can get", func() {
		grant("alice")
		_, err := validator.ValidateCreate(withUser("alice"), sopsSecretWithKeyRef())
		Expect(err).NotTo(HaveOccurred())
	})

	It("denies the requestor when they cannot get the referenced Secret", func() {
		grant("alice")
		_, err := validator.ValidateCreate(withUser("bob"), sopsSecretWithKeyRef())
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("not authorized"))
	})

	It("checks the namespace specified by keyRef.namespace, not the SopsSecret namespace", func() {
		otherNS := "team-b"
		nsObj := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: otherNS}}
		Expect(k8sClient.Create(ctx, nsObj)).To(Succeed())
		DeferCleanup(func() {
			Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, nsObj))).To(Succeed())
		})

		otherSecret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: otherNS},
			Data:       map[string][]byte{"k": []byte("v")},
		}
		Expect(k8sClient.Create(ctx, otherSecret)).To(Succeed())
		DeferCleanup(func() {
			Expect(client.IgnoreNotFound(k8sClient.Delete(ctx, otherSecret))).To(Succeed())
			Expect(k8sClient.DeleteAllOf(ctx, &rbacv1.RoleBinding{}, client.InNamespace(otherNS))).To(Succeed())
			Expect(k8sClient.DeleteAllOf(ctx, &rbacv1.Role{}, client.InNamespace(otherNS))).To(Succeed())
		})

		role := &rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{Name: "allow-bob", Namespace: otherNS},
			Rules:      []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}}},
		}
		Expect(k8sClient.Create(ctx, role)).To(Succeed())
		binding := &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "allow-bob", Namespace: otherNS},
			Subjects:   []rbacv1.Subject{{Kind: "User", Name: "bob", APIGroup: "rbac.authorization.k8s.io"}},
			RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: role.Name, APIGroup: "rbac.authorization.k8s.io"},
		}
		Expect(k8sClient.Create(ctx, binding)).To(Succeed())

		obj := sopsSecretWithKeyRef()
		nsRef := otherNS
		obj.Spec.Decryption.PGP.KeyRef.Namespace = &nsRef

		_, err := validator.ValidateCreate(withUser("bob"), obj)
		Expect(err).NotTo(HaveOccurred(), "bob should be able to reference the Secret in team-b")
	})

	It("also checks the passphraseRef", func() {
		grant("alice", secretName)
		obj := sopsSecretWithKeyRef()
		obj.Spec.Decryption.PGP.PassphraseRef = &sopsv1alpha1.SecretKeySelector{
			Name: "passphrase-secret", Key: "pass",
		}
		_, err := validator.ValidateCreate(withUser("alice"), obj)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("passphrase-secret"))
	})
})
