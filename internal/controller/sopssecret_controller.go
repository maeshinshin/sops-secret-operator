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

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	sopsv1alpha1 "github.com/maeshinshin/sops-secret-operator/api/v1alpha1"
)

// SopsSecretReconciler reconciles a SopsSecret object
type SopsSecretReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

// +kubebuilder:rbac:groups=sops.maesh.dev,resources=sopssecrets,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=sops.maesh.dev,resources=sopssecrets/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=sops.maesh.dev,resources=sopssecrets/finalizers,verbs=update
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update;patch;delete

func (r *SopsSecretReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	ss := &sopsv1alpha1.SopsSecret{}
	if err := r.Get(ctx, req.NamespacedName, ss); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	logger := loggerForSopsSecret(ctx, ss)
	logger.V(1).Info("reconciling SopsSecret", "generation", ss.Generation)

	decryptor, err := r.newDecryptor(ctx, ss)
	if err != nil {
		logger.Error(err, "creating decryptor")
		r.setKeyAvailableCondition(ss, metav1.ConditionFalse, sopsv1alpha1.ReasonDecryptError, err.Error())
		r.setReadyCondition(ss)
		r.applyStatusBestEffort(ctx, ss, logger)
		return ctrl.Result{}, err
	}

	r.setKeyAvailableCondition(ss, metav1.ConditionTrue, sopsv1alpha1.ReasonReconciled, sopsv1alpha1.MessageCredentialsLoaded)
	logger.Info("decryptor ready", "provider", decryptor.Provider())

	var sopsRaw []byte
	if ss.Sops != nil {
		sopsRaw = ss.Sops.Raw
	}
	decrypted, err := decryptor.Decrypt(ctx, sopsRaw, ss.Data, ss.StringData)
	if err != nil {
		logger.Error(err, "decrypting sops data")
		r.setSecretSyncedCondition(ss, metav1.ConditionFalse, sopsv1alpha1.ReasonDecryptError, err.Error())
		r.setReadyCondition(ss)
		r.applyStatusBestEffort(ctx, ss, logger)
		return ctrl.Result{}, err
	}

	if err := r.applySecret(ctx, ss, decrypted); err != nil {
		logger.Error(err, "applying secret")
		r.setSecretSyncedCondition(ss, metav1.ConditionFalse, sopsv1alpha1.ReasonApplyFailed, err.Error())
		r.setReadyCondition(ss)
		r.applyStatusBestEffort(ctx, ss, logger)
		return ctrl.Result{}, err
	}

	r.setSecretSyncedCondition(ss, metav1.ConditionTrue, sopsv1alpha1.ReasonReconciled, sopsv1alpha1.MessageSecretApplied)
	r.setReadyCondition(ss)
	if err := r.applyStatus(ctx, ss); err != nil {
		logger.Error(err, "updating status")
		return ctrl.Result{}, err
	}

	logger.Info("reconciliation complete", "generation", ss.Generation)

	return ctrl.Result{}, nil
}

func (r *SopsSecretReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&sopsv1alpha1.SopsSecret{}).
		Owns(&corev1.Secret{}).
		Named("sopssecret").
		Complete(r)
}
