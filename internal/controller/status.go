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

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	sopsv1alpha1 "github.com/maeshinshin/sops-secret-operator/api/v1alpha1"
)

func (r *SopsSecretReconciler) setKeyAvailableCondition(ss *sopsv1alpha1.SopsSecret, status metav1.ConditionStatus, reason, message string) {
	meta.SetStatusCondition(&ss.Status.Conditions, metav1.Condition{
		Type:    sopsv1alpha1.ConditionTypeKeyAvailable,
		Status:  status,
		Reason:  reason,
		Message: message,
	})
}

func (r *SopsSecretReconciler) setSecretSyncedCondition(ss *sopsv1alpha1.SopsSecret, status metav1.ConditionStatus, reason, message string) {
	meta.SetStatusCondition(&ss.Status.Conditions, metav1.Condition{
		Type:    sopsv1alpha1.ConditionTypeSecretSynced,
		Status:  status,
		Reason:  reason,
		Message: message,
	})
}

func (r *SopsSecretReconciler) setReadyCondition(ss *sopsv1alpha1.SopsSecret) {
	ready := metav1.ConditionTrue
	reason := sopsv1alpha1.ReasonReconciled
	message := "all components reconciled"

	if !meta.IsStatusConditionPresentAndEqual(ss.Status.Conditions, sopsv1alpha1.ConditionTypeKeyAvailable, metav1.ConditionTrue) {
		ready = metav1.ConditionFalse
		reason = sopsv1alpha1.ReasonKeyUnavailable
		message = "SopsSecret key is unavailable"
	} else if !meta.IsStatusConditionPresentAndEqual(ss.Status.Conditions, sopsv1alpha1.ConditionTypeSecretSynced, metav1.ConditionTrue) {
		ready = metav1.ConditionFalse
		reason = sopsv1alpha1.ReasonSecretNotSynced
		message = "SopsSecret has not been synced to the target secret"
	}

	meta.SetStatusCondition(&ss.Status.Conditions, metav1.Condition{
		Type:    sopsv1alpha1.ConditionTypeReady,
		Status:  ready,
		Reason:  reason,
		Message: message,
	})
}

func (r *SopsSecretReconciler) applyStatus(ctx context.Context, ss *sopsv1alpha1.SopsSecret) error {
	ss.Status.ObservedGeneration = ss.Generation
	if err := r.Status().Update(ctx, ss); err != nil {
		return fmt.Errorf("failed to update SopsSecret status: %w", err)
	}
	return nil
}
