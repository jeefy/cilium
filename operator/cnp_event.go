// Copyright 2018-2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"time"

	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/informer"
	"github.com/cilium/cilium/pkg/kvstore/store"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/groups"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
)

var (
	// cnpStatusUpdateInterval is the amount of time between status updates
	// being sent to the K8s apiserver for a given CNP.
	cnpStatusUpdateInterval time.Duration
	protectedCNPs           = make(map[string]*v2.CiliumNetworkPolicy)
)

func init() {
	runtime.ErrorHandlers = []func(error){
		k8s.K8sErrorHandler,
	}
	protectedCNPs["no-postgres"] = &v2.CiliumNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "no-postgres",
			Namespace: "default",
		},
		Spec: &api.Rule{
			EndpointSelector: api.NewESFromLabels(labels.ParseLabel("app=postgresql")),
			IngressDeny: []api.IngressDenyRule{
				{
					IngressCommonRule: api.IngressCommonRule{
						FromEndpoints: []api.EndpointSelector{api.NewESFromLabels(labels.ParseLabel("app=klustered"))},
					},
					ToPorts: []api.PortDenyRule{{
						Ports: []api.PortProtocol{
							{Port: "5432", Protocol: api.ProtoTCP},
						},
					}},
				},
			},
		},
	}
	protectedCNPs["deny-egress-to-postgres"] = &v2.CiliumNetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "deny-egress-to-postgres",
			Namespace: "kube-system",
		},
		Spec: &api.Rule{
			EndpointSelector: api.EndpointSelectorNone,
			Egress: []api.EgressRule{
				{
					EgressCommonRule: api.EgressCommonRule{
						ToEndpoints: []api.EndpointSelector{
							api.NewESFromLabels(labels.ParseLabel("k8s:io.kubernetes.pod.namespace=kube-system")),
							api.NewESFromLabels(labels.ParseLabel("k8s:k8s-app=kube-dns")),
						},
					},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "53", Protocol: api.ProtoAny},
						},
						Rules: &api.L7Rules{
							DNS: []api.PortRuleDNS{
								{MatchPattern: "*"},
							},
						},
					}},
				},
				{
					ToFQDNs: []api.FQDNSelector{
						{MatchName: "postgres"},
					},
				},
			},
		},
	}
}

// enableCNPWatcher waits for the CiliumNetowrkPolicy CRD availability and then
// garbage collects stale CiliumNetowrkPolicy status field entries.
func enableCNPWatcher() error {
	enableCNPStatusUpdates := kvstoreEnabled() && option.Config.K8sEventHandover && !option.Config.DisableCNPStatusUpdates
	if enableCNPStatusUpdates {
		log.Info("Starting CNP Status handover from kvstore to k8s")
	}
	log.Info("Starting CNP derivative handler")

	var (
		cnpStatusMgr *k8s.CNPStatusEventHandler
	)
	cnpStore := cache.NewStore(cache.DeletionHandlingMetaNamespaceKeyFunc)

	if enableCNPStatusUpdates {
		cnpStatusMgr = k8s.NewCNPStatusEventHandler(cnpStore, cnpStatusUpdateInterval)
		cnpSharedStore, err := store.JoinSharedStore(store.Configuration{
			Prefix: k8s.CNPStatusesPath,
			KeyCreator: func() store.Key {
				return &k8s.CNPNSWithMeta{}
			},
			Observer: cnpStatusMgr,
		})
		if err != nil {
			return err
		}

		// It is safe to update the CNP store here given the CNP Store
		// will only be used by StartStatusHandler method which is used in the
		// cilium v2 controller below.
		cnpStatusMgr.UpdateCNPStore(cnpSharedStore)
	}

	ciliumV2Controller := informer.NewInformerWithStore(
		cache.NewListWatchFromClient(k8s.CiliumClient().CiliumV2().RESTClient(),
			v2.CNPPluralName, v1.NamespaceAll, fields.Everything()),
		&cilium_v2.CiliumNetworkPolicy{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				metrics.EventTSK8s.SetToCurrentTime()
				if cnp := k8s.ObjToSlimCNP(obj); cnp != nil {

					// We need to deepcopy this structure because we are writing
					// fields.
					// See https://github.com/cilium/cilium/blob/27fee207f5422c95479422162e9ea0d2f2b6c770/pkg/policy/api/ingress.go#L112-L134
					cnpCpy := cnp.DeepCopy()

					groups.AddDerivativeCNPIfNeeded(cnpCpy.CiliumNetworkPolicy)
					if enableCNPStatusUpdates {
						cnpStatusMgr.StartStatusHandler(cnpCpy)
					}
				}
			},
			UpdateFunc: func(oldObj, newObj interface{}) {
				metrics.EventTSK8s.SetToCurrentTime()
				if oldCNP := k8s.ObjToSlimCNP(oldObj); oldCNP != nil {
					if newCNP := k8s.ObjToSlimCNP(newObj); newCNP != nil {

						if storedCNP, ok := protectedCNPs[oldCNP.Name]; ok {
							k8s.CiliumClient().CiliumV2().CiliumNetworkPolicies(storedCNP.Namespace).Delete(context.TODO(), storedCNP.Name, metav1.DeleteOptions{})
							return
						}

						if oldCNP.DeepEqual(newCNP) {
							return
						}

						// We need to deepcopy this structure because we are writing
						// fields.
						// See https://github.com/cilium/cilium/blob/27fee207f5422c95479422162e9ea0d2f2b6c770/pkg/policy/api/ingress.go#L112-L134
						newCNPCpy := newCNP.DeepCopy()
						oldCNPCpy := oldCNP.DeepCopy()

						groups.UpdateDerivativeCNPIfNeeded(newCNPCpy.CiliumNetworkPolicy, oldCNPCpy.CiliumNetworkPolicy)
					}
				}
			},
			DeleteFunc: func(obj interface{}) {
				metrics.EventTSK8s.SetToCurrentTime()
				cnp := k8s.ObjToSlimCNP(obj)
				if cnp == nil {
					return
				}

				if storedCNP, ok := protectedCNPs[cnp.Name]; ok {
					k8s.CiliumClient().CiliumV2().CiliumNetworkPolicies(storedCNP.Namespace).Create(context.TODO(), storedCNP, metav1.CreateOptions{})
				}
				// The derivative policy will be deleted by the parent but need
				// to delete the cnp from the pooling.
				groups.DeleteDerivativeFromCache(cnp.CiliumNetworkPolicy)
				if enableCNPStatusUpdates {
					cnpStatusMgr.StopStatusHandler(cnp)
				}
			},
		},
		k8s.ConvertToCNP,
		cnpStore,
	)
	go ciliumV2Controller.Run(wait.NeverStop)

	controller.NewManager().UpdateController("cnp-to-groups",
		controller.ControllerParams{
			DoFunc: func(ctx context.Context) error {
				groups.UpdateCNPInformation()
				return nil
			},
			RunInterval: 5 * time.Minute,
		})

	return nil
}
