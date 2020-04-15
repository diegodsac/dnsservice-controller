package main

import (
	"os"
	"os/signal"
	"strings"
	"syscall"

	//"net/http"

	//"github.com/gorilla/mux"
	log "github.com/sirupsen/logrus"
	"k8s.io/apimachinery/pkg/api/meta"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/workqueue"

	"dnsservice-controller/pkg/config"
	"dnsservice-controller/pkg/service"

	"k8s.io/client-go/rest"

	dnsserviceclientset "dnsservice-controller/pkg/client/clientset/versioned"
	dnsserviceinformer_v1 "dnsservice-controller/pkg/client/informers/externalversions/dnsservice/v1"
)

var cfg rest.Config

// retrieve the Kubernetes cluster client from outside of the cluster
func getKubernetesClient() (kubernetes.Interface, dnsserviceclientset.Interface) {
	config, err := rest.InClusterConfig()

	if err != nil {
		// construct the path to resolve to `~/.kube/config`
		//kubeConfigPath := os.Getenv("HOME") + "/.kube/k8s-desenv"
		kubeConfigPath := os.Getenv("HOME") + "/.kube/config"

		// create the config from the path
		config, err = clientcmd.BuildConfigFromFlags("", kubeConfigPath)
	}
	//log.Infof("Config: [%T]", cfg)
	cfg = *config
	if err != nil {
		log.Fatalf("getClusterConfig: %v", err)
	}

	// generate the client based off of the config
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatalf("getClusterConfig: %v", err)
	}

	dnsserviceClient, err := dnsserviceclientset.NewForConfig(config)
	if err != nil {
		log.Fatalf("getClusterConfig: %v", err)
	}

	return client, dnsserviceClient
}

func main() {
	var crDZ config.CrDZ
	var crZONE []config.CrZONE

	var UID_OLD string
	client, dnsserviceClient := getKubernetesClient()
	tmpZone := os.Getenv("NAME")
	tmpNsZone := os.Getenv("NAMESPACE")
	if (tmpZone == "") || (tmpNsZone == "") {
		if tmpZone == "" {
			log.Infof("Error - NAME")
		}
		if tmpNsZone == "" {
			log.Infof("Error - NAMESPACE")
		}
		return
	}
	if strings.Index(tmpZone, ",") > 0 {
		tmpZoneSplit := strings.Split(tmpZone, ",")
		crZONE = make([]config.CrZONE, len(tmpZoneSplit))
		for i := 0; i < len(crZONE); i++ {
			crZONE[i].NameZONE = tmpZoneSplit[i]
			crZONE[i].NsZONE = os.Getenv("NAMESPACE")
		}

	} else {
		crZONE = make([]config.CrZONE, 1)
		crZONE[0].NameZONE = tmpZone
		crZONE[0].NsZONE = os.Getenv("NAMESPACE")
	}
	log.Infof("Tamanho: %d ", len(crZONE))
	for i := 0; i < len(crZONE); i++ {
		log.Infof("indice: %d crZONE[i].NameZONE: %s\n", i, crZONE[i].NameZONE)
	}
	//crZONE = make([]config.CrZONE, len(tmpZoneSplit))
	//for i := 0; i < len(crZONE); i++ {
	//	crZONE[i].NameZONE = tmpZoneSplit[i]
	//	crZONE[i].NsZONE = os.Getenv("NAMESPACE")
	//}

	//match, _ := regexp.MatchString("[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}", "be2bf153-e145-40af-8277-9581c51381cc")
	//log.Infof("REGEX %s", match)
	//match, _ = regexp.MatchString("[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[89ab][a-f0-9]{3}-[a-f0-9]{12}", "f6a3ff5b-991a-11e9-b902-025000000001")
	//log.Infof("REGEX %s", match)

	// retrieve our custom resource informer which was generated from
	// the code generator and pass it the custom resource client, specifying
	// we should be looking through all namespaces for listing and watching
	informer := dnsserviceinformer_v1.NewDnsServiceInformer(
		dnsserviceClient,
		meta_v1.NamespaceAll,
		0,
		cache.Indexers{},
	)
	// create a new queue so that when the informer gets a resource that is either
	// a result of listing or watching, we can add an idenfitying key to the queue
	// so that it can be handled in the handler
	queue := workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter())
	// add event handlers to handle the three types of events for resources:
	//  - adding new resources
	//  - updating existing resources
	//  - deleting resources
	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			// convert the resource object into a key (in this case
			// we are just doing it in the format of 'namespace/name')
			key, err := cache.MetaNamespaceKeyFunc(obj)
			key2, _ := meta.Accessor(obj)
			//log.Infof("key2: \n[%T] \n%s",name, name)
			//log.Infof("%d", key2.GetDeletionGracePeriodSeconds())
			tmpTime := int64(15)
			key2.SetDeletionGracePeriodSeconds(&tmpTime)
			//log.Infof("%d", key2.GetDeletionGracePeriodSeconds())
			crDZ.CrDNS.UID = string(key2.GetUID())
			if crDZ.CrDNS.UID == "" || UID_OLD != crDZ.CrDNS.UID {
				//log.Infof("%d", key2.GetDeletionGracePeriodSeconds())
				UID_OLD = crDZ.CrDNS.UID
				crDZ.NameDNS = string(key2.GetName())
				crDZ.NsDNS = string(key2.GetNamespace())
				crDZ.Cfg = &cfg
				crDZ.Cache = key2
				service.HandleFuncCommonAdd(crDZ, crZONE)
				log.Infof("Add dnsservice: %s", key)
				if err == nil {
					queue.Add(key)
				}
			}

			log.Infof("Add dnsservice: %s", key)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			var crDZOld config.CrDZ
			var crDZNew config.CrDZ
			key, err := cache.MetaNamespaceKeyFunc(oldObj)
			//Struct Config Spec
			key2, _ := meta.Accessor(oldObj)
			key3, _ := meta.Accessor(newObj)
			// log.Infof("oldObj: %s", key2)
			// log.Infof("newObj: %s", key3)
			crDZOld.CrDNS.UID = string(key2.GetUID())
			crDZOld.NameDNS = string(key2.GetName())
			crDZOld.NsDNS = string(key2.GetNamespace())
			crDZOld.Cfg = &cfg
			crDZOld.CFG.Cache = key2
			crDZNew.CrDNS.UID = string(key3.GetUID())
			crDZNew.NameDNS = string(key3.GetName())
			crDZNew.NsDNS = string(key3.GetNamespace())
			crDZNew.Cfg = &cfg
			crDZNew.CFG.Cache = key3

			service.HandleFuncCommonUpdate(crDZNew, crDZOld, crZONE)
			log.Infof("Update dnsservice: %s", key)
			if err == nil {
				queue.Add(key)
			}
		},
		DeleteFunc: func(obj interface{}) {
			// DeletionHandlingMetaNamsespaceKeyFunc is a helper function that allows
			// us to check the DeletedFinalStateUnknown existence in the event that
			// a resource was deleted but it is still contained in the index
			//
			// this then in turn calls MetaNamespaceKeyFunc
			key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
			key2, _ := meta.Accessor(obj)
			crDZ.CrDNS.UID = string(key2.GetUID())
			crDZ.NameDNS = string(key2.GetName())
			crDZ.NsDNS = string(key2.GetNamespace())
			crDZ.Cfg = &cfg
			crDZ.CFG.Cache = key2
			service.HandleFuncCommonDelete(crDZ, crZONE)
			log.Infof("Delete dnsservice: %s", key)
			if err == nil {
				queue.Add(key)
			}
		},
	})

	// construct the Controller object which has all of the necessary components to
	// handle logging, connections, informing (listing and watching), the queue,
	// and the handler
	controller := Controller{
		logger:    log.NewEntry(log.New()),
		clientset: client,
		informer:  informer,
		queue:     queue,
		handler:   &TestHandler{},
	}

	// use a channel to synchronize the finalization for a graceful shutdown
	stopCh := make(chan struct{})
	defer close(stopCh)

	// run the controller loop to process items
	go controller.Run(stopCh)

	// use a channel to handle OS signals to terminate and gracefully shut
	// down processing
	sigTerm := make(chan os.Signal, 1)
	signal.Notify(sigTerm, syscall.SIGTERM)
	signal.Notify(sigTerm, syscall.SIGINT)
	<-sigTerm
}

//Condicoes de regex para entrada dos valores
//Condicoes para delecao quando nao criado
//token de autorizacao
