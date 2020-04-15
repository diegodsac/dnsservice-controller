package config

import (
	dnsserviceclientset "dnsservice-controller/pkg/client/clientset/versioned"
	"log"
	"net/http"

	"github.com/gorilla/mux"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type CFG struct {
	client           kubernetes.Clientset
	dnsserviceClient dnsserviceclientset.Clientset
	dynclient        dynamic.Interface
	Cfg              *rest.Config
	DynClient        *dynamic.Interface
	Cache            v1.Object
}

type SpecDNSeZONE struct {
	Zone        string `json:"zone,omitempty"`
	Type        string `json:"type,omitempty"`
	Records     string `json:"records,omitempty"`
	TTL         string `json:"ttl,omitempty"`
	Server      string `json:"server,omitempty"`
	Description string `json:"description,omitempty"`
}

type SpecDNS struct {
	SpecDNSeZONE
	URL       string `json:"url,omitempty"`
	UID       string `json:"authkey,omitempty"`
	Hostname  string `json:"hostname,omitempty"`
	Operation string `json:"operation,omitempty"`
}

type Status struct {
	State   string `json:"state,omitempty"`
	Message string `json:"message,omitempty"`
}
type SpecZONE struct {
	SpecDNSeZONE
	AuthKey          string `json:"authkey,omitempty"`
	BrokerVersion    string `json:"BrokerVersion,omitempty"`
	BrokerIdentity   string `json:"BrokerIdentity,omitempty"`
	Clusterid        string `json:"clusterid,omitempty"`
	Namespace        string `json:"namespace,omitempty"`
	Platform         string `json:"platform,omitempty"`
	Serviceid        string `json:"Serviceid,omitempty"`
	Planid           string `json:"Planid,omitempty"`
	Spaceguid        string `json:"spaceguid,omitempty"`
	Organizationguid string `json:"organizationguid,omitempty"`
	Url1             string `json:"Url1,omitempty"`
	Url2             string `json:"Url2,omitempty"`
}

type CrZONE struct {
	SpecZONE
	NameZONE string
	NsZONE   string
}

type MetaData struct {
	Name      string
	NameSPACE string
	UID       string
}

type CrDNS struct {
	SpecDNS
	NameDNS string
	NsDNS   string
	UID     string
	Status
}

type CrDZ struct {
	CFG
	CrZONE
	CrDNS
}

type PatchStringValue struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value string `json:"value"`
}

type PatchIntValue struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value int    `json:"value"`
}

//TODO mudar o nome para service
var VirtualServiceSERVICE = schema.GroupVersionResource{
	Group:    "io.bb.com.br",
	Version:  "v1",
	Resource: "dnsservices",
}

var VirtualServiceZONE = schema.GroupVersionResource{
	Group:    "io.bb.com.br",
	Version:  "v1",
	Resource: "dnszones",
}

func InitHttp() {
	router := mux.NewRouter()
	log.Fatal(http.ListenAndServe(":8585", router))
}
