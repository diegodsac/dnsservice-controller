package v1

import (
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +genclient:noStatus
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// DnsService describes a DnsService resource
type DnsService struct {
	// TypeMeta is the metadata for the resource, like kind and apiversion
	meta_v1.TypeMeta `json:",inline"`
	// ObjectMeta contains the metadata for the particular object, including
	// things like...
	//  - name
	//  - namespace
	//  - self link
	//  - labels
	//  - ... etc ...
	meta_v1.ObjectMeta `json:"metadata,omitempty"`

	// Spec is the custom resource spec
	Spec   DnsServiceSpec   `json:"spec,omitempty"`
	Status DnsServiceStatus `json:"status,omitempty"`
}

// DnsServiceSpec is the spec for a DnsService resource
type DnsServiceSpec struct {
	// Message and TTL are example custom spec fields
	//
	// this is where you would put your custom resource data
	URL         string `json:"url"`
	UID         string `json:"uid"`
	TTL         *int32 `json:"ttl"`
	Server      string `json:"server"`
	Zone        string `json:"zone"`
	Hostname    string `json:"hostname"`
	Type        string `json:"type"`
	Records     string `json:"records"`
	Description string `json:"description"`
	Operation   string `json:"operation"`
}

type DnsServiceStatus struct {
	State   string `json:"state"`
	Message string `json:"message"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// DnsServiceList is a list of DnsService resources
type DnsServiceList struct {
	meta_v1.TypeMeta `json:",inline"`
	meta_v1.ListMeta `json:"metadata"`

	Items []DnsService `json:"items"`
}
