module dnsservice-controller

go 1.13

require (
	github.com/gorilla/mux v1.7.4
	github.com/imdario/mergo v0.3.9 // indirect
	github.com/sirupsen/logrus v1.5.0
	golang.org/x/oauth2 v0.0.0-20200107190931-bf48bf16ab8d // indirect
	golang.org/x/time v0.0.0-20191024005414-555d28b269f0 // indirect
	k8s.io/api v0.18.1 // indirect
	k8s.io/apimachinery v0.18.1
	k8s.io/client-go v11.0.0+incompatible
	k8s.io/utils v0.0.0-20200414100711-2df71ebbae66 // indirect
)

replace k8s.io/client-go v11.0.0+incompatible => k8s.io/client-go v0.18.0
