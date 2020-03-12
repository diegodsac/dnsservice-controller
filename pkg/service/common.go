package service

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"

	//"k8s.io/client-go/rest"
	"net"
	"strconv"
	"strings"

	"dnsservice-controller/pkg/config"

	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
)

var regexOperation = "[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}" //string
var regexUid = "[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}"

func HandleFuncError(m string, err error) {
	if err != nil {
		log.Infof("ERROR - %s %s\n", m, err)
	}
}

func HandleFuncSucess(m string, v string) {
	log.Infof("SUCESS - %s %s\n", m, v)
}

func HandleFuncCommonUpdate(crDZNew config.CrDZ, crDZOld config.CrDZ, crZONE []config.CrZONE) {
	var f int
	crDZOld.SpecDNS = getSpecDnsMAP(crDZOld)
	// printKIND(crDZOld)
	crDZNew.SpecDNS = getSpecDnsMAP(crDZNew)
	// printKIND(crDZNew)
	// log.Infof("crDZOld %s", crDZOld.CFG.Cache)
	// log.Infof("crDZNew %s", crDZNew.CFG.Cache)
	// printZONE(crDZ)
	tmp := fmt.Sprintf("%s", crDZOld.CFG.Cache)
	i := strings.Index(tmp, "spec")
	tmpSpec := tmp[i:]
	//url
	i = strings.Index(tmpSpec, "url")
	if i > 0 {
		i = i + len("url") + 2
		URL := tmpSpec[i:]
		f = strings.Index(URL, ",")
		if f > 0 {
			URL = URL[:f]
		} else if f = strings.Index(URL, "}"); f > 0 {
			URL = URL[:f]
		} else {
			URL = ""
		}
		// crDZOld.URL = URL
		log.Infof("URL %s", URL)
		log.Infof("crDZOld.SpecDNS.URL %s", crDZOld.SpecDNS.URL)
	}
	//description
	i = strings.Index(tmpSpec, "description")
	if i > 0 {
		i = i + len("description") + 2
		crDZOld.SpecDNS.Description = tmpSpec[i:]
		f = strings.Index(crDZOld.SpecDNS.Description, ",")
		if f > 0 {
			crDZOld.SpecDNS.Description = crDZOld.SpecDNS.Description[:f]
			crDZOld.SpecDNS.Description = strings.Replace(crDZOld.SpecDNS.Description, "\"", "", -1)
		} else {
			crDZOld.SpecDNS.Description = ""
		}
		log.Infof("crDZOld.SpecDNS.Description %s", crDZOld.SpecDNS.Description)
	}
	//hostname
	i = strings.Index(tmpSpec, "hostname")
	if i > 0 {
		i = i + len("hostname") + 2
		crDZOld.SpecDNS.Hostname = tmpSpec[i:]
		f = strings.Index(crDZOld.SpecDNS.Hostname, ",")
		if f > 0 {
			crDZOld.SpecDNS.Hostname = crDZOld.SpecDNS.Hostname[:f]
			crDZOld.SpecDNS.Hostname = strings.Replace(crDZOld.SpecDNS.Hostname, "\"", "", -1)
		} else {
			crDZOld.SpecDNS.Hostname = ""
		}
		log.Infof("crDZOld.SpecDNS.Hostname %s", crDZOld.SpecDNS.Hostname)
	}
	//operation
	i = strings.Index(tmpSpec, "operation")
	if i > 0 {
		i = i + len("operation") + 2
		crDZOld.SpecDNS.Operation = tmpSpec[i:]
		f = strings.Index(crDZOld.SpecDNS.Operation, ",")
		if f > 0 {
			crDZOld.SpecDNS.Operation = crDZOld.SpecDNS.Operation[:f]
			crDZOld.SpecDNS.Operation = strings.Replace(crDZOld.SpecDNS.Operation, "\"", "", -1)
		} else {
			crDZOld.SpecDNS.Operation = ""
		}
		log.Infof("crDZOld.SpecDNS.Operation %s", crDZOld.SpecDNS.Operation)
	}
	//records
	i = strings.Index(tmpSpec, "records")
	if i > 0 {
		i = i + len("records") + 2
		crDZOld.SpecDNS.Records = tmpSpec[i:]
		f = strings.Index(crDZOld.SpecDNS.Records, ",")
		if f > 0 {
			crDZOld.SpecDNS.Records = crDZOld.SpecDNS.Records[:f]
			crDZOld.SpecDNS.Records = strings.Replace(crDZOld.SpecDNS.Records, "\"", "", -1)
		} else {
			crDZOld.SpecDNS.Records = ""
		}
		log.Infof("crDZOld.SpecDNS.Records %s", crDZOld.SpecDNS.Records)
	}
	//server
	i = strings.Index(tmpSpec, "server")
	if i > 0 {
		i = i + len("server") + 2
		crDZOld.SpecDNS.Server = tmpSpec[i:]
		f = strings.Index(crDZOld.SpecDNS.Server, ",")
		if f > 0 {
			crDZOld.SpecDNS.Server = crDZOld.SpecDNS.Server[:f]
			crDZOld.SpecDNS.Server = strings.Replace(crDZOld.SpecDNS.Server, "\"", "", -1)
		} else {
			crDZOld.SpecDNS.Server = ""
		}
		log.Infof("crDZOld.SpecDNS.Server %s", crDZOld.SpecDNS.Server)
	}
	//ttl
	i = strings.Index(tmpSpec, "ttl")
	if i > 0 {
		i = i + len("ttl") + 2
		crDZOld.SpecDNS.TTL = tmpSpec[i:]
		f = strings.Index(crDZOld.SpecDNS.TTL, ",")
		if f > 0 {
			crDZOld.SpecDNS.TTL = crDZOld.SpecDNS.TTL[:f]
			crDZOld.SpecDNS.TTL = strings.Replace(crDZOld.SpecDNS.TTL, "\"", "", -1)
		} else {
			crDZOld.SpecDNS.TTL = "0"
		}
		log.Infof("crDZOld.SpecDNS.TTL %s", crDZOld.SpecDNS.TTL)
	}
	//type
	i = strings.Index(tmpSpec, "type")
	if i > 0 {
		i = i + len("type") + 2
		crDZOld.SpecDNS.Type = tmpSpec[i:]
		f = strings.Index(crDZOld.SpecDNS.Type, ",")
		if f > 0 {
			crDZOld.SpecDNS.Type = crDZOld.SpecDNS.Type[:f]
			crDZOld.SpecDNS.Type = strings.Replace(crDZOld.SpecDNS.Type, "\"", "", -1)
		} else {
			crDZOld.SpecDNS.Type = ""
		}
		log.Infof("crDZOld.SpecDNS.Type %s", crDZOld.SpecDNS.Type)
	}
	//zone
	i = strings.Index(tmpSpec, "zone")
	if i > 0 {
		i = i + len("zone") + 2
		crDZOld.SpecDNS.Zone = tmpSpec[i:]
		f = strings.Index(crDZOld.SpecDNS.Zone, "}")
		if f > 0 {
			crDZOld.SpecDNS.Zone = crDZOld.SpecDNS.Zone[:f]
			crDZOld.SpecDNS.Zone = strings.Replace(crDZOld.SpecDNS.Zone, "\"", "", -1)
		} else {
			crDZOld.SpecDNS.Zone = ""
		}

		log.Infof("crDZOld.SpecDNS.Zone %s", crDZOld.SpecDNS.Zone)
	}
	printKIND(crDZOld)
	// log.Infof("TMP %s", tmpSpec)
	// log.Infof("URL %s", url)
	if crDZNew.URL == crDZOld.URL {
		log.Infof("########################\n")
		if (crDZNew.SpecDNS.Description == "") && (crDZNew.SpecDNS.Hostname == "") &&
			(crDZNew.SpecDNS.Operation == "") && (crDZNew.SpecDNS.Records == "") &&
			(crDZNew.SpecDNS.Server == "") && (crDZNew.SpecDNS.Type == "") && (crDZNew.SpecDNS.Zone == "") {
			// if crDZNew.SpecDNS.Description == "" {
			crDZNew.SpecDNS.Description = crDZOld.SpecDNS.Description
			crDZNew.SpecDNS.Hostname = crDZOld.SpecDNS.Hostname
			crDZNew.SpecDNS.Operation = crDZOld.SpecDNS.Operation
			crDZNew.SpecDNS.Records = crDZOld.SpecDNS.Records
			crDZNew.SpecDNS.Server = crDZOld.SpecDNS.Server
			crDZNew.SpecDNS.TTL = crDZOld.SpecDNS.TTL
			crDZNew.SpecDNS.Type = crDZOld.SpecDNS.Type
			crDZNew.SpecDNS.Zone = crDZOld.SpecDNS.Zone
			log.Infof("-------------------------\n")
			patchCrDNS(&crDZNew)
		}
	}
	log.Infof("crDZNEWW\n")
	printKIND(crDZNew)
}

//-------------------------------------------NEW------------------------------------------------------
func printKIND(dz config.CrDZ) {
	log.Infof("crDZ.URL %s", dz.URL)
	log.Infof("crDZ.TTL %s", dz.SpecDNS.TTL)
	log.Infof("crDZ.Description %s", dz.SpecDNS.Description)
	log.Infof("crDZ.Records %s", dz.SpecDNS.Records)
	log.Infof("crDZ.Hostname %s", dz.SpecDNS.Hostname)
	log.Infof("crDZ.Type %s", dz.SpecDNS.Type)
	log.Infof("crDZ.Server %s", dz.SpecDNS.Server)
	log.Infof("crDZ.Zone %s", dz.SpecDNS.Zone)
	log.Infof("crDZ.Operation %s", dz.SpecDNS.Operation)
	log.Infof("crDZ.UID %s", dz.SpecDNS.UID)
	log.Infof("crDZ.clusterid %s", dz.SpecZONE.Clusterid)
	log.Infof("crDZ.namespace %s", dz.SpecZONE.Namespace)
	log.Infof("crDZ.platform %s", dz.SpecZONE.Platform)
	log.Infof("dz.CrDNS.State %s", dz.CrDNS.State)
	log.Infof("dz.CrDNS.Message %s", dz.CrDNS.Message)

}

func printZONE(crZONE config.CrZONE) {
	log.Infof("AuthKey %s", crZONE.AuthKey)
	log.Infof("BrokerVersion %s", crZONE.BrokerVersion)
	log.Infof("BrokerIdentity %s", crZONE.BrokerIdentity)
	log.Infof("Clusterid %s", crZONE.Clusterid)
	log.Infof("Namespace %s", crZONE.Namespace)
	log.Infof("Platform %s", crZONE.Platform)
	log.Infof("Serviceid %s", crZONE.Serviceid)
	log.Infof("Planid %s", crZONE.Planid)
	log.Infof("Organizationguid %s", crZONE.Organizationguid)
	log.Infof("Spaceguid %s", crZONE.Spaceguid)
	log.Infof("Url1 %s", crZONE.Url1)
	log.Infof("Url2 %s", crZONE.Url2)
	//log.Infof("Status %s", dz.CrZONE.Status)
	//log.Infof("Message %s", dz.CrZONE.Message)

}

func mapToString(a string, b string, get map[string]interface{}) (string, bool) {
	var tmp string
	var err bool
	if errMAP := get[a]; errMAP != nil {
		tmp, err = get[a].(map[string]interface{})[b].(string)
	}
	return tmp, err
}

func mapToInt(a string, b string, get map[string]interface{}) (int64, bool) {
	tmp, err := get[a].(map[string]interface{})[b].(int64)
	return tmp, err
}

func getSpecZone(crDZ config.CrDZ, crZONE config.CrZONE) config.SpecZONE {
	dynamicClient, _ := dynamic.NewForConfig(crDZ.Cfg)
	get, err := dynamicClient.Resource(config.VirtualServiceZONE).Namespace(crZONE.NsZONE).Get(crZONE.NameZONE, metav1.GetOptions{})
	if err != nil {
		//log.Infof("EROOR: %s", err)
		return crZONE.SpecZONE
	}
	getToLIST, _ := get.ToList()
	if err != nil {
		return crZONE.SpecZONE
	}
	mapZONE := getToLIST.UnstructuredContent()
	crZONE.AuthKey, _ = mapToString("spec", "authkey", mapZONE)
	crZONE.Server, _ = mapToString("spec", "server", mapZONE)
	crZONE.Zone, _ = mapToString("spec", "zone", mapZONE)
	crZONE.Type, _ = mapToString("spec", "type", mapZONE)
	crZONE.Records, _ = mapToString("spec", "records", mapZONE)
	crZONE.TTL, _ = mapToString("spec", "ttl", mapZONE)
	crZONE.Description, _ = mapToString("spec", "description", mapZONE)
	crZONE.BrokerVersion, _ = mapToString("spec", "brokerversion", mapZONE)
	crZONE.BrokerIdentity, _ = mapToString("spec", "brokeridentity", mapZONE)
	crZONE.Clusterid, _ = mapToString("spec", "clusterid", mapZONE)
	crZONE.Namespace, _ = mapToString("spec", "namespace", mapZONE)
	crZONE.Platform, _ = mapToString("spec", "platform", mapZONE)
	crZONE.Serviceid, _ = mapToString("spec", "serviceid", mapZONE)
	crZONE.Planid, _ = mapToString("spec", "planid", mapZONE)
	crZONE.Spaceguid, _ = mapToString("spec", "spaceguid", mapZONE)
	crZONE.Organizationguid, _ = mapToString("spec", "organizationguid", mapZONE)
	crZONE.Url1, _ = mapToString("spec", "url1", mapZONE)
	crZONE.Url2, _ = mapToString("spec", "url2", mapZONE)
	return crZONE.SpecZONE
}

func getProvision(dz *config.CrDZ) (string, string) {
	var state, description string

	url := dz.SpecZONE.Server + dz.SpecZONE.Url1 + dz.CrDNS.UID + "/last_operation?service_id=" + dz.Serviceid + "&plan_id=" + dz.Planid + "&operation=" + dz.Operation
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		HandleFuncError("SERVER:", err)
		return state, err.Error()
	} else {
		HandleFuncSucess("SERVER:", "string(req)")
	}
	req.Header.Set("X-Broker-API-Version", "2.13")
	req.Header.Set("X-Broker-Api-Originating-Identity", "kubernetes eyJ1c2VybmFtZSI6Imt1YmUtYWRtaW4tcHhsMXBzY210MDAyIiwidWlkIjoiIiwiZ3JvdXBzIjpbInN5c3RlbTptYXN0ZXJzIiwic3lzdGVtOmF1dGhlbnRpY2F0ZWQiXX0=")
	req.Header.Set("cache-control", "no-cache")
	req.Header.Set("Authorization", dz.AuthKey)
	req.Header.Set("Postman-Token", "fd592644-df29-4ca5-ae8a-0c590990960b")
	resp, err := client.Do(req)
	if err == nil {
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			HandleFuncError("REQUEST:", err)
		} else {
			HandleFuncSucess("REQUEST:", string(body))
			bodyString := string(body)
			log.Infof("%s", body)
			if strings.Index(bodyString, "state") > 0 {
				state = bodyString[(strings.Index(bodyString, "state") + 9):(strings.Index(bodyString, ",") - 1)]
			}
			if strings.Index(bodyString, "description") > 0 {
				description = bodyString[(strings.Index(bodyString, "description") + 15):(strings.LastIndex(bodyString, "\"") - 1)]
			}
			HandleFuncSucess("REQUEST:", state)
			HandleFuncSucess("REQUEST:", description)
		}
	} else {
		HandleFuncError("SERVER", err)
	}
	return state, description
}

func getSpecDnsMAP(dz config.CrDZ) config.SpecDNS {
	dynamicClient, _ := dynamic.NewForConfig(dz.CFG.Cfg)
	get, err := dynamicClient.Resource(config.VirtualServiceSERVICE).Namespace(dz.NsDNS).Get(dz.NameDNS, metav1.GetOptions{})
	if err != nil {
		log.Infof("ERROR: %s", err)
		return dz.CrDNS.SpecDNS
	}
	getToLIST, _ := get.ToList()
	if err != nil {
		return dz.CrDNS.SpecDNS
	}

	mapSERVICE := getToLIST.UnstructuredContent()
	dz.SpecDNS.URL, _ = mapToString("spec", "url", mapSERVICE)
	dz.SpecDNS.Zone, _ = mapToString("spec", "zone", mapSERVICE)
	dz.SpecDNS.Description, _ = mapToString("spec", "description", mapSERVICE)
	dz.SpecDNS.Server, _ = mapToString("spec", "server", mapSERVICE)
	dz.SpecDNS.Operation, _ = mapToString("spec", "operation", mapSERVICE)
	dz.SpecDNS.UID, _ = mapToString("spec", "uid", mapSERVICE)
	dz.SpecDNS.Records, _ = mapToString("spec", "records", mapSERVICE)
	dz.SpecDNS.Hostname, _ = mapToString("spec", "hostname", mapSERVICE)
	tmp, _ := mapToInt("spec", "ttl", mapSERVICE)
	dz.SpecDNS.TTL = strconv.FormatInt(tmp, 10)
	dz.SpecDNS.Type, _ = mapToString("spec", "type", mapSERVICE)
	dz.CrDNS.Message, _ = mapToString("status", "message", mapSERVICE)
	dz.CrDNS.State, _ = mapToString("status", "state", mapSERVICE)

	//tmpGracePeriodSeconds ,_:= mapToInt("metadata", "deletiongraceperiodseconds", mapSERVICE)
	//log.Infof("tmpGracePeriodSeconds %s",tmpGracePeriodSeconds)
	return dz.SpecDNS
}

func getSpecDnsCrZONE(dz config.CrDZ) config.SpecDNS {

	var crDNS config.SpecDNS
	crDNS.Description = dz.CrZONE.Description
	tmp := dz.SpecDNS.URL + "."
	crDNS.Hostname = dz.SpecDNS.URL[0:strings.Index(tmp, dz.CrZONE.Zone)]
	crDNS.Records = dz.SpecZONE.Records
	crDNS.Server = dz.SpecZONE.Server
	crDNS.TTL = dz.SpecZONE.TTL
	crDNS.Type = dz.SpecZONE.Type
	crDNS.URL = dz.URL
	crDNS.Zone = dz.SpecZONE.Zone
	crDNS.UID = dz.UID
	crDNS.Operation = dz.Operation

	return crDNS
}

func getStatus(dz config.CrDZ) [2]string {
	//var tmp unstructured.Unstructured
	dynamicClient, _ := dynamic.NewForConfig(dz.Cfg)
	get, _ := dynamicClient.Resource(config.VirtualServiceSERVICE).Namespace(dz.NsDNS).Get(dz.NameDNS, metav1.GetOptions{})

	//inicio do for para NsZONE
	getToList, _ := get.ToList()
	mapSERVICE := getToList.UnstructuredContent()
	errStatus := mapSERVICE["status"]
	if errStatus != nil {
		message, _ := mapToString("status", "message", mapSERVICE)
		state, _ := mapToString("status", "state", mapSERVICE)
		status := [2]string{message, state}
		return status
	} else if errStatus == nil {

		return [2]string{"", ""}
	}
	return [2]string{"", ""}
}

func getAnnotationsCrDZ(dz config.CrDZ) config.CrDNS {

	//TODO mudar para usar tanto GetAnnotations quanto o estado
	//TODO deletar quando o state estiver Pending e a message operation
	//TODO quando tiver o operation tentar deletar

	cacheAnnotations := (dz.CFG.Cache).GetAnnotations()
	log.Infof("RESULT %s", cacheAnnotations)
	values := []string{}
	for _, value := range cacheAnnotations {
		values = append(values, value)
	}
	getslice := values[0]
	tmpSpec := getslice[strings.Index(getslice, "spec")+7 : len(getslice)-2]
	tmpSpecArray := strings.Split(tmpSpec, ",")

	for _, value := range tmpSpecArray {
		if strings.Index(value, "url") > 0 {
			dz.CrDNS.URL = value[strings.Index(value, ":")+2 : strings.LastIndex(value, "\"")]
		} else if strings.Index(value, "description") > 0 {
			dz.CrDNS.Description = value[strings.Index(value, ":")+2 : strings.LastIndex(value, "\"")]
		} else if strings.Index(value, "hostname") > 0 {
			dz.CrDNS.Hostname = value[strings.Index(value, ":")+2 : strings.LastIndex(value, "\"")]
		} else if strings.Index(value, "records") > 0 {
			dz.CrDNS.Records = value[strings.Index(value, ":")+2 : strings.LastIndex(value, "\"")]
		} else if strings.Index(value, "server") > 0 {
			dz.CrDNS.Server = value[strings.Index(value, ":")+2 : strings.LastIndex(value, "\"")]
		} else if strings.Index(value, "ttl") > 0 {
			dz.CrDNS.TTL = value[strings.Index(value, ":")+1:]
		} else if strings.Index(value, "type") > 0 {
			dz.CrDNS.Type = value[strings.Index(value, ":")+2 : strings.LastIndex(value, "\"")]
		} else if strings.Index(value, "zone") > 0 {
			dz.CrDNS.Zone = value[strings.Index(value, ":")+2 : strings.LastIndex(value, "\"")]
		} else if strings.Index(value, "operation") > 0 {
			dz.CrDNS.Operation = value[strings.Index(value, ":")+2 : strings.LastIndex(value, "\"")]
		}
		tmpStatus := getslice[strings.Index(getslice, "status")+9 : len(getslice)-2]
		tmpStatusArray := strings.Split(tmpStatus, ",")
		for _, value := range tmpStatusArray {
			log.Infof("value tmpStatusArray %s", value)
			if strings.Index(value, "message") > 0 {
				dz.CrDNS.Message = value[strings.Index(value, ":")+2 : strings.LastIndex(value, "\"")]
			} else if strings.Index(value, "state") > 0 {
				dz.CrDNS.State = value[strings.Index(value, ":")+2 : strings.LastIndex(value, "\"")]
			}
		}
	}

	log.Infof("DELETE")
	log.Infof("getslice %s", getslice)
	return dz.CrDNS
}

func fetchZone(dz config.CrDZ, crZONE []config.CrZONE) config.CrZONE {
	tmpURL := dz.URL + "."
	for i := 0; i < len(crZONE); i++ {
		crZONE[i].SpecZONE = getSpecZone(dz, crZONE[i])
		log.Infof("Comparação: %s -- %s", tmpURL, crZONE[i].Zone)
		if strings.Index(tmpURL, crZONE[i].Zone) > 0 {
			dz.SpecZONE = crZONE[i].SpecZONE
			dz.SpecDNS = getSpecDnsCrZONE(dz)
			patchCrDNS(&dz)
			break
		}
	}
	return dz.CrZONE
}

func patchValueStatus(dz config.CrDZ, state string, message string) {
	var tmp unstructured.Unstructured
	dynamicClient, _ := dynamic.NewForConfig(dz.Cfg)
	get, _ := dynamicClient.Resource(config.VirtualServiceSERVICE).Namespace(dz.CrDNS.NsDNS).Get(dz.CrDNS.NameDNS, metav1.GetOptions{})
	getlist, _ := get.ToList()
	getservice := getlist.UnstructuredContent()
	getservice["status"] = map[string]interface{}{"message": message, "state": state}
	delete(getservice, "items")
	tmp.Object = getservice
	_, _ = dynamicClient.Resource(config.VirtualServiceSERVICE).Namespace(dz.NsDNS).UpdateStatus(&tmp, metav1.UpdateOptions{})
}

func patchAnnotations(dz config.CrDZ) {
	var tmp unstructured.Unstructured
	dynamicClient, _ := dynamic.NewForConfig(dz.Cfg)
	annotations, mapAnnotations := getAnnotationsNEW(&dz)
	//log.Infof("\nTT%s", len(annotations))
	//log.Infof("%s", annotations)
	//log.Infof("getAnnotations%s", mapAnnotations)
	tmpAnnotations := "\"url\":" + "\"" + dz.URL + "\","
	tmpAnnotations = tmpAnnotations + "\"description\":" + "\"" + dz.CrDNS.Description + "\","
	tmpAnnotations = tmpAnnotations + "\"hostname\":" + "\"" + dz.CrDNS.Hostname + "\","
	tmpAnnotations = tmpAnnotations + "\"operation\":" + "\"" + dz.CrDNS.Operation + "\","
	tmpAnnotations = tmpAnnotations + "\"records\":" + "\"" + dz.CrDNS.Records + "\","
	tmpAnnotations = tmpAnnotations + "\"server\":" + "\"" + dz.CrDNS.Server + "\","
	tmpAnnotations = tmpAnnotations + "\"ttl\":" + dz.CrDNS.TTL + ","
	tmpAnnotations = tmpAnnotations + "\"type\":" + "\"" + dz.CrDNS.Type + "\","
	//tmpAnnotations = tmpAnnotations + "\"zone\":" + "\"" + dz.CrDNS.Zone + "\"}}"
	tmpAnnotations = tmpAnnotations + "\"zone\":" + "\"" + dz.CrDNS.Zone + "\"}"
	tmpAnnotations = tmpAnnotations + "," + "\"status\":{"
	tmpAnnotations = tmpAnnotations + "\"message\":" + "\"" + dz.CrDNS.Message + "\","
	tmpAnnotations = tmpAnnotations + "\"state\":" + "\"" + dz.CrDNS.State + "\"}}"

	//log.Infof("tmpAnnotations %s",tmpAnnotations)
	if strings.Index(annotations, "spec") > 0 {
		annotations = annotations[0:strings.Index(annotations, "spec")+7] + tmpAnnotations
	} else if (len(annotations) - 3) > 0 {
		annotations = annotations[0:(len(annotations)-3)] + "," + tmpAnnotations
	} else {
		get, err := dynamicClient.Resource(config.VirtualServiceSERVICE).Namespace(dz.NsDNS).Get(dz.NameDNS, metav1.GetOptions{})
		if err != nil {
			log.Infof("ERROR: %s", err)
			return
		}
		getToLIST, _ := get.ToList()
		mapSERVICE := getToLIST.UnstructuredContent()
		//tmpApiVersion, _ = mapToString("spec", "url", mapSERVICE)
		tmpApiVersion, _ := mapSERVICE["apiVersion"].(string)
		tmpKind, _ := mapSERVICE["kind"].(string)
		tmpName, _ := mapSERVICE["metadata"].(map[string]interface{})["name"].(string)
		tmpNameSpace, _ := mapSERVICE["metadata"].(map[string]interface{})["namespace"].(string)
		//log.Infof("tmpApiVersion %s", tmpApiVersion)
		//log.Infof("tmpKind %s", tmpKind)
		//log.Infof("tmpName %s", tmpName)
		//log.Infof("tmpNameSpace %s", tmpNameSpace)
		tmpAnnotations = "\"namespace\":\"" + tmpNameSpace + "\"},\"spec\":{" + tmpAnnotations
		tmpAnnotations = "\"name\":\"" + tmpName + "\"," + tmpAnnotations
		tmpAnnotations = "\"metadata\":{\"annotations\":{}," + tmpAnnotations
		tmpAnnotations = "\"kind\":\"" + tmpKind + "\"," + tmpAnnotations
		tmpAnnotations = "{\"apiVersion\":\"" + tmpApiVersion + "\"," + tmpAnnotations
		log.Infof("tmpAnnotations %s", tmpAnnotations)
		annotations = tmpAnnotations
		//getservice["status"] = map[string]interface{}{"message": message, "state": state}
		//tmp2 := map[string]string{"kubectl.kubernetes.io/last-applied-configuration":annotations}
		//dz.Cache.SetAnnotations(tmp2)
		//mapAnnotations["metadata"] = map[string]interface{}{"annotations": "kubectl.kubernetes.io/last-applied-configuration: |"}
		//delete(mapAnnotations, "items")
		//tmp.Object = mapAnnotations
		//_, _ = dynamicClient.Resource(config.VirtualServiceSERVICE).Namespace(dz.NsDNS).Update(&tmp, metav1.UpdateOptions{})
		//mapAnnotations["metadata"].(map[string]interface{})["annotations"].(map[string]interface{})["kubectl.kubernetes.io/last-applied-configuration"] = annotations
		////delete(mapAnnotations, "items")
		//tmp.Object = mapAnnotations
		//_, _ = dynamicClient.Resource(config.VirtualServiceSERVICE).Namespace(dz.NsDNS).Update(&tmp, metav1.UpdateOptions{})
	}
	log.Infof("annotations %s", tmpAnnotations)
	//--------------------
	mapAnnotations["metadata"].(map[string]interface{})["annotations"].(map[string]interface{})["kubectl.kubernetes.io/last-applied-configuration"] = annotations
	delete(mapAnnotations, "items")
	tmp.Object = mapAnnotations
	_, _ = dynamicClient.Resource(config.VirtualServiceSERVICE).Namespace(dz.NsDNS).Update(&tmp, metav1.UpdateOptions{})
	//--------------------
	//log.Infof("\nannotations%s\n getMap%s", annotations, tmpAnnotations)

}

func patchValueInt(value int, path string, dz *config.CrDZ) {
	patchPayload := make([]config.PatchIntValue, 1)
	patchPayload[0].Op = "replace"
	patchPayload[0].Path = path
	patchPayload[0].Value = value
	patchBytes, _ := json.Marshal(patchPayload)
	dynamicClient, _ := dynamic.NewForConfig(dz.Cfg)
	_, err := dynamicClient.Resource(config.VirtualServiceSERVICE).Namespace(dz.CrDNS.NsDNS).Patch(dz.CrDNS.NameDNS, types.JSONPatchType, patchBytes, metav1.UpdateOptions{})
	if err != nil {
		HandleFuncError("PATCH:", err)
	} else {
		HandleFuncSucess("PATCH:", string(value))
	}
}

func patchValueString(value string, path string, dz *config.CrDZ) {
	patchPayload := make([]config.PatchStringValue, 1)
	patchPayload[0].Op = "replace"
	patchPayload[0].Path = path
	patchPayload[0].Value = value
	patchBytes, _ := json.Marshal(patchPayload)
	dynamicClient, _ := dynamic.NewForConfig(dz.Cfg)
	_, err := dynamicClient.Resource(config.VirtualServiceSERVICE).Namespace(dz.CrDNS.NsDNS).Patch(dz.CrDNS.NameDNS, types.JSONPatchType, patchBytes, metav1.UpdateOptions{})
	if err != nil {
		HandleFuncError("PATCH:", err)
	} else {
		HandleFuncSucess("PATCH:", string(value))
	}
}

func patchCrDNS(dz *config.CrDZ) {
	if dz.CrDNS.Server != "" {
		patchValueString(dz.CrDNS.Server, "/spec/server", dz)
	}
	if dz.CrDNS.Zone != "" {
		patchValueString(dz.CrDNS.Zone, "/spec/zone", dz)
	}
	if dz.CrDNS.Hostname != "" {
		patchValueString(dz.CrDNS.Hostname, "/spec/hostname", dz)
	}
	if dz.CrDNS.Type != "" {
		patchValueString(dz.CrDNS.Type, "/spec/type", dz)
	}
	intTTL, _ := strconv.Atoi(dz.CrDNS.TTL)
	if dz.CrDNS.TTL != "" {
		patchValueInt(intTTL, "/spec/ttl", dz)
	}
	if dz.CrDNS.Records != "" {
		patchValueString(dz.CrDNS.Records, "/spec/records", dz)
	}
	if dz.CrDNS.Description != "" {
		patchValueString(dz.CrDNS.Description, "/spec/description", dz)
	}
	if dz.CrDNS.Operation != "" {
		patchValueString(dz.CrDNS.Operation, "/spec/operation", dz)
	}

}

func HandleFuncCommonAdd(crDZ config.CrDZ, crZONE []config.CrZONE) {
	//TODO 1) checar quais os parametros passados
	//TODO 2) Status da aplicaçao
	//TODO 3) atualizar o spec com as informaçoes não passadas

	// log.Infof("ZONAZONAZONAZONAZONAZONA %s\n", crZONE)
INIT:
	crDZ.SpecDNS = getSpecDnsMAP(crDZ)
	//printKIND(crDZ)
	tmp := getStatus(crDZ)
	crDZ.CrDNS.Message = tmp[0]
	crDZ.CrDNS.State = tmp[1]

	//log.Infof("crDZ.CrDNS.State %s", crDZ.CrDNS.State)

	if crDZ.CrDNS.State == "" {
		patchValueStatus(crDZ, "Pending", "Waiting...")
		goto INIT
	} else if crDZ.CrDNS.State == "Pending" {
		if crDZ.CrDNS.Message == "Waiting..." {
			printKIND(crDZ)
			if crDZ.URL != "" {
				tmpURL := crDZ.URL + "."
				//Multiplas zonas
				if len(crZONE) > 1 {
					log.Infof("Multiplas Zonas")
					log.Infof("%v", tmpURL)
					for i := 0; i < len(crZONE); i++ {
						crZONE[i].SpecZONE = getSpecZone(crDZ, crZONE[i])
						log.Infof("Comparação: %s -- %s", tmpURL, crZONE[i].Zone)
						if strings.Index(tmpURL, crZONE[i].Zone) > 0 {
							crDZ.SpecZONE = crZONE[i].SpecZONE
							crDZ.SpecDNS = getSpecDnsCrZONE(crDZ)
							patchCrDNS(&crDZ)
							break
						}
					}
					crDZ.SpecDNS = getSpecDnsMAP(crDZ)
					if crDZ.SpecDNS.Zone == "" {
						patchValueStatus(crDZ, "Failed", "unauthorized zone")
					} else {
						patchValueStatus(crDZ, "Pending", "Creating...")
					}

					printKIND(crDZ)
					//Unica zona de dns
				} else {
					crZONE[0].SpecZONE = getSpecZone(crDZ, crZONE[0])
					log.Infof("ZONAZONAZONAZONAZONAZONA %s\n")
					printZONE(crZONE[0])
					log.Infof("Comparação: %s -- %s", tmpURL, crZONE[0].Zone)
					if strings.Index(tmpURL, crZONE[0].Zone) > 0 {
						crDZ.SpecZONE = crZONE[0].SpecZONE
						crDZ.SpecDNS = getSpecDnsCrZONE(crDZ)
						patchCrDNS(&crDZ)
					}
					crDZ.SpecDNS = getSpecDnsMAP(crDZ)
					if crDZ.SpecDNS.Zone == "" {
						patchValueStatus(crDZ, "Failed", "unauthorized zone")
					} else {
						patchValueStatus(crDZ, "Pending", "Creating...")
					}
				}
				//} else if (crDZ.CrDNS.TTL != "") && (crDZ.CrDNS.Description != "") && (crDZ.CrDNS.Records != "") &&
				//	(crDZ.CrDNS.Type != "") && (crDZ.CrDNS.Server != "") && (crDZ.CrDNS.Zone != "") && (crDZ.CrDNS.Hostname != "") {
			} else if (crDZ.CrDNS.TTL != "") && (crDZ.CrDNS.Description != "") && (crDZ.CrDNS.Records != "") &&
				(crDZ.CrDNS.Type != "") && (crDZ.CrDNS.Server != "") && (crDZ.CrDNS.Zone != "") && (crDZ.CrDNS.Hostname != "") {
				log.Infof("TESTE")
				crDZ.CrDNS.URL = crDZ.CrDNS.Hostname + crDZ.CrDNS.Zone[0:len(crDZ.CrDNS.Zone)-1]
				patchValueString(crDZ.CrDNS.URL, "/spec/url", &crDZ)
				patchValueStatus(crDZ, "Pending", "Creating...")
			} else if (crDZ.CrDNS.Operation != "") && (crDZ.CrDNS.UID != "") {
				if match, _ := regexp.MatchString("[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}", crDZ.Operation); match == true {
					patchValueStatus(crDZ, "Running", "provision job complete")
				} else {
					patchValueStatus(crDZ, "Failed", "Operation")
				}

			}
		}
		//patchValueStatus(crDZ, "Pending", "Creating...")
	} else if crDZ.CrDNS.State == "Failed" {
		log.Infof("TESTEration\n")

	} else if crDZ.CrDNS.State == "Running" {
		log.Infof("###########TESTE  #############")
		if crDZ.CrDNS.Message == "provision job complete" {

			if crDZ.CrDNS.Description == "" || crDZ.CrDNS.Records == "" || crDZ.CrDNS.Hostname == "" {
				log.Infof("###########TESTE 1 ENTRADA #############")
				printKIND(crDZ)
				if crDZ.URL != "" {
					tmpURL := crDZ.URL + "."
					//Multiplas zonas
					if len(crZONE) > 1 {
						log.Infof("Multiplas Zonas")
						log.Infof("%v", tmpURL)
						for i := 0; i < len(crZONE); i++ {
							crZONE[i].SpecZONE = getSpecZone(crDZ, crZONE[i])
							log.Infof("Comparação: %s -- %s", tmpURL, crZONE[i].Zone)
							if strings.Index(tmpURL, crZONE[i].Zone) > 0 {
								crDZ.SpecZONE = crZONE[i].SpecZONE
								crDZ.SpecDNS = getSpecDnsCrZONE(crDZ)
								patchCrDNS(&crDZ)
								break
							}
						}
					} else {
						crZONE[0].SpecZONE = getSpecZone(crDZ, crZONE[0])
						log.Infof("Comparação: %s -- %s", tmpURL, crZONE[0].Zone)
						if strings.Index(tmpURL, crZONE[0].Zone) > 0 {
							crDZ.SpecZONE = crZONE[0].SpecZONE
							crDZ.SpecDNS = getSpecDnsCrZONE(crDZ)
							patchCrDNS(&crDZ)
						}
					}
					printZONE(crDZ.CrZONE)
					log.Infof("###########TESTE 1 SAINDO #############")
				}
			}
		}
		// if
	}
	patchAnnotations(crDZ)
	//Chamar add
	//TODO checar se as variaveis de getSpecDNSMAP estao preenchidas
	//TODO checar se as variais de getSpecDnsZone estao preenchidas
	tmpStatus := getStatus(crDZ)
	crDZ.Status.Message = tmpStatus[0]
	crDZ.Status.State = tmpStatus[1]
	//log.Infof("crDZ.CrDNS.State %s", crDZ.CrDNS.State)
	if (crDZ.CrDNS.State == "Pending") && (crDZ.CrDNS.Message == "Creating...") {
		if (crDZ.CrDNS.TTL == "") || (crDZ.CrDNS.Description != "") || (crDZ.CrDNS.Records == "") ||
			(crDZ.CrDNS.Type == "") || (crDZ.CrDNS.Server == "") || (crDZ.CrDNS.Zone == "") ||
			(crDZ.CrDNS.Hostname == "") || (crDZ.SpecDNS.URL == "") {
			crDZ.SpecDNS = getSpecDnsMAP(crDZ)
		}
		if (crDZ.NsZONE == "") || (crDZ.NameZONE == "") {
			crDZ.CrZONE = fetchZone(crDZ, crZONE)
		}
		temp, errUrl := net.LookupHost(crDZ.CrDNS.URL)
		log.Infof("temp %s", temp)
		log.Infof("errUrl %s", errUrl)
		if errUrl != nil {
			log.Infof("errUrl != nil")
			log.Infof("TESTE")
			log.Infof("crDZ.CrZONE.NameZONE %s", crDZ.CrZONE.NameZONE)
			log.Infof("crDZ.CrZONE.NsZONE %s", crDZ.CrZONE.NsZONE)
			printKIND(crDZ)
			HandleFuncAddNEW(&crDZ)
			//patchAnnotations(crDZ)

		} else {
			log.Infof("errUrl.Error() %s", errUrl)
			patchValueStatus(crDZ, "Failed", "Error, already used url")
		}
	} else if (crDZ.CrDNS.State == "Pending") && (crDZ.CrDNS.Operation == "") && (crDZ.CrDNS.Message == "") {
		patchValueStatus(crDZ, "Failed", "Error, already used url")
	}

}

//--------------------------------NEW_DELETE-------------------------------

func HandleFuncCommonDelete(dz config.CrDZ, crZONE []config.CrZONE) {
	//log.Infof("dz.CrDNS.UID %s",dz.CrDNS.UID)
	dz.SpecDNS.UID = dz.CrDNS.UID
	printKIND(dz)
	dz.CrDNS = getAnnotationsCrDZ(dz)
	//log.Infof("%d", dz.CFG.Cache.GetDeletionGracePeriodSeconds())
	//TODO mudar para usar tanto GetAnnotations quanto o estado
	//TODO deletar quando o state estiver Pending e a message operation
	//TODO quando tiver o operation tentar deletar
	//deletePolicy := metav1.DeletePropagationForeground
	//deleteOptions := &metav1.DeleteOptions{
	//	PropagationPolicy: &deletePolicy,
	//}
	//log.Infof("deletePolicy %s", deletePolicy)
	//log.Infof("deleteOptions %s", deleteOptions)
	tmpURL := dz.URL + "."
	if len(crZONE) > 1 {
		log.Infof("Varias Zonas")
		log.Infof("%v", tmpURL)
		for i := 0; i < len(crZONE); i++ {
			crZONE[i].SpecZONE = getSpecZone(dz, crZONE[i])
			log.Infof("Comparação: %s -- %s", tmpURL, crZONE[i].Zone)
			if strings.Index(tmpURL, crZONE[i].Zone) > 0 {
				dz.SpecZONE = crZONE[i].SpecZONE
				dz.SpecDNS = getSpecDnsCrZONE(dz)
				//patchCrDNS(&dz)
				break
			}
		}
		//dz.SpecDNS = getSpecDnsMAP(dz)
		printKIND(dz)
		//print("%s ", dz.Cache.GetOwnerReferences())
	}
	if dz.CrDNS.State == "Running" {
		if dz.SpecDNS.Operation != "" {
			log.Infof("HandleFuncDeleteNEW")
			HandleFuncDeleteNEW(dz)
		}
	} else if dz.CrDNS.State == "Failed" {
		log.Infof("-- Delete --")
	} else if dz.CrDNS.State == "Pending" {
		log.Infof("-- Delete --")
	}

}
