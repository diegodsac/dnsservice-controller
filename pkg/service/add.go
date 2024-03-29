package service

import (
	"context"
	"crypto/tls"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"

	"dnsservice-controller/pkg/config"

	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/dynamic"
)

func patchDeployNEW(dz *config.CrDZ, annotations string, getMap map[string]interface{}) {
	var tmp unstructured.Unstructured
	log.Infof("INIT patchDeployNEW")

	dynamicClient, err := dynamic.NewForConfig(dz.Cfg)
	getMap["metadata"].(map[string]interface{})["annotations"].(map[string]interface{})["kubectl.kubernetes.io/last-applied-configuration"] = annotations
	delete(getMap, "items")
	tmp.Object = getMap
	log.Infof("\nANNOTATIONS%s", annotations)
	_, err = dynamicClient.Resource(config.VirtualServiceSERVICE).Namespace(dz.CrDNS.NsDNS).Update(context.TODO(), &tmp, metav1.UpdateOptions{})
	if err != nil {
		HandleFuncError("ADD ANNOTATIONS:", err)
	} else {
		HandleFuncSucess("ADD ANNOTATIONS:", string(annotations))
	}
}

func putDnsNEW(dz *config.CrDZ) (string, error) {
	var operation string
	var payload *strings.Reader
	log.Infof("INIT putDnsNEW")
	printZONE(*&dz.CrZONE)
	url := dz.SpecZONE.Server + dz.SpecZONE.Url1 + dz.CrDNS.UID + dz.SpecZONE.Url2
	log.Infof("\n[%T] - URL  %s", url, url)
	if (dz.SpecZONE.Spaceguid != "") || (dz.SpecZONE.Organizationguid != "") {
		payload = strings.NewReader("{\n    \"service_id\": \"" + dz.Serviceid + "\",\n    \"organization_guid\": \"" + dz.Organizationguid + "\",\n    \"space_guid\": \"" + dz.Spaceguid + "\",\n    \"plan_id\": \"" + dz.Planid + "\",\n    \"context\": {\n        \"project_id\": \"" + dz.Hostname[:len(dz.Hostname)-1] + "\",\n        \"clusterid\": \"" + dz.SpecZONE.Clusterid + "\",\n        \"namespace\": \"" + dz.Namespace + "\",\n        \"platform\": \"" + dz.SpecZONE.Platform + "\"\n    },\n    \"parameters\": {\n        \"ex_var_zone\": \"" + dz.CrDNS.Zone + "\",\n        \"hostname\": \"" + dz.CrDNS.Hostname + dz.CrDNS.Zone + "\",\n        \"tipo\": \"" + dz.CrDNS.Type + "\",\n        \"ttl\": \"" + dz.CrDNS.TTL + "\",\n        \"reverso\": \"false\",\n        \"str_records\": \"" + dz.CrDNS.Records + "\",\n        \"descricao\": \"" + dz.CrDNS.Description + "\"\n    }\n}")
	} else {
		payload = strings.NewReader("{\n  \"service_id\": \"" + dz.Serviceid + "\",\n  \"plan_id\": \"" + dz.Planid + "\",\n  \"context\": {\n\t\"clusterid\": \"" + dz.SpecZONE.Clusterid + "\",\n\t\"namespace\": \"" + dz.Namespace + "\",\n\t\"platform\": \"" + dz.SpecZONE.Platform + "\"\n  },\n  \"parameters\": {\n  \t\"zone\": \"" + dz.CrDNS.Zone + "\",\n    \"hostname\": \"" + dz.CrDNS.Hostname + dz.CrDNS.Zone + "\",\n\t\"tipo\": \"" + dz.CrDNS.Type + "\",\n\t\"ttl\": \"" + dz.CrDNS.TTL + "\",\n\t\"records\": [\"" + dz.CrDNS.Records + "\"],\n\t\"descricao\": \"" + dz.CrDNS.Description + "\"\n  }\n}")
	}
	// payload := strings.NewReader("{\n  \"service_id\": \"" + dz.Serviceid + "\",\n  \"plan_id\": \"" + dz.Planid + "\",\n  \"context\": {\n\t\"clusterid\": \"" + dz.SpecZONE.Clusterid + "\",\n\t\"namespace\": \"" + dz.Namespace + "\",\n\t\"platform\": \"" + dz.SpecZONE.Platform + "\"\n  },\n  \"parameters\": {\n  \t\"zone\": \"" + dz.CrDNS.Zone + "\",\n    \"hostname\": \"" + dz.CrDNS.Hostname + dz.CrDNS.Zone + "\",\n\t\"tipo\": \"" + dz.CrDNS.Type + "\",\n\t\"ttl\": \"" + dz.CrDNS.TTL + "\",\n\t\"records\": [\"" + dz.CrDNS.Records + "\"],\n\t\"descricao\": \"" + dz.CrDNS.Description + "\"\n  }\n}")

	log.Infof("\n[%T] - payload  %s", payload, payload)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	req, _ := http.NewRequest("PUT", url, payload)
	req.Header.Set("X-Broker-API-Version", dz.BrokerVersion)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Broker-Api-Originating-Identity", dz.BrokerIdentity)
	req.Header.Set("Authorization", dz.AuthKey)
	req.Header.Set("User-Agent", "PostmanRuntime/7.11.0")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("cache-control", "no-cache")
	resp, err := client.Do(req)
	if err == nil {
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			HandleFuncError("ADD RESQUEST:", err)
		} else {
			HandleFuncSucess("ADD RESQUEST:", string(body))
			operation = string(body)
		}
	}
	log.Infof("operation %s", operation)
	log.Infof("err %s", err)
	return operation, err
}

func getAnnotationsNEW(dz *config.CrDZ) (string, map[string]interface{}) {
	var annotations string
	log.Infof("INIT getAnnotationsNEW")
	dynamicClient, _ := dynamic.NewForConfig(dz.Cfg)
	get, err := dynamicClient.Resource(config.VirtualServiceSERVICE).Namespace(dz.CrDNS.NsDNS).Get(context.TODO(), dz.CrDNS.NameDNS, metav1.GetOptions{})
	if err != nil {
		HandleFuncError("ADD GET:", err)
		return annotations, make(map[string]interface{})
	} else {
		HandleFuncSucess("ADD GET:", "string(get)")
	}
	getList, err := get.ToList()
	if err != nil {
		HandleFuncError("ADD GETLIST:", err)
		return annotations, make(map[string]interface{})
	} else {
		HandleFuncSucess("ADD GETLIST:", "string(getList)")
	}
	getMap := getList.UnstructuredContent()
	if getMap["metadata"].(map[string]interface{})["annotations"] != nil {
		annotations = getMap["metadata"].(map[string]interface{})["annotations"].(map[string]interface{})["kubectl.kubernetes.io/last-applied-configuration"].(string)
	}

	return annotations, getMap
}

func HandleFuncAddNEW(dz *config.CrDZ) {
	log.Infof("INIT HandleFuncAddNEW")
	printKIND(*dz)
	annotations, getMap := getAnnotationsNEW(dz)
	if annotations == "" {
		log.Infof("FIM\n")
		return
	}
	if (dz.CrDNS.SpecDNS.UID != "0000000-0000-0000-0000-0000") && (dz.CrDNS.SpecDNS.UID != "") {
		patchValueString(dz.CrDNS.SpecDNS.UID, "/metadata/uid", dz)
		dz.CrDNS.UID = dz.CrDNS.SpecDNS.UID
	}
	//- INICIO - Trecho responsavel por checar o operation
	//Caso o uid operation nao seja fornecido no deploy, sera considerado que e uma nova url, sera chamada a funcao putDns, recebendo de volta um uid.
	if dz.CrDNS.Operation == "0000000-0000-0000-0000-0000" || dz.CrDNS.Operation == "" {
		operation, err := putDnsNEW(dz)
		if match, _ := regexp.MatchString("[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}", operation); (match == false) && (err == nil) {
			patchValueStatus(*dz, "Failed", "Invalid operation number")
			return
		} else if err != nil {
			log.Infof("ADD ERROR: %v\n", err)
			patchValueStatus(*dz, "Failed", err.Error())
			HandleFuncError("ADD putDns", err)
			return
		} else {
			patchValueStatus(*dz, "Pending", "Checking ...")
		}

		if strings.Index(operation, "operation") > 0 {
			operation = operation[(strings.Index(operation, "operation") + 12):(strings.Index(operation, "operation") + 49)]
			patchValueStatus(*dz, "Pending", dz.CrDNS.Operation)
			// dz.CrDNS.Operation = operation
			operation = strings.Replace(operation, "\"", "", -1)
			operation = strings.Replace(operation, " ", "", -1)
			dz.CrDNS.Operation = operation
			patchCrDNS(dz)
		}
		//spec.Operation = operation
		//Checando se o uid operation esta correto.
		//funcao inutil, so serve para checar quando nao usava o status, usava o annotation
		if match, _ := regexp.MatchString("[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}", operation); match == true {
			//Alterando o uid do operation, setando no spec o valor recebido em putDns.
			patchValueStatus(*dz, "Pending", operation)
			//Quando o valor em operation foi passado como 0000000-0000-0000-0000-0000.
			if strings.Index(annotations, "0000000-0000-0000-0000-0000") > 0 {
				annotations, getMap = getAnnotationsNEW(dz)
				if annotations == "" {
					return
				} else {
					annotations = strings.Replace(annotations, "0000000-0000-0000-0000-0000", operation, -1)
					dz.CrDNS.Operation = strings.Replace(operation, "\"", "", -1)
				}

				//Quando o spec.Operation nao foi passado do deploy.
			} else {
				annotations, getMap = getAnnotationsNEW(dz)
				if annotations == "" {
					return
				}
				posTTL := strings.Index(annotations, "ttl")
				//posTTL menor que 0 é um indicio que não existe annotations.
				if posTTL > 0 {
					annotations = annotations[:(posTTL-1)] + "\"operation\":" + "\"" + operation + "\"" + annotations[(posTTL-2):]
				}
				//annotations = annotations[:(posTTL - 1)] + "\"operation\":" + "\"" + operation + "\"" + annotations[(posTTL - 2):]
				dz.CrDNS.Operation = strings.Replace(operation, "\"", "", -1)

				//patchDeploy(metadata, dynamicClient, annotations, getMap)
				//Em caso de erro.
				//-IMPLEMENTAR FUNCAO EM CASO DE ERRO.
				//UID ERRADO; CASO EXISTA O UID, CASO NAO EXISTA
				//ERRO NO BROKER
			}
		}
		patchDeployNEW(dz, annotations, getMap)
		//Quando e passado um uid operation correto.
	} else if match, _ := regexp.MatchString("[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}", dz.CrDNS.Operation); match == true {
		posTTL := strings.Index(annotations, "ttl")
		annotations = annotations[:(posTTL-1)] + "\"operation\":" + "\"" + dz.CrDNS.Operation + "\"" + annotations[(posTTL-2):]
		patchDeployNEW(dz, annotations, getMap)
		//Em caso de spec inconsistente.
	} else if dz.CrDNS.Operation == "" || dz.CrDNS.Status.State == "Running" {
		log.Infof("TESTEration\n")

	} else {
		log.Infof("Operation: %s\n", dz.CrDNS.Operation)
		//return
	}

	if match, _ := regexp.MatchString("[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}", dz.CrDNS.Operation); match == true {
		LoopGetProvision(dz)
		//var state, description string
		//for {
		//	state, description = getProvision(dz)
		//	if (state == "in progress") || (state == "PROVISIONING") {
		//		log.Infof("Operation: %s\n", dz.CrDNS.Operation)
		//		continue
		//
		//	} else if (state == "failed") || (state == "PROVISION_FAIL") {
		//		if description != "" {
		//			dz.CrDNS.State = "Failed"
		//			dz.CrDNS.Message = description
		//			log.Infof("State: %s", dz.CrDNS.State)
		//			log.Infof("Description: %s", dz.CrDNS.Message)
		//			patchValueStatus(*dz, dz.CrDNS.State, dz.CrDNS.Message)
		//			patchAnnotations(*dz)
		//			return
		//		} else {
		//			dz.CrDNS.State = "Failed"
		//			dz.CrDNS.Message = description
		//			patchValueStatus(*dz, dz.CrDNS.State, dz.CrDNS.Message)
		//			patchAnnotations(*dz)
		//			return
		//		}
		//
		//	} else if (state == "succeeded") || (state == "PROVISIONED") {
		//		dz.CrDNS.State = "Running"
		//		if description != "" {
		//			dz.CrDNS.Message = description
		//		} else {
		//			dz.CrDNS.Message = "provision job complete"
		//		}
		//		patchValueStatus(*dz, dz.CrDNS.State, dz.CrDNS.Message)
		//		log.Infof("State: %s", dz.CrDNS.State)
		//		log.Infof("Description: %s", dz.CrDNS.Message)
		//		patchAnnotations(*dz)
		//		return
		//	} else if description == "Job not found" {
		//		dz.CrDNS.State = "Failed"
		//		dz.CrDNS.Message = description
		//		patchValueStatus(*dz, dz.CrDNS.State, dz.CrDNS.Message)
		//		patchAnnotations(*dz)
		//		return
		//	}
		//}
	}
	return
}

func LoopGetProvision(dz *config.CrDZ) {
	var state, description string
	for {
		state, description = getProvision(dz)
		if (state == "in progress") || (state == "PROVISIONING") {
			log.Infof("Operation: %s\n", dz.CrDNS.Operation)
			continue

		} else if (state == "failed") || (state == "PROVISION_FAIL") {
			if description != "" {
				dz.CrDNS.State = "Failed"
				dz.CrDNS.Message = description
				log.Infof("State: %s", dz.CrDNS.State)
				log.Infof("Description: %s", dz.CrDNS.Message)
				patchValueStatus(*dz, dz.CrDNS.State, dz.CrDNS.Message)
				patchAnnotations(*dz)
				return
			} else {
				dz.CrDNS.State = "Failed"
				dz.CrDNS.Message = description
				patchValueStatus(*dz, dz.CrDNS.State, dz.CrDNS.Message)
				patchAnnotations(*dz)
				return
			}

		} else if (state == "succeeded") || (state == "PROVISIONED") {
			dz.CrDNS.State = "Running"
			//if description != "" {
			//	dz.CrDNS.Message = "provision job complete"
			//} else {
			//	dz.CrDNS.Message = "provision job complete"
			//}
			dz.CrDNS.Message = "provision job complete"
			patchValueStatus(*dz, dz.CrDNS.State, dz.CrDNS.Message)
			log.Infof("State: %s", dz.CrDNS.State)
			log.Infof("Description: %s", dz.CrDNS.Message)
			patchAnnotations(*dz)
			return
		} else if description == "Job not found" {
			dz.CrDNS.State = "Failed"
			dz.CrDNS.Message = description
			patchValueStatus(*dz, dz.CrDNS.State, dz.CrDNS.Message)
			patchAnnotations(*dz)
			return
		}
	}
}

//func HandleFuncAddV3(dz *config.CrDZ) {
//	log.Infof("INIT HandleFuncAddNEW")
//	printKIND(*dz)
//	annotations, getMap := getAnnotationsNEW(dz)
//	if annotations == "" {
//		log.Infof("FIM\n")
//		return
//	}
//	if (dz.CrDNS.State == "") && (dz.CrDNS.Message == "") {
//		//UID Recuperado do get
//		if (dz.CrDNS.SpecDNS.UID != "0000000-0000-0000-0000-0000") && (dz.CrDNS.SpecDNS.UID != "") {
//			log.Infof("TESTEration\n")
//		}
//	}
//}
