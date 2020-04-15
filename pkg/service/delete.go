package service

import (
	"crypto/tls"
	"dnsservice-controller/pkg/config"
	"io/ioutil"
	"net/http"

	log "github.com/sirupsen/logrus"
)

func HandleFuncDeleteNEW(dz config.CrDZ) {
	dryRUN := false
	var url string
	if (dz.SpecZONE.Spaceguid != "") || (dz.SpecZONE.Organizationguid != "") || (dz.SpecDNS.Operation == "") {
		url = dz.SpecZONE.Server + dz.SpecZONE.Url1 + dz.SpecDNS.UID + dz.SpecZONE.Url2 + "&plan_id=" + dz.SpecZONE.Planid + "&service_id=" + dz.SpecZONE.Serviceid
	} else {
		url = dz.SpecZONE.Server + dz.SpecZONE.Url1 + dz.SpecDNS.UID + dz.SpecZONE.Url2 + "&plan_id=" + dz.SpecZONE.Planid + "&service_id=" + dz.SpecZONE.Serviceid + "&operation=" + dz.SpecDNS.Operation
	}
	log.Infof("\n[%T] - URL  %s", url, url)
	if dryRUN == false {
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
		client := &http.Client{Transport: tr}
		req, err := http.NewRequest("DELETE", url, nil)
		if err != nil {
			HandleFuncError("SERVER", err)
			return
		} else {
			HandleFuncSucess("SERVER", "string(req)")
		}

		req.Header.Set("X-Broker-API-Version", dz.SpecZONE.BrokerVersion)
		req.Header.Set("X-Broker-Api-Originating-Identity", dz.SpecZONE.BrokerIdentity)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", dz.SpecZONE.AuthKey)

		resp, err := client.Do(req)
		if err == nil {
			defer resp.Body.Close()
			body, err := ioutil.ReadAll(resp.Body)
			if err != nil {
				HandleFuncError("REQUEST", err)
			} else {
				HandleFuncSucess("REQUEST", string(body))
			}
		} else {
			HandleFuncError("SERVER", err)
		}
	}
}
