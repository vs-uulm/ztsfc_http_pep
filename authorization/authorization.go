package authorization

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"strconv"

	"local.com/leobrada/ztsfc_http_pep/env"
	metadata "local.com/leobrada/ztsfc_http_pep/metadata"
	proxies "local.com/leobrada/ztsfc_http_pep/proxies"
)

const (
	// @author:marie
	// Last part of the endpoint's request URI of the PDP API
	requestEndpoint = "/v1/authorization"
)

type authResponse struct {
	allow bool
	sfc   []string
}

func PerformAuthorization(req *http.Request, cpm *metadata.Cp_metadata) error {
	collectAttributes(req, cpm)

	autho_req, err := http.NewRequest("GET", env.Config.Pdp.Target_pdp_addr+requestEndpoint, nil)
	if err != nil {
		return err
	}

	prepareAuthRequest(autho_req, cpm)
	resp, err := proxies.Pdp_client_pool[rand.Int()%50].Do(autho_req)
	if err != nil {
		return err
		//fmt.Fprintf(os.Stderr, "Error when sending to pdp (2): %v\n", err)
	}

	// @author:marie
	// Decode json body received from PDP
	var authRes authResponse
	err = json.NewDecoder(resp.Body).Decode(&authRes)
	if err != nil {
		return fmt.Errorf("Could not parse json answer from PDP: %v", err)
	}

	cpm.SFC = authRes.sfc
	cpm.Auth_decision = authRes.allow

	return nil
}

func prepareAuthRequest(req *http.Request, cpm *metadata.Cp_metadata) {
	// @author:marie
	// send parameters as a query parameter instead of custom header
	req.URL.Query().Set("user", cpm.User)
	req.URL.Query().Set("pwAuthenticated", strconv.FormatBool(cpm.Pw_authenticated))
	req.URL.Query().Set("certAuthenticated", strconv.FormatBool(cpm.Cert_authenticated))
	req.URL.Query().Set("resource", cpm.Resource)
	req.URL.Query().Set("action", cpm.Action)
	req.URL.Query().Set("device", cpm.Device)
	req.URL.Query().Set("requestToday", cpm.RequestToday)
	req.URL.Query().Set("failedToday", cpm.FailedToday)
	req.URL.Query().Set("location", cpm.Location)
}

func collectAttributes(req *http.Request, cpm *metadata.Cp_metadata) {
	collectResource(req, cpm)
	collectAction(req, cpm)
	collectDevice(req, cpm)
	collectRequestToday(req, cpm)
	collectFailedToday(req, cpm)
	collectLocation(req, cpm)
}

func collectResource(req *http.Request, cpm *metadata.Cp_metadata) {
	cpm.Resource = req.Host
}

func collectAction(req *http.Request, cpm *metadata.Cp_metadata) {
	cpm.Action = req.Method
}

func collectDevice(req *http.Request, cpm *metadata.Cp_metadata) {
	cpm.Device = req.Header.Get("device")
}

func collectRequestToday(req *http.Request, cpm *metadata.Cp_metadata) {
	cpm.RequestToday = req.Header.Get("requestToday")
}

func collectFailedToday(req *http.Request, cpm *metadata.Cp_metadata) {
	cpm.FailedToday = req.Header.Get("failedToday")
}

func collectLocation(req *http.Request, cpm *metadata.Cp_metadata) {
	cpm.Location = req.Header.Get("location")
}
