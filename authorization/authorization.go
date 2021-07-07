package authorization

import (
	"fmt"
	"math/rand"
	"net/http"
	"os"

	//   "crypto/tls"
	"strconv"
	//"strings"
	env "local.com/leobrada/ztsfc_http_pep/env"
	metadata "local.com/leobrada/ztsfc_http_pep/metadata"
	proxies "local.com/leobrada/ztsfc_http_pep/proxies"
	//    bauth "local.com/leobrada/ztsfc_http_pep/basic_auth"
)

//func PerformAuthorization(req *http.Request, cpm *metadata.Cp_metadata) (allow bool, sfc []string) {
func PerformAuthorization(req *http.Request, cpm *metadata.Cp_metadata) {
	collectAttributes(req, cpm)

	autho_req, err := http.NewRequest("GET", env.Config.Pdp.Target_pdp_addr, nil)
	// TODO: Catch error
	prepareAuthRequest(autho_req, cpm)
	response, err := proxies.Pdp_client_pool[rand.Int()%50].Do(autho_req)

	if err != nil {
		fmt.Printf("Error when sending to pdp (2): %v\n", err)
		fmt.Fprintf(os.Stderr, "Error when sending to pdp (2): %v\n", err)
	}

	cpm.SFC = response.Header.Get("sfc")
	cpm.Auth_decision, _ = strconv.ParseBool(response.Header.Get("allow"))

	// if response.Header.Get("allow") == "yes" {
	//     allow = true
	// } else {
	//     allow = false
	// }

	// return allow, sfc
}

func prepareAuthRequest(autho_req *http.Request, cpm *metadata.Cp_metadata) {
	autho_req.Header.Set("user", cpm.User)
	autho_req.Header.Set("pwAuthenticated", strconv.FormatBool(cpm.Pw_authenticated))
	autho_req.Header.Set("certAuthenticated", strconv.FormatBool(cpm.Cert_authenticated))
	autho_req.Header.Set("resource", cpm.Resource)
	autho_req.Header.Set("action", cpm.Action)
	autho_req.Header.Set("device", cpm.Device)
	autho_req.Header.Set("requestToday", cpm.RequestToday)
	autho_req.Header.Set("failedToday", cpm.FailedToday)
	autho_req.Header.Set("location", cpm.Location)
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
