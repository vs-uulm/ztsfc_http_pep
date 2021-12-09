// Package authorization handles the communication with the PEP.
// (See https://github.com/vs-uulm/ztsfc_http_pdp)
package authorization

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"strconv"

	"github.com/vs-uulm/ztsfc_http_pep/internal/app/config"
	"github.com/vs-uulm/ztsfc_http_pep/internal/app/logwriter"
	"github.com/vs-uulm/ztsfc_http_pep/internal/app/metadata"
	"github.com/vs-uulm/ztsfc_http_pep/internal/app/proxies"
)

const (
	// @author:marie
	// Last part of the endpoint's request URI of the PDP API
	requestEndpoint = "/v1/authorization"
)

type authResponse struct {
	Allow bool     `json:"allow"`
	SFC   []string `json:"sfc"`
}

var logWriter *logwriter.LogWriter

// SetLogWriter() sets the logWriter to send the log messages to
func SetLogWriter(lw *logwriter.LogWriter) {
	logWriter = lw
}

// PerformAuthorization decides for a specific client request, wether it should
// allowed and if so, under which conditions. Therefore, it communicates with
// the PDP over HTTPS. The PDP makes the authorization decision and returns it
// together with an SFC.
// The functions writes some meta data about the request into cpm and also
// stores the answers of the PDP in here.
func PerformAuthorization(clientReq *http.Request, cpm *metadata.CpMetadata) error {
	collectAttributes(clientReq, cpm)

	// send request to correct address and API endpoint
	// @author:marie
	req, err := http.NewRequest("GET", config.Config.Pdp.TargetPdpAddr+requestEndpoint, nil)
	if err != nil { // @author:marie catch error
		return err
	}

	prepareAuthRequest(req, cpm)
	resp, err := proxies.PdpClientPool[rand.Int()%50].Do(req)
	if err != nil {
		return fmt.Errorf("error when sending to pdp: %v", err)
	}

	// @author:marie
	// Decode json body received from PDP
	var authRes authResponse
	err = json.NewDecoder(resp.Body).Decode(&authRes)
	if err != nil {
		return fmt.Errorf("could not parse json answer from PDP: %v", err)
	}

	if logWriter != nil {
		logWriter.Debugf("Response from PDP: %v", authRes)
	}
	cpm.SFC = authRes.SFC
	cpm.AuthDecision = authRes.Allow

	return nil
}

func prepareAuthRequest(req *http.Request, cpm *metadata.CpMetadata) {
	// @author:marie
	// send parameters as a query parameter instead of custom header
	q := req.URL.Query()
	q.Set("user", cpm.User)
	q.Set("pwAuthenticated", strconv.FormatBool(cpm.PwAuthenticated))
	q.Set("certAuthenticated", strconv.FormatBool(cpm.CertAuthenticated))
	q.Set("resource", cpm.Resource)
	q.Set("action", cpm.Action)
	q.Set("device", cpm.Device)
	q.Set("requestToday", cpm.RequestToday)
	q.Set("failedToday", cpm.FailedToday)
	q.Set("location", cpm.Location)
	req.URL.RawQuery = q.Encode()
}

func collectAttributes(req *http.Request, cpm *metadata.CpMetadata) {
	collectResource(req, cpm)
	collectAction(req, cpm)
	collectDevice(req, cpm)
	collectRequestToday(req, cpm)
	collectFailedToday(req, cpm)
	collectLocation(req, cpm)
}

func collectResource(req *http.Request, cpm *metadata.CpMetadata) {
	cpm.Resource = req.Host
}

func collectAction(req *http.Request, cpm *metadata.CpMetadata) {
	cpm.Action = req.Method
}

func collectDevice(req *http.Request, cpm *metadata.CpMetadata) {
	cpm.Device = req.Header.Get("device")
}

func collectRequestToday(req *http.Request, cpm *metadata.CpMetadata) {
	cpm.RequestToday = req.Header.Get("requestToday")
}

func collectFailedToday(req *http.Request, cpm *metadata.CpMetadata) {
	cpm.FailedToday = req.Header.Get("failedToday")
}

func collectLocation(req *http.Request, cpm *metadata.CpMetadata) {
	cpm.Location = req.Header.Get("location")
}
