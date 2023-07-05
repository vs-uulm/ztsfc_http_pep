// Package authorization handles the communication with the PEP.
// (See https://github.com/vs-uulm/ztsfc_http_pdp)
package authorization

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"strconv"

	logger "github.com/vs-uulm/ztsfc_http_logger"
	"github.com/vs-uulm/ztsfc_http_pep/internal/app/config"
	"github.com/vs-uulm/ztsfc_http_pep/internal/app/metadata"
	"github.com/vs-uulm/ztsfc_http_pep/internal/app/proxies"
	//"github.com/mileusna/useragent"
)

const (
	// Last part of the endpoint's request URI of the PDP API
	requestEndpoint = "/v1/authorization"
)

// Sends an auhtorization request to the PEP for to the passed client resource access request
// Step 1: Extracts all needed authorization metadata from the passed client request
func PerformAuthorization(sysLogger *logger.Logger, clientReq *http.Request, cpm *metadata.CpMetadata) error {
	// send request to correct address and API endpoint
	authoReq, err := http.NewRequest("GET", config.Config.Pdp.TargetPdpAddr+requestEndpoint, nil)
	if err != nil {
		return fmt.Errorf("unable to create authorization request for PDP: %w", err)
	}

	sysLogger.Debugf("%s", cpm.String())

	prepareAuthRequest(authoReq, cpm)
	pdpResp, err := proxies.PdpClientPool[rand.Int()%50].Do(authoReq)
	if err != nil {
		return fmt.Errorf("unable to send to PDP: %w", err)
	}

	// Decode json body received from PDP (pdpResp)
	var authoResp metadata.AuthoResponse
	err = json.NewDecoder(pdpResp.Body).Decode(&authoResp)
	if err != nil {
		return fmt.Errorf("unable to parse json answer from PDP: %w", err)
	}

	if sysLogger != nil {
		sysLogger.Debugf("Response from PDP: %v", authoResp)
	}
	cpm.SFC = authoResp.SFC
	cpm.AuthDecision = authoResp.Allow
	cpm.AuthReason = authoResp.Reason

	return nil
}

func prepareAuthRequest(authoReq *http.Request, cpm *metadata.CpMetadata) {
	// send parameters as a query parameter instead of custom header
	q := authoReq.URL.Query()
	q.Set("user", cpm.User)
	q.Set("pwAuthenticated", strconv.FormatBool(cpm.PwAuthenticated))
	q.Set("certAuthenticated", strconv.FormatBool(cpm.CertAuthenticated))
	q.Set("resource", cpm.Resource)
	q.Set("action", cpm.Action)
	q.Set("device", cpm.Device)
	//q.Set("requestToday", cpm.RequestToday)
	//q.Set("failedToday", cpm.FailedToday)
	q.Set("location", cpm.Location)
	q.Set("connectionSecurity", cpm.ConnectionSecurity)
	q.Set("userAgent", cpm.UserAgent)
	q.Set("requestProtocol", strconv.FormatFloat(cpm.RequestProtocol, 'f', -1, 32))
	authoReq.URL.RawQuery = q.Encode()
}
