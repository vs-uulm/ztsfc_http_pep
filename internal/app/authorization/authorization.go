// Package authorization handles the communication with the PEP.
// (See https://github.com/vs-uulm/ztsfc_http_pdp)
package authorization

import (
	"encoding/json"
	"fmt"
	"math/rand"
    "net"
	"net/http"
	"strconv"
    "strings"

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
	collectAttributes(clientReq, cpm)

	// send request to correct address and API endpoint
	authoReq, err := http.NewRequest("GET", config.Config.Pdp.TargetPdpAddr+requestEndpoint, nil)
	if err != nil {
		return fmt.Errorf("unable to create authorization request for PDP: %w", err)
	}

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
	authoReq.URL.RawQuery = q.Encode()
}

func collectAttributes(clientReq *http.Request, cpm *metadata.CpMetadata) {
	collectResource(clientReq, cpm)
	collectAction(clientReq, cpm)
	collectDevice(clientReq, cpm)
	//collectRequestToday(clientReq, cpm)
	//collectFailedToday(clientReq, cpm)
	collectLocation(clientReq, cpm)
}

func collectResource(clientReq *http.Request, cpm *metadata.CpMetadata) {
	cpm.Resource = clientReq.Host
}

func collectAction(clientReq *http.Request, cpm *metadata.CpMetadata) {
	cpm.Action = strings.ToLower(clientReq.Method)
}

func collectDevice(clientReq *http.Request, cpm *metadata.CpMetadata) {
    if len(clientReq.TLS.PeerCertificates) == 0 {
        cpm.Device = ""
        return
    }
    clientCert := clientReq.TLS.PeerCertificates[0]
    if clientCert == nil {
        cpm.Device = ""
        return
    }
    cpm.Device = clientCert.Subject.CommonName
    //ua := ua.Parse(clientReq.Header.Get("User-Agent"))
	//cpm.Device = ua.Device + ";" + ua.Name + ";" + ua.OS + ";" + ua.OSVersion
}

func collectRequestToday(clientReq *http.Request, cpm *metadata.CpMetadata) {
	cpm.RequestToday = clientReq.Header.Get("clientRequestToday")
}

func collectFailedToday(clientReq *http.Request, cpm *metadata.CpMetadata) {
	cpm.FailedToday = clientReq.Header.Get("failedToday")
}

// TODO: Harden this function
func collectLocation(clientReq *http.Request, cpm *metadata.CpMetadata) error {
    host, _, err := net.SplitHostPort(clientReq.RemoteAddr)
    if err != nil {
        return fmt.Errorf("authorization: collectLocation(): provided req.RemoteAddr not in valid host:port form %w", err)
    }

	cpm.Location = host
    return nil
}
