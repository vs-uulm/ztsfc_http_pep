// Package metadata provides a struct for storing meta data about requests
// during processing inside the PEP.
package metadata

import (
	"net"
	"net/http"
	"strings"
	"fmt"
)

type AuthoResponse struct {
        Allow bool     `json:"allow"`
        Reason string `json:"reason"`
        SFC   []Sf `json:"sfc"`
}

type Sf struct {
    Name string `json:"name"`
    Md string `json:"md"`
}

// The struct CpMetadata is for storing several meta data for a client
// request. The struct can be passed across the PEP, such that several
// components can collect different information in here.
type CpMetadata struct {
	AuthDecision      bool
    AuthReason string
	User              string
	PwAuthenticated   bool
	CertAuthenticated bool
	Resource          string
	Action            string
	Device            string
	RequestToday      string
	FailedToday       string
	Location          string
	SFC               []Sf
	SFP               []struct {
		Name    string
		URL string
	}
}

// ClearMetadata resets all values from a CpMetadata instance to their
// zero values.
func (cpm *CpMetadata) ClearMetadata() {
	cpm.AuthDecision = false
	cpm.AuthReason = ""
	cpm.User = ""
	cpm.PwAuthenticated = false
	cpm.CertAuthenticated = false
	cpm.Resource = ""
	cpm.Action = ""
	cpm.Device = ""
	cpm.RequestToday = ""
	cpm.FailedToday = ""
	cpm.Location = ""
	cpm.SFC = []Sf{}
	cpm.SFP = []struct {
		Name    string
		URL string
	}{}
}

func (cpm *CpMetadata) String() string {
	header := "Metadata: "
	authDecision := fmt.Sprintf("AuthDecision=%t, ", cpm.AuthDecision)
	authReason := fmt.Sprintf("AuthReason=%s, ", cpm.AuthReason)
	user := fmt.Sprintf("User=%s, ", cpm.User)
	pwAuthenticated := fmt.Sprintf("PwAuthenticated=%t, ", cpm.PwAuthenticated)
	certAuthenticated := fmt.Sprintf("CertAuthenticated=%t, ", cpm.CertAuthenticated)
	resource := fmt.Sprintf("Resource=%s, ", cpm.Resource)
	action := fmt.Sprintf("Action=%s, ", cpm.Action)
	device := fmt.Sprintf("Device=%s, ", cpm.Device)
	requestToday := fmt.Sprintf("RequestToday=%s, ", cpm.RequestToday)
	failedToday := fmt.Sprintf("FailedToday=%s, ", cpm.FailedToday)
	location := fmt.Sprintf("Location=%s, ", cpm.Location)
	mdString := header + authDecision + authReason + user + pwAuthenticated + certAuthenticated +
		resource + action + device + requestToday + failedToday + location

	return mdString
}

func CollectMetadata(clientReq *http.Request, cpm *CpMetadata) {
    // pwAuthenticated & certAuthenticated are already set by BasicAuth()
	collectResource(clientReq, cpm)
	collectAction(clientReq, cpm)
	collectDevice(clientReq, cpm)
	//collectRequestToday(clientReq, cpm)
	//collectFailedToday(clientReq, cpm)
	collectLocation(clientReq, cpm)
}

func collectResource(clientReq *http.Request, cpm *CpMetadata) {
	cpm.Resource = clientReq.Host
}

func collectAction(clientReq *http.Request, cpm *CpMetadata) {
	cpm.Action = strings.ToLower(clientReq.Method)
}

func collectDevice(clientReq *http.Request, cpm *CpMetadata) {
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

func collectRequestToday(clientReq *http.Request, cpm *CpMetadata) {
	cpm.RequestToday = clientReq.Header.Get("clientRequestToday")
}

func collectFailedToday(clientReq *http.Request, cpm *CpMetadata) {
	cpm.FailedToday = clientReq.Header.Get("failedToday")
}

// TODO: Harden this function
func collectLocation(clientReq *http.Request, cpm *CpMetadata) error {
    host, _, err := net.SplitHostPort(clientReq.RemoteAddr)
    if err != nil {
        return fmt.Errorf("authorization: collectLocation(): provided req.RemoteAddr not in valid host:port form %w", err)
    }

	cpm.Location = host
    return nil
}