// Package metadata provides a struct for storing meta data about requests
// during processing inside the PEP.
package metadata

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
)

type AuthoResponse struct {
	Allow  bool   `json:"allow"`
	Reason string `json:"reason"`
	SFC    []Sf   `json:"sfc"`
}

type Sf struct {
	Name string `json:"name"`
	Md   string `json:"md"`
}

// The struct CpMetadata is for storing several meta data for a client
// request. The struct can be passed across the PEP, such that several
// components can collect different information in here.
type CpMetadata struct {
	AuthDecision         bool
	AuthReason           string
	User                 string
	PwAuthenticated      bool
	PasskeyAuthenticated bool
	CertAuthenticated    bool
	Resource             string
	Action               string
	Device               string
	Location             string
	ConnectionSecurity   string
	UserAgent            string
	RequestProtocol      float64
	SFC                  []Sf
	SFP                  []struct {
		Name string
		URL  string
	}
}

// ClearMetadata resets all values from a CpMetadata instance to their
// zero values.
func (cpm *CpMetadata) ClearMetadata() {
	cpm.AuthDecision = false
	cpm.AuthReason = ""
	cpm.User = ""
	cpm.PwAuthenticated = false
	cpm.PasskeyAuthenticated = false
	cpm.CertAuthenticated = false
	cpm.Resource = ""
	cpm.Action = ""
	cpm.Device = ""
	cpm.Location = ""
	cpm.ConnectionSecurity = ""
	cpm.UserAgent = ""
	cpm.RequestProtocol = 0.0
	cpm.SFC = []Sf{}
	cpm.SFP = []struct {
		Name string
		URL  string
	}{}
}

func (cpm *CpMetadata) String() string {
	header := "Metadata: "
	authDecision := fmt.Sprintf("AuthDecision=%t, ", cpm.AuthDecision)
	authReason := fmt.Sprintf("AuthReason=%s, ", cpm.AuthReason)
	user := fmt.Sprintf("User=%s, ", cpm.User)
	pwAuthenticated := fmt.Sprintf("PwAuthenticated=%t, ", cpm.PwAuthenticated)
	passkeyAuthenticated := fmt.Sprintf("PasskeyAuthenticaed=%t, ", cpm.PasskeyAuthenticated)
	certAuthenticated := fmt.Sprintf("CertAuthenticated=%t, ", cpm.CertAuthenticated)
	resource := fmt.Sprintf("Resource=%s, ", cpm.Resource)
	action := fmt.Sprintf("Action=%s, ", cpm.Action)
	device := fmt.Sprintf("Device=%s, ", cpm.Device)
	location := fmt.Sprintf("Location=%s, ", cpm.Location)
	connectionSecurity := fmt.Sprintf("ConnectionSecurity=%s, ", cpm.ConnectionSecurity)
	userAgent := fmt.Sprintf("UserAgent=%s", cpm.UserAgent)
	requestProtocol := fmt.Sprintf("RequestProtocol=%f", cpm.RequestProtocol)
	mdString := header + authDecision + authReason + user + pwAuthenticated + passkeyAuthenticated + certAuthenticated +
		resource + action + device + location + connectionSecurity + userAgent + requestProtocol

	return mdString
}

func CollectMetadata(clientReq *http.Request, cpm *CpMetadata) {
	// User is set by BasicAuth()
	// PwAuthenticated is set by BasicAuth()
	// PasskeyAuthenticated is set by BasicAuth()
	// CertAuthenticated is set by BasicAuth()
	collectResource(clientReq, cpm)
	collectAction(clientReq, cpm)
	collectDevice(clientReq, cpm)
	//collectRequestToday(clientReq, cpm)
	//collectFailedToday(clientReq, cpm)
	collectLocation(clientReq, cpm)
	collectConnectionSecurity(clientReq, cpm)
	collectUserAgent(clientReq, cpm)
	collectRequestProtocol(clientReq, cpm)
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
	// "github.com/mileusna/useragent"
	// ua := ua.Parse(clientReq.Header.Get("User-Agent"))
	// cpm.Device = ua.Device + ";" + ua.Name + ";" + ua.OS + ";" + ua.OSVersion
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

func collectConnectionSecurity(clientReq *http.Request, cpm *CpMetadata) {
	cpm.ConnectionSecurity = tls.CipherSuiteName(clientReq.TLS.CipherSuite)
}

func collectUserAgent(clientReq *http.Request, cpm *CpMetadata) {
	cpm.UserAgent = clientReq.Header.Get("User-Agent")
}

func collectRequestProtocol(clientReq *http.Request, cpm *CpMetadata) {
	cpm.RequestProtocol = float64(clientReq.ProtoMajor) + float64(clientReq.ProtoMinor)/10
}
