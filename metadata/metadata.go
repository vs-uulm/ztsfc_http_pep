// Package metadata provides a struct for storing meta data about requests
// during processing inside the PEP.
package metadata

// The struct CpMetadata is for storing several meta data for a client
// request. The struct can be passed across the PEP, such that several
// components can collect different information in here.
type CpMetadata struct {
	AuthDecision      bool
	User              string
	PwAuthenticated   bool
	CertAuthenticated bool
	Resource          string
	Action            string
	Device            string
	RequestToday      string
	FailedToday       string
	Location          string
	SFC               []string
	SFP               []struct {
		Name    string
		Address string
	}
}

// ClearMetadata resets all values from a CP_metadata instance to their
// zero values.
func (cpm *CpMetadata) ClearMetadata() {
	cpm.AuthDecision = false
	cpm.User = ""
	cpm.PwAuthenticated = false
	cpm.CertAuthenticated = false
	cpm.Resource = ""
	cpm.Action = ""
	cpm.Device = ""
	cpm.RequestToday = ""
	cpm.FailedToday = ""
	cpm.Location = ""
	cpm.SFC = []string{}
	cpm.SFP = []struct {
		Name    string
		Address string
	}{}
}
