// Package metadata provides a struct for storing meta data about requests
// during processing inside the PEP.
package metadata

type AuthoResponse struct {
        Allow bool     `json:"allow"`
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
