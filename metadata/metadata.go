// Package metadata provides a struct for storing meta data about requests
// during processing inside the PEP.
package metadata

// The struct Cp_metadata is for storing several meta data for a client
// request. The struct can be passed across the PEP, such that several
// components can collect different information in here.
type Cp_metadata struct {
	Auth_decision      bool
	User               string
	Pw_authenticated   bool
	Cert_authenticated bool
	Resource           string
	Action             string
	Device             string
	RequestToday       string
	FailedToday        string
	Location           string
	SFC                []string
	SFP                []string
}

// ClearMetadata resets all values from a CP_metadata instance to their
// zero values.
func (cpm *Cp_metadata) ClearMetadata() {
	cpm.Auth_decision = false
	cpm.User = ""
	cpm.Pw_authenticated = false
	cpm.Cert_authenticated = false
	cpm.Resource = ""
	cpm.Action = ""
	cpm.Device = ""
	cpm.RequestToday = ""
	cpm.FailedToday = ""
	cpm.Location = ""
	cpm.SFC = []string{}
	cpm.SFP = []string{}
}
