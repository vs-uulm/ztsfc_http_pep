// Package sfp_logic handles the communication with the SFP Logic.
// (See https://github.com/vs-uulm/ztsfc_http_sfp_logic)
package sfp_logic

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"

	"github.com/vs-uulm/ztsfc_http_pep/internal/app/config"
	"github.com/vs-uulm/ztsfc_http_pep/internal/app/logwriter"
	"github.com/vs-uulm/ztsfc_http_pep/internal/app/metadata"
	"github.com/vs-uulm/ztsfc_http_pep/internal/app/proxies"
)

const (
	// @author:marie
	// Last part of the endpoint's request URI of the PDP API
	requestEndpoint = "/v1/sfp"
)

type sfpResponse struct {
	SFC []string `json:"sfc"`
	SFP []struct {
		Name    string `json:"name"`
		Address string `json:"address"`
	} `json:"sfp"`
}

var logWriter *logwriter.LogWriter

// SetLogWriter() sets the logWriter to send the log messages to
func SetLogWriter(lw *logwriter.LogWriter) {
	logWriter = lw
}

// TransformSFCintoSFP creates a service function path out of a service
// function chain. Therefore, it communicates with the SFP Logic over HTTPS.
// The SFP Logic determines the order of the service functions inside the SFC
// and then returns the result, the SFP.
// The functions reads the SFC from cpm and also writes the SFP into this
// struct.
func TransformSFCintoSFP(cpm *metadata.CpMetadata) error {

	// send request to correct address and API endpoint
	// @author:marie
	req, err := http.NewRequest("GET", config.Config.SfpLogic.TargetSfplAddr+requestEndpoint, nil)
	if err != nil { // @author:marie catch error
		return err
	}
	prepareSFPRequest(req, cpm)

	if logWriter != nil {
		logWriter.Debugf("Request to sfp logic: %v", req)
	}

	resp, err := proxies.SfpLogicClientPool[rand.Int()%50].Do(req)
	if err != nil {
		return err
	}

	// @author:marie
	// Decode json body received from SFP logic
	var sfpRes sfpResponse

	err = json.NewDecoder(resp.Body).Decode(&sfpRes)
	if err != nil {
		return fmt.Errorf("could not parse json answer from sfp logic: %v", err)
	}

	if logWriter != nil {
		logWriter.Debugf("Response from SFP logic: %v", sfpRes)
	}

	for _, sf := range sfpRes.SFP {
		cpm.SFP = append(cpm.SFP, struct {
			Name    string
			Address string
		}{Name: sf.Name, Address: sf.Address})
	}

	return nil
}

func prepareSFPRequest(req *http.Request, cpm *metadata.CpMetadata) {

	// @author:marie
	// send SFC as a query parameter instead of custom header
	q := req.URL.Query()
	for _, sf := range cpm.SFC {
		q.Add("sf", sf)
	}
	req.URL.RawQuery = q.Encode()

}
