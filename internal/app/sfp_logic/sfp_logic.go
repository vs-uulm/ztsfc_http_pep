// Package sfp_logic handles the communication with the SFP Logic.
// (See https://github.com/vs-uulm/ztsfc_http_sfp_logic)
package sfp_logic

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"

	logger "github.com/vs-uulm/ztsfc_http_logger"
	"github.com/vs-uulm/ztsfc_http_pep/internal/app/config"
	"github.com/vs-uulm/ztsfc_http_pep/internal/app/metadata"
	"github.com/vs-uulm/ztsfc_http_pep/internal/app/proxies"
)

const (
	requestEndpoint = "/v1/sfp"
)

type sfpResponse struct {
	SFC []string `json:"sfc"`
	SFP []struct {
		Name    string `json:"name"`
		URL string `json:"url"`
	} `json:"sfp"`
}

// TransformSFCintoSFP creates a service function path out of a service
// function chain. Therefore, it communicates with the SFP Logic over HTTPS.
// The SFP Logic determines the order of the service functions inside the SFC
// and then returns the result, the SFP.
// The functions reads the SFC from cpm and also writes the SFP into this
// struct.
func TransformSFCIntoSFP(sysLogger *logger.Logger, cpm *metadata.CpMetadata) error {

	// send request to correct address and API endpoint
	req, err := http.NewRequest("GET", config.Config.SfpLogic.TargetSfplAddr+requestEndpoint, nil)
	if err != nil {
		return fmt.Errorf("sfp_logic: TransformSFCIntoSFP(): could not create new SFPL request: %v", err)
	}

	prepareSFPRequest(req, cpm)

    sysLogger.Debugf("sfp_log: TransformSFCIntoSFP(): Request to sfp logic: %v", req)

	resp, err := proxies.SfpLogicClientPool[rand.Int()%50].Do(req)
	if err != nil {
		return fmt.Errorf("sfp_logic: TransformSFCIntoSFP(): could not sent sfpl reqest: %v", err)
	}

	// Decode json body received from SFP logic
	var sfpRes sfpResponse

	err = json.NewDecoder(resp.Body).Decode(&sfpRes)
	if err != nil {
		return fmt.Errorf("sfp_logic: TransformSFCIntoSFP(): could not parse json answer from sfp logic: %w", err)
	}

    sysLogger.Debugf("sfp_logic: TransformSFCIntoSFP(): response from SFP logic: %v", sfpRes)

	for _, sf := range sfpRes.SFP {
		cpm.SFP = append(cpm.SFP, struct {
			Name    string
			URL string
		}{
            Name: sf.Name,
            URL: sf.URL,
        })
	}

	return nil
}

func prepareSFPRequest(req *http.Request, cpm *metadata.CpMetadata) {

	// send SFC as a query parameter
	q := req.URL.Query()
	for _, sf := range cpm.SFC {
		q.Add("sfc", sf.Name)
	}
	req.URL.RawQuery = q.Encode()

}
