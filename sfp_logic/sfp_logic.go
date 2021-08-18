package authorization

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"

	env "local.com/leobrada/ztsfc_http_pep/env"
	"local.com/leobrada/ztsfc_http_pep/logwriter"
	metadata "local.com/leobrada/ztsfc_http_pep/metadata"
	proxies "local.com/leobrada/ztsfc_http_pep/proxies"
)

const (
	// @author:marie
	// Last part of the endpoint's request URI of the PDP API
	requestEndpoint = "/v1/sfp"
)

type sfpResponse struct {
	SFP []string `json:"sfp"`
}

func TransformSFCintoSFP(cpm *metadata.Cp_metadata) error {

	sfp_req, err := http.NewRequest("GET", env.Config.Sfp_logic.Target_sfpl_addr+requestEndpoint, nil)
	if err != nil {
		return err
	}
	prepareSFPRequest(sfp_req, cpm)

	resp, err := proxies.Sfp_logic_client_pool[rand.Int()%50].Do(sfp_req)
	if err != nil {
		return err
	}

	// @author:marie
	// Decode json body received from SFP logic
	var sfpRes sfpResponse
	err = json.NewDecoder(resp.Body).Decode(&sfpRes)
	if err != nil {
		return fmt.Errorf("Could not parse json answer from sfp logic: %v", err)
	}

	logwriter.LW.Logger.Debugf("Response from PDP: %v", sfpRes)
	cpm.SFP = sfpRes.SFP

	return nil
}

func prepareSFPRequest(req *http.Request, cpm *metadata.Cp_metadata) {

	// @author:marie
	// send SFC as a query parameter instead of custom header
	for _, sf := range cpm.SFC {
		req.URL.Query().Add("sf", sf)
	}
	// req.Header.Set("sfc", cpm.SFC)

}
