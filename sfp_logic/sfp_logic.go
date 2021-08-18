package authorization

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"

	env "local.com/leobrada/ztsfc_http_pep/env"
	metadata "local.com/leobrada/ztsfc_http_pep/metadata"
	proxies "local.com/leobrada/ztsfc_http_pep/proxies"
)

const (
	// @author:marie
	// Last part of the endpoint's request URI of the PDP API
	requestEndpoint = "/v1/authorization"
)

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
	err = json.NewDecoder(resp.Body).Decode(&cpm.SFP)
	if err != nil {
		return fmt.Errorf("Could not parse json answer from sfp logic: %v", err)
	}

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
