package authorization

import (
	"math/rand"
	"net/http"

	env "local.com/leobrada/ztsfc_http_pep/env"
	metadata "local.com/leobrada/ztsfc_http_pep/metadata"
	proxies "local.com/leobrada/ztsfc_http_pep/proxies"
)

func TransformSFCintoSFP(cpm *metadata.Cp_metadata) error {

	//    fmt.Printf("SFC BEFORE SENT TO SFP LOPGIC: %s\n", cpm.SFC)

	sfp_req, err := http.NewRequest("GET", env.Config.Sfp_logic.Target_sfpl_addr, nil)
	if err != nil {
		return err
	}
	prepareSFPRequest(sfp_req, cpm)

	response, err := proxies.Sfp_logic_client_pool[rand.Int()%50].Do(sfp_req)
	if err != nil {
		return err
		//fmt.Fprintf(os.Stderr, "Error when sending to sfp logic (2): %v\n", err)
	}
	cpm.SFP = response.Header.Get("sfp")

	return nil
}

func prepareSFPRequest(req *http.Request, cpm *metadata.Cp_metadata) {
	//    fmt.Printf("cpm.SFC value: %s\n", cpm.SFC)
	req.Header.Set("sfc", cpm.SFC)
	//    fmt.Printf("HTTP Header: %s\n", req.Header.Get("sfc"))
	//    fmt.Fprintf(os.Stderr, "HTTP Header: %s\n", req.Header.Get("sfc"))
}
