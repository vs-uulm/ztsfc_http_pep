package authorization

import (
    "os"
    "fmt"
    "net/http"
    "math/rand"
//    "crypto/tls"
    //"strconv"
    //"strings"
    metadata "local.com/leobrada/ztsfc_http_pep/metadata"
  //  env "local.com/leobrada/ztsfc_http_pep/env"
    proxies "local.com/leobrada/ztsfc_http_pep/proxies"
//    bauth "local.com/leobrada/ztsfc_http_pep/basic_auth"
)

//func PerformAuthorization(req *http.Request, cpm *metadata.Cp_metadata) (allow bool, sfc []string) {
func TransformSFCintoSFP(cpm *metadata.Cp_metadata) {

//    fmt.Printf("SFC BEFORE SENT TO SFP LOPGIC: %s\n", cpm.SFC)

    sfp_req, err := http.NewRequest("GET", "https://10.4.0.52:8889", nil)
    if err != nil {
        fmt.Printf("Error when sending to sfp logic (1): %v\n", err)
    }
    prepareSFPRequest(sfp_req, cpm)
    response, err := proxies.Sfp_logic_client_pool[rand.Int()%50].Do(sfp_req)
    if err != nil {
        fmt.Printf("Error when sending to sfp logic (2): %v\n", err)
        fmt.Fprintf(os.Stderr, "Error when sending to sfp logic (2): %v\n", err)
    }

    cpm.SFP = response.Header.Get("sfp")

   // if response.Header.Get("allow") == "yes" {
   //     allow = true
   // } else {
   //     allow = false
   // }

   // return allow, sfc
}

func prepareSFPRequest(req *http.Request, cpm *metadata.Cp_metadata) {
//    fmt.Printf("cpm.SFC value: %s\n", cpm.SFC)
    req.Header.Set("sfc", cpm.SFC)
//    fmt.Printf("HTTP Header: %s\n", req.Header.Get("sfc"))
//    fmt.Fprintf(os.Stderr, "HTTP Header: %s\n", req.Header.Get("sfc"))
}
