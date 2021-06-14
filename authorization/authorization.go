package authorization

import (
    "os"
    "fmt"
    "net/http"
    "math/rand"
    "strconv"
    metadata "local.com/leobrada/ztsfc_http_pep/metadata"
    proxies "local.com/leobrada/ztsfc_http_pep/proxies"
)

func PerformAuthorization(req *http.Request, cpm *metadata.Cp_metadata) {
    collectAttributes(req, cpm)


    autho_req, _ := http.NewRequest("GET", "https://10.4.0.52:8888", nil)
    prepareAuthRequest(autho_req, cpm)
    response, err := proxies.Pdp_client_pool[rand.Int()%50].Do(autho_req)

    if err != nil {
        fmt.Printf("Error when sending to pdp (2): %v\n", err)
        fmt.Fprintf(os.Stderr, "Error when sending to pdp (2): %v\n", err)
    }

    cpm.SFC = response.Header.Get("sfc")
    cpm.Auth_decision, _ = strconv.ParseBool(response.Header.Get("allow"))
}

func prepareAuthRequest(autho_req *http.Request, cpm *metadata.Cp_metadata) {
    autho_req.Header.Set("user", cpm.User)
    autho_req.Header.Set("pwAuthenticated", strconv.FormatBool(cpm.Pw_authenticated))
    autho_req.Header.Set("certAuthenticated", strconv.FormatBool(cpm.Cert_authenticated))
    autho_req.Header.Set("resource", cpm.Resource)
    autho_req.Header.Set("action", cpm.Action)
    autho_req.Header.Set("device", cpm.Device)
    autho_req.Header.Set("requestToday", cpm.RequestToday)
    autho_req.Header.Set("failedToday", cpm.FailedToday)
    autho_req.Header.Set("location", cpm.Location)
}

func collectAttributes(req *http.Request, cpm *metadata.Cp_metadata) {
    collectResource(req, cpm)
    collectAction(req, cpm)
    collectDevice(req, cpm)
    collectRequestToday(req, cpm)
    collectFailedToday(req, cpm)
    collectLocation(req, cpm)
}

func collectResource(req *http.Request, cpm *metadata.Cp_metadata) {
    cpm.Resource = req.Host
}

func collectAction(req *http.Request, cpm *metadata.Cp_metadata) {
    cpm.Action = req.Method
}

func collectDevice(req *http.Request, cpm *metadata.Cp_metadata) {
    cpm.Device = req.Header.Get("device")
}

func collectRequestToday(req *http.Request, cpm *metadata.Cp_metadata) {
    cpm.RequestToday = req.Header.Get("requestToday")
}

func collectFailedToday(req *http.Request, cpm *metadata.Cp_metadata) {
    cpm.FailedToday = req.Header.Get("failedToday")
}

func collectLocation(req *http.Request, cpm *metadata.Cp_metadata) {
    cpm.Location = req.Header.Get("location")
}
