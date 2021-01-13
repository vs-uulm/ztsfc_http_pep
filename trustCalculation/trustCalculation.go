package trustCalculation

import "net/http"

/* This function decides based on the achieved trust-value and the requested service, if the request should be directly
send to the service, send to the DPI or be blocked.
 */
func ForwardingDecision(req *http.Request) (forwardSFC bool, block bool){
return false,false
}

func calcUserAttributes() (trust int) {
return 0
}
