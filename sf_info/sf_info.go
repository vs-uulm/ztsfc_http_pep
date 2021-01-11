package sf_info

import (
    "net/url"
    "crypto/tls"
    "log"
)

type ServiceFunctionInfo struct {
    Sf_name string
    Dst_url *url.URL // if empty ServiceFunctionInfo is implementing the functionality itself (see ServeHTTP function)
    SNI string // should only be populated if its a actual service such as Gitlab or Nginx
    Certificate tls.Certificate
    // TODO: public_pdp string, // indicates the pdp's public address
}

func NewServiceFunctionInfo(_sf_name string, _dst_url *url.URL, _cert_path string, _key_path string) (ServiceFunctionInfo, error) {
    cert, err := tls.LoadX509KeyPair(_cert_path, _key_path)
    if err != nil {
        log.Fatal("[sf_info.NewServiceFunctionInfo]: LoadX509KeyPair: ", err)
    }
    
    sf_info := ServiceFunctionInfo{
        Sf_name:     _sf_name,
        Dst_url:     _dst_url,
        Certificate:  cert,
        SNI:          "",
    }
    // TODO: check if its reachable

    return sf_info, nil
}

func NewServiceInfo(_sf_name string, _dst_url *url.URL, _cert_path string, _key_path string, _SNI string) (ServiceFunctionInfo, error) {
    cert, err := tls.LoadX509KeyPair(_cert_path, _key_path)
    if err != nil {
        log.Fatal("[sf_info.NewServiceFunctionInfo]: LoadX509KeyPair: ", err)
    }
    
    sf_info := ServiceFunctionInfo{
        Sf_name:     _sf_name,
        Dst_url:     _dst_url,
        Certificate:  cert,
        SNI:         _SNI,
    }
    // TODO: check if its reachable

    return sf_info, nil
}
/*
func (mw *Middleware) (req *http.Request) (error){
    
}

func (mw *Middleware) Evaluate(req *http.Request) (error){
    
}

func (mw *Middleware) ServeHTTP(req *http.Request) (error, bool){
    // TODO: implement
}
*/
