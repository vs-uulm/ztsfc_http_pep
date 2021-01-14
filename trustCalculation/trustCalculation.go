package trustCalculation

/*
In this package, the trust of a request is calculated. According to the trust it is decided, if a request is forwarded
or blocked
*/

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

type TrustCalculation struct {
	dataSources *DataSources
	logChannel chan []byte
}

func NewTrustCalculation(log chan []byte) TrustCalculation{
	datasources := NewDataSources()
	trustCalculation := TrustCalculation{dataSources: datasources, logChannel: log}
	return trustCalculation
}

/* This function decides based on the achieved trust-value and the requested service, if the request should be directly
send to the service, send to the DPI or be blocked.
 */
func (trustCalc TrustCalculation) ForwardingDecision(req *http.Request) (forwardSFC bool, block bool){
	trustCalc.Log("---Trustcalculation\n")

	userTrust, block := trustCalc.calcUserTrust(req)
	trustCalc.Log("----User-trust: " + strconv.Itoa(userTrust) + "; Block user: " + strconv.FormatBool(block) + "\n")
	fmt.Printf("User-Trust: %d\n",userTrust)
	if block {
		return false, true
	}

	deviceTrust := trustCalc.calcDeviceTrust(req)
	trustCalc.Log("----Device-trust: " + strconv.Itoa(deviceTrust) + "\n")
	fmt.Printf("Device-Trust: %d\n", deviceTrust)

	trust := userTrust + deviceTrust
	service := strings.Split(req.URL.String(),"/")[1]
	trustCalc.Log("----Requested service: " + service + "\n")
	if threshold, ok := trustCalc.dataSources.thresholdValues[service]; ok{
		if trust >= threshold {													// In this case the threshold was reached, without a DPI -> Send request directly to service
			trustCalc.Log("----Request directly send to service\n")
			fmt.Println("Direct to service")
			return false, false
		} else if (trust+trustCalc.dataSources.dpiTrustIncrease)>=threshold {	// In this case the threshold was only reached with the DPI -> Send request at first to the DPI
			trustCalc.Log("----Request send to DPI\n")
			fmt.Println("Request send to DPI")
			return true, false
		} else {																// In this case the threshold was not reached with the DPI because the trust-value is very low -> Request is blocked
			trustCalc.Log("----Trust to low. Request blocked\n")
			fmt.Printf("Request blocked")
			return false, true
		}
	}

	return false,true											// In this case an unknown service was requested -> Request is blocked
}

func (trustCalc TrustCalculation) calcUserTrust(req *http.Request) (trust int, block bool) {
	trust = 0
	block = false

	// Analyze authentication type
	userPW := ""	// Not empty, when authenticated with password
	userCert := ""	// Not empty, when authenticated with Client-certificate
	user := ""

	if name, err := req.Cookie("Username"); err==nil{
		userPW = name.Value
		trustCalc.Log("----Authenticated with password, username: " + userPW+"\n")
	}

	if certs := req.TLS.PeerCertificates; (len(certs) > 0) {
		userCert = certs[0].Subject.CommonName
		trustCalc.Log("----Authenticated with certificate, username: " + userCert + "\n")
	}

	user = userPW
	if userPW!="" && userCert!="" &&userPW==userCert {
		trust = trust+trustCalc.dataSources.trustIncreaseUserAttr["CRT_PW"]		// Authenticated with Password and Client-Certificate
		trustCalc.Log("----User and Certificate authentication, Trust: " + strconv.Itoa(trust) + "\n")
	} else if userCert!="" {
		trust = trust+trustCalc.dataSources.trustIncreaseUserAttr["CRT"] 		// Authenticated only with Client-Certificate
		user = userCert
		trustCalc.Log("----Certificate authentication, Trust: " + strconv.Itoa(trust) + "\n")
	} else if userPW == ""{
		trust = 0
		return trust, true												// Block user, because it didn't authenticate itself to the PEP
	}

	// Analyze geographic area
	if ip, err := req.Cookie("ip-addr-geo-area"); err==nil{
		if geoArea, ok := trustCalc.dataSources.mapIPgeoArea[ip.Value]; ok {
			if trustCalc.dataSources.userDatabase[user].usualGeo == geoArea{
				trust = trust + trustCalc.dataSources.trustIncreaseUserAttr["UGA"]
				trustCalc.Log("Geographic area: " + geoArea + ", Trust: " +  strconv.Itoa(trust) + "\n")
			}
		}
	}

	// Analyze commonly used services
	requestedService := strings.Split(req.URL.String(),"/")[1]
	for _, commonService := range trustCalc.dataSources.userDatabase[user].commonUsedService {
		if requestedService == commonService {								// service is identified with first part in the requested URL
				trust = trust + trustCalc.dataSources.trustIncreaseUserAttr["CUS"]
				trustCalc.Log("Commonly used service: " + commonService+", Trust: " +  strconv.Itoa(trust) + "\n")
				break
		}
	}

	// Analyze usual amount of requests
	trustCalc.dataSources.userDatabase[user].IncRequ()
	if trustCalc.dataSources.userDatabase[user].usualRequest>trustCalc.dataSources.userDatabase[user].currentRequest {
		trust = trust + trustCalc.dataSources.trustIncreaseUserAttr["UAR"]
		trustCalc.Log("Amount of requests: " +  strconv.Itoa(trustCalc.dataSources.userDatabase[user].currentRequest) + ", Trust: " + strconv.Itoa(trust)+"\n")
	}

	// Analyze authentication attempts
	if trustCalc.dataSources.maxAuthAttempts > trustCalc.dataSources.userDatabase[user].authAttempts {			// Only when the authentication attempts of the user don't exceed the maximum authentication attempts, the trust is increased
		trust = trust + trustCalc.dataSources.trustIncreaseUserAttr["AA"]
		trustCalc.Log("Authentication Attempts: " +  strconv.Itoa(trustCalc.dataSources.userDatabase[user].authAttempts) + ", " +  strconv.Itoa(trust) + "\n")
	}

	return trust, false
}

func (trustCalc TrustCalculation) calcDeviceTrust(req *http.Request) (trust int) {
	deviceName := ""
	if device, err := req.Cookie("managedDevice"); err==nil{
		deviceName = device.Value
		trustCalc.Log("----Managed device: " + deviceName + "\n")
	} else{
		return 0		// In this case no managed device is used
	}

	fmt.Println(deviceName)
	trust = 0
	if device, ok := trustCalc.dataSources.deviceDatabase[deviceName]; ok {
		if(device["LPL"]){	// Check, if on the device the latest patch levels are installed
			trust = trust + trustCalc.dataSources.trustIncreaseDeviceAttr["LPL"]
			trustCalc.Log("----Patch level, " +  strconv.Itoa(trust) + "\n")
		}
		if(device["NAVS"]){ // Check, if there are (no) alerts from the virus scanner
			trust = trust + trustCalc.dataSources.trustIncreaseDeviceAttr["NAVS"]
			trustCalc.Log("----Virus Scanner, " +  strconv.Itoa(trust) + "\n")
		}
		if(device["RI"]){ // Check, if device was recently re-installed
			trust = trust + trustCalc.dataSources.trustIncreaseDeviceAttr["RI"]
			trustCalc.Log("----Re-Installed, " +  strconv.Itoa(trust) + "\n")
		}
	}
	return trust
}

func (trustCalc TrustCalculation) GetDataSources() *DataSources{
	return trustCalc.dataSources
}

func (trustCalc TrustCalculation) Log(s string) {
	trustCalc.logChannel <- []byte(s)
}
