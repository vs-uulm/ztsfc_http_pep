package trustCalculation

/*
In this file, the trust of a request is calculated. According to the trust it is decided, if a request is forwarded
or blocked.
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
	// Check authentication
	authenticated := trustCalc.checkAuthentication(req)
	if !authenticated {	// Check if authentication is valid
		return false, true
	}

	trustCalc.Log("---Trustcalculation\n")

	userTrust := trustCalc.calcUserTrust(req)
	trustCalc.Log("----User-trust: " + strconv.Itoa(userTrust) + "\n")
	fmt.Printf("User-Trust: %d\n",userTrust)

	deviceTrust := trustCalc.calcDeviceTrust(req)
	trustCalc.Log("----Device-trust: " + strconv.Itoa(deviceTrust) + "\n")
	fmt.Printf("Device-Trust: %d\n", deviceTrust)

	trustCalc.removeHTTPHeader(req)												// Remove http header, which are only necessary for trust-calculation

	trust := userTrust + deviceTrust
	service := strings.Split(req.URL.String(),"/")[1]						// Derive requested service from URL
	trustCalc.Log("----Requested service: " + service + "\n")

	if threshold, ok := trustCalc.dataSources.thresholdValues[service]; ok {
		if trust >= threshold {													// In this case the threshold was reached, without a DPI -> Send request directly to service
			trustCalc.Log("----Request directly send to service\n")
			fmt.Println("Direct to service")
			return false, false
		} else if (trust+trustCalc.dataSources.dpiTrustIncrease) >= threshold {	// In this case the threshold was only reached with the DPI -> Send request at first to the DPI
			trustCalc.Log("----Request send to DPI\n")
			fmt.Println("Request send to DPI")
			return true, false
		} else {																// In this case the threshold was not reached with the DPI because the trust-value is very low -> Request is blocked
			trustCalc.Log("----Trust to low. Request blocked\n")
			fmt.Printf("Request blocked")
			return false, true
		}
	} else {
		return false,true										// In this case an unknown service was requested -> Request is blocked
	}
}

// Calculate trust of the user attributes
func (trustCalc TrustCalculation) calcUserTrust(req *http.Request) (trust int) {
	trust = 0

	// Analyze authentication type
	userPW := ""	// Not empty, when authenticated with password
	userCert := ""	// Not empty, when authenticated with client-certificate
	user := ""

	if name, err := req.Cookie("Username"); err==nil {
		userPW = name.Value
		trustCalc.Log("----Authenticated with password, username: " + userPW+"\n")
	}

	if certs := req.TLS.PeerCertificates; (len(certs) > 0) {
		userCert = certs[0].Subject.CommonName
		trustCalc.Log("----Authenticated with certificate, username: " + userCert + "\n")
	}

	if userPW != "" && userCert != "" && userPW == userCert {
		trust = trust + trustCalc.dataSources.trustIncreaseUserAttr["CRT_PW"]	// Authenticated with Password and Client-Certificate
		user = userPW
		trustCalc.Log("----User and Certificate authentication, Trust: " + strconv.Itoa(trust) + "\n")
	} else if userCert != "" {
		trust = trust + trustCalc.dataSources.trustIncreaseUserAttr["CRT"] 		// Authenticated only with Client-Certificate
		user = userCert
		trustCalc.Log("----Certificate authentication, Trust: " + strconv.Itoa(trust) + "\n")
	} else if userPW != "" {
		user = userPW															// Authenticated only with password
		trustCalc.Log("----Password authentication (no trust-increase), Trust: " + strconv.Itoa(trust) + "\n")
	}

	// Analyze geographic area
	ip := req.Header.Get("ip-addr-geo-area")
	if geoArea, ok := trustCalc.dataSources.mapIPgeoArea[ip]; ok {
		if trustCalc.dataSources.UserDatabase[user].usualGeo == geoArea { // Check, if usual geographic area corresponds to geographic area of the request
			trust = trust + trustCalc.dataSources.trustIncreaseUserAttr["UGA"]
			trustCalc.Log("----Geographic area: " + geoArea + ", Trust: " +  strconv.Itoa(trust) + "\n")
		}
	}

	// Analyze commonly used services
	requestedService := strings.Split(req.URL.String(),"/")[1]				// service is identified with first part in the requested URL
	for _, commonService := range trustCalc.dataSources.UserDatabase[user].commonUsedService {
		if requestedService == commonService {									// Check, if commonly used service corresponds to the requested service
			trust = trust + trustCalc.dataSources.trustIncreaseUserAttr["CUS"]
			trustCalc.Log("----Commonly used service: " + commonService+", Trust: " +  strconv.Itoa(trust) + "\n")
			break
		}
	}

	// Analyze usual amount of requests
	if trustCalc.dataSources.UserDatabase[user].usualRequest > trustCalc.dataSources.UserDatabase[user].currentRequest { // Check, if the amount of requests is below the usual amount of requests for this user
		trust = trust + trustCalc.dataSources.trustIncreaseUserAttr["UAR"]
		trustCalc.Log("----Amount of requests: " +  strconv.Itoa(trustCalc.dataSources.UserDatabase[user].currentRequest) + ", Trust: " + strconv.Itoa(trust)+"\n")
	}

	// Analyze authentication attempts
	if trustCalc.dataSources.maxAuthAttempts > trustCalc.dataSources.UserDatabase[user].authAttempts { // Check, if the authentication attempts of the user are below the maximum authentication attempts
		trust = trust + trustCalc.dataSources.trustIncreaseUserAttr["AA"]
		trustCalc.Log("----Authentication Attempts: " +  strconv.Itoa(trustCalc.dataSources.UserDatabase[user].authAttempts) + ", Trust: " +  strconv.Itoa(trust) + "\n")
	}

	return trust
}

// Calculate trust of the device attributes
func (trustCalc TrustCalculation) calcDeviceTrust(req *http.Request) (trust int) {
	trust = 0
	deviceName := ""

	if device := req.Header.Get("managedDevice"); device != "" {
		deviceName = device
		trustCalc.Log("----Managed device: " + deviceName + "\n")
	} else{
		trustCalc.Log("----No Managed device used\n")
		return 0		// In this case no managed device is used
	}

	fmt.Println(deviceName)
	if device, ok := trustCalc.dataSources.deviceDatabase[deviceName]; ok {			// Check, if managed device is known to device database
		if device["LPL"] { 	// Check, if on the device the latest patch levels are installed
			trust = trust + trustCalc.dataSources.trustIncreaseDeviceAttr["LPL"]
			trustCalc.Log("----Current Patch level, Trust: " +  strconv.Itoa(trust) + "\n")
		}
		if device["NAVS"] {	// Check, if there are (no) alerts from the virus scanner
			trust = trust + trustCalc.dataSources.trustIncreaseDeviceAttr["NAVS"]
			trustCalc.Log("----No alerts from virus scanner, Trust: " +  strconv.Itoa(trust) + "\n")
		}
		if device["RI"] { 	// Check, if device was recently re-installed
			trust = trust + trustCalc.dataSources.trustIncreaseDeviceAttr["RI"]
			trustCalc.Log("----Re-Installed, Trust: " +  strconv.Itoa(trust) + "\n")
		}
	}

	return trust
}

// In this method is checked, if the user authenticated with a password or client-certificate and if the user is known to the PEP
func (trustCalc TrustCalculation) checkAuthentication(req *http.Request) (authenticated bool) {
	userNamePW := ""
	userNameCert := ""

	// Check password-authentication
	if name, err := req.Cookie("Username"); err == nil {
		userNamePW = name.Value
		// Check if user exists in user-database
		if _, ok:= trustCalc.dataSources.UserDatabase[userNamePW]; !ok {
			trustCalc.Log("----Username " + userNamePW + "unknown -> Block\n")
			fmt.Println("Username " + userNamePW + " unknown")
			return false
		}
	}

	// Check certificate-authentication
	if certs := req.TLS.PeerCertificates; len(certs) > 0 {
		userNameCert = certs[0].Subject.CommonName
		// Check if user exists in user-database
		if _, ok:= trustCalc.dataSources.UserDatabase[userNameCert]; !ok {
			trustCalc.Log("Username " + userNameCert + "unknown -> Block\n")
			fmt.Println("Username " + userNameCert + " unknown")
			return false
		}
	}

	// Check if user authenticated with two different accounts in password and certificate
	if userNamePW != "" && userNameCert != "" && userNamePW != userNameCert {
		trustCalc.Log("----Username in Password" + userNamePW + "and Username in certificate " + userNamePW+" are different -> Block\n")
		return false
	}

	trustCalc.Log("---User authenticated\n")
	return true
}

// In this method the custom headers, which are only necessary for the PEP for trust-calculation, are removed
func (trustCalc TrustCalculation) removeHTTPHeader(req *http.Request) {
		req.Header.Del("ip-addr-geo-area")
		req.Header.Del("managedDevice")
}

func (trustCalc TrustCalculation) GetDataSources() *DataSources{
	return trustCalc.dataSources
}

func (trustCalc TrustCalculation) Log(s string) {
	trustCalc.logChannel <- []byte(s)
}
