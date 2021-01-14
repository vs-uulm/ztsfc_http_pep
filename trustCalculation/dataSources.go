package trustCalculation

/*
In this file the threshold values for the three provided services, the trust-increase for user-attribtues, the
trust-increase for device attributes, user-information and device information of managed devices is stored
 */

type DataSources struct {

	// Trust-increase, when a DPI is used
	dpiTrustIncrease int

	// Maximum authentication attempts to get trust for the attribute authetnication attempts
	maxAuthAttempts int

	// Map, where threshold values for the devices are stored
	thresholdValues map[string]int

	// Map, where the trust-increase of user attributes is provided, when these attributes are fulfilled
	trustIncreaseUserAttr map[string]int

	// Map, where the trust-increase of device attributes is provided, when these attributes are fulfilled
	trustIncreaseDeviceAttr map[string]int

	// Map, where the current status of each user is stored
	userDatabase map[string]*User

	// Map, where the current status of managed devices is stored
	deviceDatabase map[string]map[string]bool

	// Map, where for a IP address the geographic area is stored, where the request comes from
	mapIPgeoArea map[string]string

}

func NewDataSources() *DataSources {
	dataSources := DataSources{}
	dataSources.InitDataSources()
	return &dataSources
}


// In this method, the specified data sources are filled with content
func (dataSources *DataSources) InitDataSources()  {
	dataSources.dpiTrustIncrease = 6

	dataSources.maxAuthAttempts = 3

	dataSources.thresholdValues = make(map[string]int)
	dataSources.thresholdValues["service1"] = 11
	dataSources.thresholdValues["service2"] = 14
	dataSources.thresholdValues["service3"] = 17

	dataSources.trustIncreaseUserAttr = make(map[string]int)
	dataSources.trustIncreaseUserAttr["UGA"] = 1 	// Usual geographic area
	dataSources.trustIncreaseUserAttr["CUS"] = 2 	// Commonly used services
	dataSources.trustIncreaseUserAttr["UAR"] = 2 	// Usual amount of requests
	dataSources.trustIncreaseUserAttr["AA"] = 3 	// Authentication attempts
	dataSources.trustIncreaseUserAttr["CRT"] = 2 	// Authentication with a client-certificate
	dataSources.trustIncreaseUserAttr["CRT_PW"] = 3	// Authentication with a client-certificate and a password

	dataSources.trustIncreaseDeviceAttr = make(map[string]int)
	dataSources.trustIncreaseDeviceAttr["LPL"] = 3	// Latest patch level
	dataSources.trustIncreaseDeviceAttr["NAVS"] = 2	// No alerts of virus scanner
	dataSources.trustIncreaseDeviceAttr["RI"] = 1	// Re-installation

	dataSources.deviceDatabase = make(map[string]map[string]bool)

	var device1 = make(map[string]bool)
	dataSources.deviceDatabase["device1"] = device1
	device1["LPL"] = true
	device1["NAVS"] = true
	device1["RI"] = true

	var device2 = make(map[string]bool)
	dataSources.deviceDatabase["device2"] = device1
	device2["LPL"] = false
	device2["NAVS"] = true
	device2["RI"] = false

	dataSources.userDatabase = make(map[string]*User)
	user := NewUser("DE",[]string{"service1"},1000,300,1)
	dataSources.userDatabase["alex"] = user

	dataSources.mapIPgeoArea = make(map[string]string)
	dataSources.mapIPgeoArea["36.10.10.20"]="DE"
}

// The method increases the authentication attempts of a user, after a failed authentication
func (dataSrc *DataSources)IncAuthAttempt(username string) {
	if user, ok := dataSrc.userDatabase[username]; ok {
		user.authAttempts++
	}
}