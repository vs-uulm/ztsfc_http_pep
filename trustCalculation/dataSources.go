package trustCalculation

/*
In this file the threshold values for the three provided services, the trust-increase for user-attributes, the
trust-increase for device attributes, user-information for registered users and device-information of managed devices
are stored
 */

type DataSources struct {

	// Trust-increase, when a DPI is used
	dpiTrustIncrease int

	// Maximum authentication attempts to get trust for the attribute authentication attempts
	maxAuthAttempts int

	// Map, where threshold values for the devices are stored
	thresholdValues map[string]int

	// Map, where the trust-increase of user attributes is provided, when these attributes are fulfilled
	trustIncreaseUserAttr map[string]int

	// Map, where the trust-increase of device attributes is provided, when these attributes are fulfilled
	trustIncreaseDeviceAttr map[string]int

	// Map, where the current status of each user is stored (= user database)
	UserDatabase map[string]*User

	// Map, where the current status of managed devices is stored (= device database)
	deviceDatabase map[string]map[string]bool

	// Map, where for a IP address the geographic area is stored (to determine from the source IP address of requests the geographic area)
	mapIPgeoArea map[string]string

}

func NewDataSources() *DataSources {
	dataSources := DataSources{}
	dataSources.InitDataSources()
	return &dataSources
}


/*
In this method values are assigned to the specified attributes
 */
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
	dataSources.trustIncreaseDeviceAttr["RI"] = 1	// Device recently re-installed

	dataSources.deviceDatabase = make(map[string]map[string]bool)

	// create managed devices in the device database
	var device1 = make(map[string]bool)
	dataSources.deviceDatabase["device1"] = device1
	device1["LPL"] = true
	device1["NAVS"] = true
	device1["RI"] = true

	var device2 = make(map[string]bool)
	dataSources.deviceDatabase["device2"] = device2
	device2["LPL"] = true
	device2["NAVS"] = true
	device2["RI"] = true

	var device3 = make(map[string]bool)
	dataSources.deviceDatabase["device3"] = device3
	device3["LPL"] = true
	device3["NAVS"] = true
	device3["RI"] = true

	// create users in the user database
	dataSources.UserDatabase = make(map[string]*User)
	alex := NewUser("DE",[]string{"service1","service2","service3"},10000,0,0)
	ceo := NewUser("DE",[]string{"service1","service2","service3"},10000,0,0)
	man := NewUser("DE",[]string{"service1","service2","service3"},10000,0,0)
	dev := NewUser("DE",[]string{"service1","service2","service3"},10000,0,0)
	dataSources.UserDatabase["alex"] = alex
	dataSources.UserDatabase["ceo"] = ceo
	dataSources.UserDatabase["man"] = man
	dataSources.UserDatabase["dev"] = dev

	// assign ip-addresses to geographic areas (exemplary values)
	dataSources.mapIPgeoArea = make(map[string]string)
	dataSources.mapIPgeoArea["36.10.10.20"]="DE"
	dataSources.mapIPgeoArea["46.10.10.20"]="US"
}