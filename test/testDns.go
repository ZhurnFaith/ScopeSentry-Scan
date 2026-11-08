// main-------------------------------------
// @file      : testDns.go
// @author    : Autumn
// @contact   : rainy-autumn@outlook.com
// @time      : 2024/9/17 16:48
// -------------------------------------------

package main

import (
	"fmt"
	"github.com/ZhurnFaith/ScopeSentry-Scan/pkg/utils"
	"time"
)

func main() {
	start := time.Now()
	// Create DNS Resolver with default options
	//dnsClient, err := dnsx.New(dnsx.DefaultOptions)
	//if err != nil {
	//	fmt.Printf("err: %v\n", err)
	//	return
	//}

	//DNS A question and returns corresponding IPs
	//result, err := dnsClient.Lookup("att-globys.idp.blogin.att.com")
	//if err != nil {
	//	fmt.Printf("err: %v\n", err)
	//	return
	//}
	//for idx, msg := range result {
	//	fmt.Printf("%d: %s\n", idx+1, msg)
	//}
	utils.InitializeDnsTools()
	// Query
	// Define an array to store domains
	domains := []string{
		"dwassentrydwasdweqewqe.dwas",
		"example.com",
		"anotherdomain.test",
	}

	// Iterate over domain array
	for _, domain := range domains {
		resultDns := utils.DNS.QueryOne(domain)
		tmp := utils.DNS.DNSdataToSubdomainResult(resultDns)
		fmt.Printf("Domain: %s, Response: %s\n", domain, tmp)
	}
	// Record program end time
	end := time.Now()

	// Calculate time difference
	duration := end.Sub(start)

	// Print program run time
	fmt.Printf("Program uptime: %v\n", duration)
	return
}
