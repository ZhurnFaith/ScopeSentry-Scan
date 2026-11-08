// task-------------------------------------
// @file      : types.go
// @author    : Autumn
// @contact   : rainy-autumn@outlook.com
// @time      : 2024/9/9 21:31
// -------------------------------------------

package options

import "sync"

type TaskOptions struct {
	ID                  string                       //Task ID
	TaskName            string                       `bson:"TaskName" json:"TaskName"`                       // Task name
	Target              string                       `bson:"target" json:"target"`                           //Target
	Type                string                       `bson:"type" json:"type"`                               //Task type
	IsStart             bool                         `bson:"isStart" json:"isStart"`                         // Whether resumed after pause
	TargetHandler       []string                     `bson:"TargetHandler" json:"TargetHandler"`             // Target parsing module
	SubdomainScan       []string                     `bson:"SubdomainScan" json:"SubdomainScan"`             // Subdomain scan module
	SubdomainSecurity   []string                     `bson:"SubdomainSecurity" json:"SubdomainSecurity"`     // Subdomain security detection module
	AssetMapping        []string                     `bson:"AssetMapping" json:"AssetMapping"`               // Asset mapping module
	AssetHandle         []string                     `bson:"AssetHandle" json:"AssetHandle"`                 // Asset handling module
	PortScanPreparation []string                     `bson:"PortScanPreparation" json:"PortScanPreparation"` // Port scan preprocessing module
	PortScan            []string                     `bson:"PortScan" json:"PortScan"`                       // Port scan module
	PortFingerprint     []string                     `bson:"PortFingerprint" json:"PortFingerprint"`         // Port fingerprinting module
	URLScan             []string                     `bson:"URLScan" json:"URLScan"`                         // URL scan module
	URLSecurity         []string                     `bson:"URLSecurity" json:"URLSecurity"`                 // URL security detection module
	WebCrawler          []string                     `bson:"WebCrawler" json:"WebCrawler"`                   // Crawler module
	DirScan             []string                     `bson:"DirScan" json:"DirScan"`                         //Directory scan module
	VulnerabilityScan   []string                     `bson:"VulnerabilityScan" json:"VulnerabilityScan"`     //Vulnerability scan module
	PassiveScan         []string                     `bson:"PassiveScan" json:"PassiveScan"`                 // Passive scan module
	Parameters          map[string]map[string]string `bson:"Parameters" json:"Parameters"`                   // Parameters of each plugin
	IsRestart           bool                         // Whether the target came from the local cache after a restart
	Duplicates          string                       `bson:"duplicates" json:"duplicates"` // Whether to ignore subdomains already stored in mongodb
	InputChan           map[string]chan interface{}  // Input of each module
	ModuleRunWg         *sync.WaitGroup              // Total WaitGroup
	SubdomainFilename   string                       // Subdomain scan dictionary
	ProtRangeId         string                       // Port range in the database id
	PortRange           string                       // Port range
}
