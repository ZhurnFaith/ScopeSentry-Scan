// results-------------------------------------
// @file      : handler.go
// @author    : Autumn
// @contact   : rainy-autumn@outlook.com
// @time      : 2024/9/19 19:10
// -------------------------------------------

package results

import (
	"context"
	"errors"
	"fmt"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/global"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/mongodb"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/notification"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/redis"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/types"
	"github.com/ZhurnFaith/ScopeSentry-Scan/pkg/logger"
	"github.com/ZhurnFaith/ScopeSentry-Scan/pkg/utils"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"strings"
)

type handler struct {
}

var Handler *handler

func InitializeHandler() {
	Handler = &handler{}
}

func (h *handler) GetAssetProject(host string) string {
	for _, p := range global.Projects {
		for _, t := range p.Target {
			if host == t {
				// Check whether blacklisted
				for _, igTarget := range p.IgnoreList {
					if host == igTarget {
						return ""
					}
				}
				// Regex check for blacklist
				for _, igRegex := range p.IgnoreRegexList {
					if igRegex.MatchString(host) {
						return ""
					}
				}
				return p.ID
			}
		}
	}
	return ""
}

func (h *handler) Subdomain(result *types.SubdomainResult) {
	var interfaceSlice interface{}
	rootDomain, err := utils.Tools.GetRootDomain(result.Host)
	if err != nil {
		logger.SlogInfoLocal(fmt.Sprintf("%v GetRootDomain error: %v", result.Host, err))
	}
	result.RootDomain = rootDomain
	if result.Time == "" {
		result.Time = utils.Tools.GetTimeNow()
	}
	result.Project = h.GetAssetProject(rootDomain)
	interfaceSlice = &result
	if global.NotificationConfig.SubdomainNotification {
		NotificationMsg := fmt.Sprintf("%v - %v\n", result.Host, result.IP)
		notification.NotificationQueues["SubdomainScan"].Queue <- NotificationMsg
	}
	ResultQueues["SubdomainScan"].Queue <- interfaceSlice
}

func (h *handler) SubdomainTakeover(result *types.SubTakeResult) {
	var interfaceSlice interface{}
	rootDomain, err := utils.Tools.GetRootDomain(result.Input)
	if err != nil {
		logger.SlogInfoLocal(fmt.Sprintf("%v GetRootDomain error: %v", result.Input, err))
	}
	result.RootDomain = rootDomain
	result.Project = h.GetAssetProject(rootDomain)
	interfaceSlice = &result
	if global.NotificationConfig.SubdomainTakeoverNotification {
		NotificationMsg := fmt.Sprintf("Subdomain Takeover:\n%v - %v\n", result.Input, result.Cname)
		notification.NotificationQueues["SubdomainSecurity"].Queue <- NotificationMsg
	}
	ResultQueues["SubdomainSecurity"].Queue <- interfaceSlice
}

func (h *handler) AssetChangeLog(result *types.AssetChangeLog) {
	var interfaceSlice interface{}
	interfaceSlice = &result
	ResultQueues["AssetChangeLog"].Queue <- interfaceSlice
}

func (h *handler) HttpBody(hash string, body string) {
	if body == "" || hash == "" {
		return
	}
	doc := bson.M{
		"hash":    hash,
		"content": body,
	}
	_, err := mongodb.MongodbClient.InsertOne("HttpBody", doc)
	if err != nil {
		// Ignore if it is a unique index conflict
		if mongo.IsDuplicateKeyError(err) {
			//logger.SlogDebugLocal(fmt.Sprintf("HttpBody: body hash  %s already exists", hash))
			return
		}
		// Log other errors
		logger.SlogError(fmt.Sprintf("HttpIcon insert error: %v", err))
	}

}

func (h *handler) HttpIcon(faviconmmh3 string, icon string) {
	if faviconmmh3 == "" || icon == "" {
		return
	}
	doc := bson.M{
		"fav3":    faviconmmh3,
		"content": icon,
	}

	_, err := mongodb.MongodbClient.InsertOne("icon", doc)
	if err != nil {
		// Ignore if it is a unique index conflict
		if mongo.IsDuplicateKeyError(err) {
			//logger.SlogDebugLocal(fmt.Sprintf("HttpIcon: faviconmmh3 %s already exists", faviconmmh3))
			return
		}
		// Log other errors
		logger.SlogError(fmt.Sprintf("HttpIcon insert error: %v", err))
	}
}

func (h *handler) HttpScreenshot(hash string, screenshot string) {
	if screenshot == "" || hash == "" {
		return
	}
	doc := bson.M{
		"hash":    hash,
		"content": screenshot,
	}
	_, err := mongodb.MongodbClient.InsertOne("screenshot", doc)
	if err != nil {
		// Ignore if it is a unique index conflict
		if mongo.IsDuplicateKeyError(err) {
			//logger.SlogDebugLocal(fmt.Sprintf("HttpBody: body hash  %s already exists", hash))
			return
		}
		// Log other errors
		logger.SlogError(fmt.Sprintf("HttpScreenshot insert error: %v", err))
	}
}

func (h *handler) AssetUpdate(id string, updateData interface{}) {
	// Assets are few and history must be fetched in real time, so bulk insert is not used
	objectID, err := primitive.ObjectIDFromHex(id) // Convert string ID to ObjectID
	if err != nil {
		logger.SlogError(fmt.Sprintf("AssetUpdate %v ObjectIDFromHex error:%v", id, err))
		return
	}
	selector := bson.M{"_id": objectID} // Create selector matching the specified ObjectID
	_, err = mongodb.MongodbClient.Update("asset", selector, bson.M{"$set": updateData})
	if err != nil {
		logger.SlogError(fmt.Sprintf("AssetUpdate %v error:%v", id, err))
	} // Update fields with $set
	go func() {
		if asset, ok := updateData.(types.AssetHttp); ok {
			ipAssetTmpDoc := types.IPAssetTmp{
				IP:           asset.IP,
				Domain:       asset.Host,
				Port:         asset.Port,
				Service:      asset.Service,
				WebServer:    asset.WebServer,
				Technologies: asset.Technologies,
				Project:      asset.Project,
				TaskName:     asset.TaskName,
				RootDomain:   asset.RootDomain,
			}
			_, err = mongodb.MongodbClient.InsertOne("IPAssetTmp", ipAssetTmpDoc)
			if err != nil {
				logger.SlogError(fmt.Sprintf("ipAssetTmpDoc error:%v", err))
			}
		}

	}()
}

func (h *handler) AssetOtherInsert(result *types.AssetOther) {
	// Assets are few and history must be fetched in real time, so bulk insert is not used
	var interfaceSlice interface{}
	rootDomain, err := utils.Tools.GetRootDomain(result.Host)
	if err != nil {
		logger.SlogInfoLocal(fmt.Sprintf("%v GetRootDomain error: %v", result.Host, err))
	}
	result.RootDomain = rootDomain
	if result.Time == "" {
		result.Time = utils.Tools.GetTimeNow()
	}

	result.Project = h.GetAssetProject(rootDomain)
	interfaceSlice = &result
	go func() {
		ipAssetTmpDoc := types.IPAssetTmp{
			IP:         result.IP,
			Domain:     result.Host,
			Port:       result.Port,
			Service:    result.Service,
			Project:    result.Project,
			TaskName:   result.TaskName,
			RootDomain: result.RootDomain,
		}
		_, err = mongodb.MongodbClient.InsertOne("IPAssetTmp", ipAssetTmpDoc)
		if err != nil {
			logger.SlogError(fmt.Sprintf("ipAssetTmpDoc error:%v", err))
		}
	}()
	_, err = mongodb.MongodbClient.InsertOne("asset", interfaceSlice)
	if err != nil {
		var we mongo.WriteException
		if errors.As(err, &we) {
			for _, e := range we.WriteErrors {
				if e.Code == 11000 {
					// Duplicate key error, do not log
					return
				}
			}
		}
		logger.SlogError(fmt.Sprintf("AssetOtherInsert error:%v", err))
		return
	}
}

func (h *handler) AssetHttpInsert(result *types.AssetHttp) {
	// Assets are few and history must be fetched in real time, so bulk insert is not used
	var interfaceSlice interface{}
	rootDomain, err := utils.Tools.GetRootDomain(result.Host)
	if err != nil {
		logger.SlogInfoLocal(fmt.Sprintf("%v GetRootDomain error: %v", result.Host, err))
	}
	result.RootDomain = rootDomain
	if result.Time == "" {
		result.Time = utils.Tools.GetTimeNow()
	}
	result.Project = h.GetAssetProject(rootDomain)
	interfaceSlice = &result

	go func() {
		ipAssetTmpDoc := types.IPAssetTmp{
			IP:           result.IP,
			Domain:       result.Host,
			Port:         result.Port,
			Service:      result.Service,
			WebServer:    result.WebServer,
			Technologies: result.Technologies,
			Project:      result.Project,
			TaskName:     result.TaskName,
			RootDomain:   result.RootDomain,
		}
		_, err = mongodb.MongodbClient.InsertOne("IPAssetTmp", ipAssetTmpDoc)
		if err != nil {
			logger.SlogError(fmt.Sprintf("ipAssetTmpDoc error:%v", err))
		}
	}()
	_, err = mongodb.MongodbClient.InsertOne("asset", interfaceSlice)
	if err != nil {
		var we mongo.WriteException
		if errors.As(err, &we) {
			for _, e := range we.WriteErrors {
				if e.Code == 11000 {
					// Duplicate key error, do not log
					return
				}
			}
		}
		// Print other errors normally
		logger.SlogError(fmt.Sprintf("AssetHttpInsert error: %v", err))
		return
	}

}

func (h *handler) URL(result *types.UrlResult) {
	var interfaceSlice interface{}
	if result.RootDomain == "" {
		rootDomain, err := utils.Tools.GetRootDomain(result.Output)
		if err != nil {
			logger.SlogInfoLocal(fmt.Sprintf("%v GetRootDomain error: %v", result.Input, err))
		}
		result.RootDomain = rootDomain
	}
	result.Project = h.GetAssetProject(result.RootDomain)
	if result.Time == "" {
		result.Time = utils.Tools.GetTimeNow()
	}
	// Create a copy of result and set Body to empty
	// Create a new result object with an empty Body
	resultCopy := types.UrlResult{
		Input:      result.Input,
		Source:     result.Source,
		OutputType: result.OutputType,
		Output:     result.Output,
		Status:     result.Status,
		Length:     result.Length,
		Time:       result.Time,
		Project:    result.Project,
		TaskName:   result.TaskName,
		ResultId:   result.ResultId,
		RootDomain: result.RootDomain,
		Body:       "", // Set Body to empty
		Tags:       result.Tags,
		Ext:        result.Ext,
	}
	interfaceSlice = &resultCopy
	ResultQueues["URLScan"].Queue <- interfaceSlice
}

func (h *handler) Crawler(result *types.CrawlerResult) {
	var interfaceSlice interface{}
	rootDomain, err := utils.Tools.GetRootDomain(result.Url)
	if err != nil {
		logger.SlogInfoLocal(fmt.Sprintf("%v GetRootDomain error: %v", result.Url, err))
	}
	result.RootDomain = rootDomain
	if result.Time == "" {
		result.Time = utils.Tools.GetTimeNow()
	}
	result.Project = h.GetAssetProject(rootDomain)
	interfaceSlice = &result
	ResultQueues["WebCrawler"].Queue <- interfaceSlice
}

func (h *handler) Sensitive(result *types.SensitiveResult) {
	var interfaceSlice interface{}
	rootDomain := ""
	var err error
	if strings.HasPrefix(result.Url, "APP:") {
		tmpPart := strings.Split(result.Url, ":")
		if len(tmpPart) >= 2 {
			rootDomain = tmpPart[1]
		}
	} else {
		rootDomain, err = utils.Tools.GetRootDomain(result.Url)
	}
	if err != nil {
		logger.SlogInfoLocal(fmt.Sprintf("%v GetRootDomain error: %v", result.Url, err))
	}
	result.RootDomain = rootDomain
	if result.Time == "" {
		result.Time = utils.Tools.GetTimeNow()
	}
	result.Project = h.GetAssetProject(rootDomain)
	interfaceSlice = &result
	if global.NotificationConfig.SensitiveNotification {
		NotificationMsg := fmt.Sprintf("Sensitive Scan:\n%v - %v\n", result.Url, result.SID)
		notification.NotificationQueues["URLSecurity"].Queue <- NotificationMsg
	}
	ResultQueues["SensitiveResult"].Queue <- interfaceSlice

}

func (h *handler) SensitiveBody(body string, md5 string) {
	selector := bson.M{"md5": md5}

	update := bson.M{
		"$set": bson.M{
			"body": body,
			"md5":  md5,
		},
	}
	op := types.BulkUpdateOperation{
		Selector: selector,
		Update:   update,
	}
	ResultQueues["SensitiveBody"].Queue <- op
}

func (h *handler) SensitiveUrl(url string, urlId string, bodyId string) {
	key := "SenU:" + urlId
	collectionName := "SensitiveUrl"
	selector := bson.M{"urlId": urlId}
	flag := Duplicate.DuplicateLocalCache(key)
	if flag {
		update := bson.M{
			"$set": bson.M{
				"url":    url,
				"urlId":  urlId,
				"bodyId": bodyId,
			},
		}
		// Call the Upsert method to insert or update
		_, err := mongodb.MongodbClient.Upsert(collectionName, selector, update)
		if err != nil {
			logger.SlogError(fmt.Sprintf("SensitiveUrl insert mongodb error:%v", err))
		}
	}
}

func (h *handler) Dir(result *types.DirResult) {
	var interfaceSlice interface{}
	rootDomain, err := utils.Tools.GetRootDomain(result.Url)
	if err != nil {
		logger.SlogInfoLocal(fmt.Sprintf("%v GetRootDomain error: %v", result.Url, err))
	}
	result.RootDomain = rootDomain
	result.Project = h.GetAssetProject(rootDomain)
	interfaceSlice = &result
	if global.NotificationConfig.DirScanNotification {
		NotificationMsg := ""
		if result.Msg != "" {
			NotificationMsg = fmt.Sprintf("%v - %v -%v\n", result.Url, result.Status, result.Msg)
		} else {
			NotificationMsg = fmt.Sprintf("%v - %v\n", result.Url, result.Status)
		}
		notification.NotificationQueues["DirScan"].Queue <- NotificationMsg
	}
	ResultQueues["DirScan"].Queue <- interfaceSlice
}

func (h *handler) Vulnerability(result *types.VulnResult) {
	var interfaceSlice interface{}
	rootDomain, err := utils.Tools.GetRootDomain(result.Url)
	if err != nil {
		logger.SlogInfoLocal(fmt.Sprintf("%v GetRootDomain error: %v", result.Url, err))
	}
	result.RootDomain = rootDomain
	if result.Time == "" {
		result.Time = utils.Tools.GetTimeNow()
	}
	result.Project = h.GetAssetProject(rootDomain)
	interfaceSlice = &result
	if global.NotificationConfig.VulNotification {
		NotificationMsg := ""
		if global.NotificationConfig.VulLevel != "" {
			if strings.Contains(strings.ToLower(global.NotificationConfig.VulLevel), strings.ToLower(result.Level)+",") {
				if result.Url != "" {
					NotificationMsg += fmt.Sprintf("%v-[%v]-[%v]-[%v]\n", result.Url, result.Level, result.VulName, result.Matched)
				} else {
					NotificationMsg += fmt.Sprintf("%v-[%v]-[%v]\n", result.Level, result.VulName, result.Matched)
				}
			}
		} else {
			if result.Url != "" {
				NotificationMsg += fmt.Sprintf("%v-[%v]-[%v]-[%v]\n", result.Url, result.Level, result.VulName, result.Matched)
			} else {
				NotificationMsg += fmt.Sprintf("%v-[%v]-[%v]\n", result.Level, result.VulName, result.Matched)
			}
		}
		notification.NotificationQueues["VulnerabilityScan"].Queue <- NotificationMsg
	}
	ResultQueues["VulnerabilityScan"].Queue <- interfaceSlice
}

func (h *handler) PageMonitoringInsert(result *types.PageMonit) {
	var interfaceSlice interface{}
	rootDomain, err := utils.Tools.GetRootDomain(result.Url)
	if err != nil {
		logger.SlogInfoLocal(fmt.Sprintf("%v GetRootDomain error: %v", result.Url, err))
	}
	result.RootDomain = rootDomain
	if result.Time == "" {
		result.Time = utils.Tools.GetTimeNow()
	}
	result.Project = h.GetAssetProject(rootDomain)
	interfaceSlice = &result
	ResultQueues["PageMonitoring"].Queue <- interfaceSlice
}

func (h *handler) PageMonitoringInsertBody(result *types.PageMonitBody) {
	var interfaceSlice interface{}
	interfaceSlice = &result
	ResultQueues["PageMonitoringBody"].Queue <- interfaceSlice
}

func (h *handler) RootDomain(result *types.RootDomain) {
	selector := bson.M{"domain": result.Domain}
	result.Project = h.GetAssetProject(result.Domain)
	if result.Project == "" {
		result.Project = h.GetAssetProject(result.ICP)
	}
	if result.Project == "" {
		result.Project = h.GetAssetProject(result.Company)
	}
	var resultEx types.RootDomain
	err := mongodb.MongodbClient.FindOne("RootDomain", bson.M{"domain": result.Domain}, nil, &resultEx)
	tmpData := bson.M{
		"icp":      result.ICP,
		"tags":     result.Tags,
		"taskName": result.TaskName,
		"project":  result.Project,
		"time":     result.Time,
		"company":  result.Company,
	}
	if err != nil {
		// An error means it does not exist in mongodb; if so, just upsert
		// Notify new root domain
		if global.NotificationConfig.NewAsset {
			tmp := fmt.Sprintf("Found a new root domain name: %v - %v - %v - %v", result.Domain, result.ICP, result.Company, result.Project)
			notification.NotificationQueues["NewAssets"].Queue <- tmp
		}
	} else {
		// mongodb exists in
		// Check whether the domain exists in mongodb; if so, compare icp, company and project, and skip the update if they match
		// If different, update is needed, and the new icp, company and project must not be empty
		if result.ICP == resultEx.ICP && result.Company == resultEx.Company && result.Project == resultEx.Project && utils.Tools.EqualStringSlices(result.Tags, resultEx.Tags) && resultEx.TaskName == result.TaskName {
			return
		}
		if result.ICP == "" {
			tmpData["icp"] = resultEx.ICP
		}
		if result.Company == "" {
			tmpData["company"] = resultEx.Company
		}
		if result.Project == "" {
			tmpData["project"] = resultEx.Project
		}
		tmpData["taskName"] = result.TaskName
		tmpData["tags"] = append(resultEx.Tags, result.Tags...)
	}
	update := bson.M{
		"$set": tmpData,
	}
	op := types.BulkUpdateOperation{
		Selector: selector,
		Update:   update,
	}
	Results.UpdateNow(op, "RootDomain")
	//ResultQueues["RootDomain"].Queue <- op
}

func (h *handler) APP(result *types.APP) {
	result.Project = h.GetAssetProject(result.ICP)
	selector := bson.M{"name": result.Name}
	result.Project = h.GetAssetProject(result.Company)
	if result.Project == "" {
		result.Project = h.GetAssetProject(result.ICP)
	}
	if result.Project == "" {
		result.Project = h.GetAssetProject(result.Company)
	}
	var resultEx types.APP
	tmpData := bson.M{
		"name":        result.Name,
		"version":     result.Version,
		"url":         result.Url,
		"icp":         result.ICP,
		"company":     result.Company,
		"bundleID":    result.BundleID,
		"category":    result.Category,
		"description": result.Description,
		"apk":         result.APK,
		"logo":        result.Logo,
		"tags":        result.Tags,
		"taskName":    result.TaskName,
		"project":     result.Project,
		"time":        result.Time,
	}
	var err error
	if result.Name != "" {
		err = mongodb.MongodbClient.FindOne("app", bson.M{"name": result.Name}, nil, &resultEx)
	} else if result.BundleID != "" {
		err = mongodb.MongodbClient.FindOne("app", bson.M{"bundleID": result.BundleID}, nil, &resultEx)
	}
	if err != nil {
		// An error means it does not exist in mongodb; if so, just upsert
		// Notify new root domain
		if global.NotificationConfig.NewAsset {
			tmp := fmt.Sprintf("Found a new app name: %v - %v - %v - %v", result.Name, result.ICP, result.Company, result.Project)
			notification.NotificationQueues["NewAssets"].Queue <- tmp
		}
	} else {
		if result.ICP == resultEx.ICP && result.Company == resultEx.Company && result.Project == resultEx.Project && resultEx.BundleID == result.BundleID {
			return
		}

		if result.Name == "" {
			tmpData["name"] = resultEx.Name
		}

		if result.Version == "" {
			tmpData["version"] = resultEx.Version
		}

		if result.Url == "" {
			tmpData["url"] = resultEx.Url
		}

		if result.ICP == "" {
			tmpData["icp"] = resultEx.ICP
		}

		if result.Company == "" {
			tmpData["company"] = resultEx.Company
		}

		if result.BundleID == "" {
			tmpData["bundleID"] = resultEx.BundleID
		}

		if result.Category == "" {
			tmpData["category"] = resultEx.Category
		}

		if result.Description == "" {
			tmpData["description"] = resultEx.Description
		}

		if result.APK == "" {
			tmpData["apk"] = resultEx.APK
		}

		if result.Logo == "" {
			tmpData["logo"] = resultEx.Logo
		}

		tmpData["tags"] = append(resultEx.Tags, result.Tags...)

	}
	update := bson.M{
		"$set": tmpData,
	}
	op := types.BulkUpdateOperation{
		Selector: selector,
		Update:   update,
	}
	Results.UpdateNow(op, "app")
}

func (h *handler) MP(result *types.MP) {
	result.Project = h.GetAssetProject(result.ICP)
	selector := bson.M{"name": result.Name}
	result.Project = h.GetAssetProject(result.Company)
	if result.Project == "" {
		result.Project = h.GetAssetProject(result.ICP)
	}
	if result.Project == "" {
		result.Project = h.GetAssetProject(result.Company)
	}
	var resultEx types.MP
	tmpData := bson.M{
		"name":        result.Name,
		"url":         result.Url,
		"icp":         result.ICP,
		"description": result.Description,
		"category":    result.Category,
		"company":     result.Company,
		"tags":        result.Tags,
		"taskName":    result.TaskName,
		"project":     result.Project,
		"time":        result.Time,
	}
	err := mongodb.MongodbClient.FindOne("mp", bson.M{"name": result.Name}, nil, &resultEx)
	if err != nil {
		// An error means it does not exist in mongodb; if so, just upsert
		// Notify new root domain
		if global.NotificationConfig.NewAsset {
			tmp := fmt.Sprintf("Found a new mp name: %v - %v - %v - %v", result.Name, result.ICP, result.Company, result.Project)
			notification.NotificationQueues["NewAssets"].Queue <- tmp
		}
	} else {
		if result.ICP == resultEx.ICP && result.Company == resultEx.Company && result.Project == resultEx.Project {
			return
		}
		if result.Name == "" {
			tmpData["name"] = resultEx.Name
		}

		if result.Url == "" {
			tmpData["url"] = resultEx.Url
		}

		if result.ICP == "" {
			tmpData["icp"] = resultEx.ICP
		}

		if result.Company == "" {
			tmpData["company"] = resultEx.Company
		}

		if result.Category == "" {
			tmpData["category"] = resultEx.Category
		}

		if result.Description == "" {
			tmpData["description"] = resultEx.Description
		}

		tmpData["tags"] = append(resultEx.Tags, result.Tags...)

	}
	update := bson.M{
		"$set": tmpData,
	}
	op := types.BulkUpdateOperation{
		Selector: selector,
		Update:   update,
	}
	Results.UpdateNow(op, "mp")
}

func (h *handler) AddParam(domain string, values []interface{}) (int64, error) {
	if len(values) == 0 {
		return 0, nil
	}

	// SAdd batch add
	addedCount, err := redis.RedisClient.SAdd(context.Background(), fmt.Sprintf("param:%v", domain), values...)
	if err != nil {
		return 0, err
	}

	return addedCount, nil
}

func (h *handler) GetParams(domain string) ([]string, error) {
	// Get all members of the Set with the Redis SMembers command
	values, err := redis.RedisClient.SMembers(context.Background(), fmt.Sprintf("param:%v", domain))
	if err != nil {
		return nil, err
	}
	return values, nil
}
