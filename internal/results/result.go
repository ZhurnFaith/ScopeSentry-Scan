// results-------------------------------------
// @file      : result.go
// @author    : Autumn
// @contact   : rainy-autumn@outlook.com
// @time      : 2024/9/17 21:12
// -------------------------------------------

package results

import (
	"errors"
	"fmt"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/mongodb"
	"github.com/ZhurnFaith/ScopeSentry-Scan/internal/types"
	"github.com/ZhurnFaith/ScopeSentry-Scan/pkg/logger"
	"github.com/ZhurnFaith/ScopeSentry-Scan/pkg/utils"
	"go.mongodb.org/mongo-driver/mongo"
	"reflect"
)

type result struct {
}

var Results *result

func InitializeResults() {
	Results = &result{}
}

//func (r *result) Subdoamin(result *[]interface{}) bool {
//	_, err := mongodb.MongodbClient.InsertMany("subdomain", *result)
//	if err != nil {
//		logger.SlogError(fmt.Sprintf("SubdoaminResult error: %s", err))
//		return false
//	}
//	return true
//}

func (r *result) Insert(name string, result *[]interface{}) bool {
	_, err := mongodb.MongodbClient.InsertMany(name, *result)
	if err != nil {
		var writeException mongo.WriteException
		if errors.As(err, &writeException) {
			if name == "PageMonitoring" || name == "PageMonitoringBody" {
				for _, wErr := range writeException.WriteErrors {
					logger.SlogWarnLocal(fmt.Sprintf("Failed to insert document: %v, error: %v\n", wErr))
				}
			}
		}
		logger.SlogWarnLocal(fmt.Sprintf("insert %v error: %s", name, err))
		return false
	}
	return true
}

func (r *result) Update(result *[]interface{}, name string) bool {
	// Will *[]interface{} convert to []types.BulkUpdateOperation
	var operations []mongo.WriteModel

	// Iterate over the passed result, type assert each and build WriteModel
	for _, item := range *result {
		// Type assertion converts item to types.BulkUpdateOperation
		op, ok := item.(types.BulkUpdateOperation)
		if !ok {
			fmt.Println("Type assertion failed: item is not of type types.BulkUpdateOperation")
			return false
		}

		// Convert BulkUpdateOperation into mongo.UpdateOneModel and add it to operations
		updateModel := mongo.NewUpdateOneModel().
			SetFilter(op.Selector).
			SetUpdate(op.Update).
			SetUpsert(true) // Set Upsert to true so a new document is inserted when none matches

		operations = append(operations, updateModel)
	}
	// Call BulkWrite for batch write or update operations
	_, err := mongodb.MongodbClient.BulkWrite(name, operations)
	if err != nil {
		fmt.Println("Error during bulk write:", err)
		return false
	}
	return true
}

func (r *result) UpdateNow(op types.BulkUpdateOperation, name string) bool {
	// Will *[]interface{} convert to []types.BulkUpdateOperation
	var operations []mongo.WriteModel

	// Convert BulkUpdateOperation into mongo.UpdateOneModel and add it to operations
	updateModel := mongo.NewUpdateOneModel().
		SetFilter(op.Selector).
		SetUpdate(op.Update).
		SetUpsert(true) // Set Upsert to true so a new document is inserted when none matches

	operations = append(operations, updateModel)
	// Call BulkWrite for batch write or update operations
	_, err := mongodb.MongodbClient.BulkWrite(name, operations)
	if err != nil {
		fmt.Println("Error during bulk write:", err)
		return false
	}
	return true
}

func (r *result) InsertVulnerabilityScan(result *[]interface{}) {
	var newVulnResults []interface{}
	var vulDetails []interface{}

	for _, v := range *result {
		var vulnResult *types.VulnResult

		// Option 1: *types.VulnResult
		if vr, ok := v.(*types.VulnResult); ok {
			vulnResult = vr
		}

		// Option 2: **types.VulnResult
		if vrPtr, ok := v.(**types.VulnResult); ok && vrPtr != nil {
			vulnResult = *vrPtr
		}

		if vulnResult == nil {
			fmt.Println("Type assertion failed:", reflect.TypeOf(v))
			continue
		}

		// Generate unique Hash
		vulnResult.Hash = utils.Tools.GenerateRandomString(16)

		// Save details
		vulDetails = append(vulDetails, types.VulnerabilityDetail{
			Hash:     vulnResult.Hash,
			Request:  vulnResult.Request,
			Response: vulnResult.Response,
		})

		// Clear request and response
		vulnResult.Request = ""
		vulnResult.Response = ""

		// Put back new result set
		newVulnResults = append(newVulnResults, vulnResult)
	}

	// Write to database
	r.Insert("vulnerability", &newVulnResults)
	r.Insert("vulnerabilityDetail", &vulDetails)
}
