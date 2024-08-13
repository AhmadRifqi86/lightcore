package context

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/mohae/deepcopy"
	"go.mongodb.org/mongo-driver/bson"

	"github.com/AhmadRifqi86/lightcore/lightcore/NFs/amf/internal/logger"
	//"github.com/AhmadRifqi86/lightcore/lightcore/NFs/amf/internal/sbi/misc"

	//"github.com/AhmadRifqi86/lightcore/lightcore/NFs/amf/internal/util"

	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/util/mongoapi"
)

func PostPoliciesProcedure(polAssoId string,
	policyAssociationRequest models.PolicyAssociationRequest,
) (*models.PolicyAssociation, string, *models.ProblemDetails) {
	fmt.Println("polAssoId is")
	fmt.Println(polAssoId)
	var response models.PolicyAssociation
	pcfSelf := GetSelf() //return AMFContext
	var ue *UeContext
	if val, ok := pcfSelf.pcfUePool.Load(policyAssociationRequest.Supi); ok {
		ue = val.(*UeContext)
	}
	fmt.Println("CREATE NEW UE")
	if ue == nil {
		if newUe, err := pcfSelf.NewPCFUe(policyAssociationRequest.Supi); err != nil {
			// supi format dose not match "imsi-..."
			problemDetail := GetProblemDetail("Supi Format Error", ERROR_REQUEST_PARAMETERS)
			logger.AmPolicyLog.Errorln(err.Error())
			return nil, "", &problemDetail
		} else {
			ue = newUe
		}
	}
	fmt.Println("GET UDR URI")
	udrUri := getUdrUri(ue)
	if udrUri == "" {
		// Can't find any UDR support this Ue
		pcfSelf.pcfUePool.Delete(ue.Supi)
		problemDetail := GetProblemDetail("Ue is not supported in PCF", USER_UNKNOWN)
		logger.AmPolicyLog.Errorf("Ue[%s] is not supported in PCF", ue.Supi)
		return nil, "", &problemDetail
	}
	ue.UdrUri = udrUri

	response.Request = deepcopy.Copy(&policyAssociationRequest).(*models.PolicyAssociationRequest)
	assolId := fmt.Sprintf("%s-%d", ue.Supi, ue.PolAssociationIDGenerator)
	fmt.Println("AssolId is")
	fmt.Println(assolId)
	amPolicy := ue.AMPolicyData[assolId]

	if amPolicy == nil || amPolicy.AmPolicyData == nil {
		fmt.Println("amPolicy is nil")
		collName := "policyData.ues.amData"
		filter := bson.M{"ueId": ue.Supi}
		data, problemDetail := getDataFromDB(collName, filter)
		fmt.Println("Data From DB (OK)")
		fmt.Println(data)
		if problemDetail != nil {
			logger.AmPolicyLog.Errorf("Can't find UE[%s] AM Policy Data in UDR", ue.Supi)
			return nil, "", problemDetail
		}

		// Konversi dari *map[string]interface{} ke *models.AmPolicyData
		//Conversion from *map[string]interface{} to *models.AmPolicyData, the error probably occur from here if DB okay
		jsonData, err := json.Marshal(data)
		if err != nil {
			pd := GetProblemDetail("Error marshalling data", SYSTEM_FAILURE)
			logger.AmPolicyLog.Errorf("Error marshalling data: %+v", err)
			return nil, "", &pd
		}
		fmt.Println("Parsing Data From DB")
		var amData models.AmPolicyData
		err = json.Unmarshal(jsonData, &amData)
		if err != nil {
			pd := GetProblemDetail("Error unmarshalling data", SYSTEM_FAILURE)
			logger.AmPolicyLog.Errorf("Error unmarshalling data: %+v", err)
			return nil, "", &pd
		}

		if amPolicy == nil {
			amPolicy = ue.NewUeAMPolicyData(assolId, policyAssociationRequest)
			amPolicy.SuppFeat = "3fff"
		}
		// fmt.Println("amData")
		// fmt.Println(amData)
		amPolicy.AmPolicyData = &amData
	}

	// TODO: according to PCF Policy to determine ServAreaRes, Rfsp, SuppFeat
	// amPolicy.ServAreaRes =
	// amPolicy.Rfsp =
	// fmt.Println("ASSIGN SUPPFEAT 1")
	// fmt.Println(policyAssociationRequest.SuppFeat)
	var requestSuppFeat openapi.SupportedFeature //pas disini policyAssociationRequest.SuppFeat masih nil
	//policyAssociationRequest.SuppFeat = "ffff"
	if suppFeat, err := openapi.NewSupportedFeature(policyAssociationRequest.SuppFeat); err != nil {
		logger.AmPolicyLog.Warnln(err)
	} else {
		requestSuppFeat = suppFeat
	}
	fmt.Println("ASSIGN SUPPFEAT 1") //opsi satu, assign suppFeat di sini, secara static
	amPolicy.SuppFeat = pcfSelf.PcfSuppFeats[models.ServiceName_NPCF_AM_POLICY_CONTROL].NegotiateWith(requestSuppFeat).String()
	if amPolicy.Rfsp != 0 {
		response.Rfsp = amPolicy.Rfsp
	}
	response.SuppFeat = amPolicy.SuppFeat
	fmt.Println(response.SuppFeat)
	// TODO: add Reports
	// rsp.Triggers
	// rsp.Pras
	fmt.Println("INCREMENT ID GENERATOR")
	ue.PolAssociationIDGenerator++
	logger.AmPolicyLog.Tracef("AMPolicy association Id[%s] Create", assolId)

	fmt.Println("OUT FROM POSTPROCEDURE")
	fmt.Println(assolId)
	fmt.Println("ASSIGN SUPPFEAT 2")
	fmt.Println(amPolicy.SuppFeat)
	return &response, assolId, nil
}

func getUdrUri(ue *UeContext) string {
	if ue.UdrUri != "" {
		return ue.UdrUri
	}
	return SendNFInstancesUDR(GetSelf().NrfUri, ue.Supi)
}

//Getter to return amPolicy.SuppFeat
// func GetSuppFeat(ue *UeContext, polAssoId string) string{
// 	return
// }

func getDataFromDB(collName string, filter bson.M) (map[string]interface{}, *models.ProblemDetails) {
	fmt.Println("try getting data from DB")
	data, err := mongoapi.RestfulAPIGetOne(collName, filter)
	fmt.Println("getting data from DB OK") //bahkan masuk sini pun engga
	if err != nil {
		fmt.Println("err is not nil")
		return nil, openapi.ProblemDetailsSystemFailure(err.Error())
	}
	if data == nil {
		fmt.Println("data not found")
		return nil, ProblemDetailsNotFound("DATA_NOT_FOUND")
	}
	fmt.Println("DB content from getDataFromDB")
	fmt.Println(data)
	return data, nil
}

func ProblemDetailsNotFound(cause string) *models.ProblemDetails {
	title := ""
	if cause == "USER_NOT_FOUND" {
		title = "User not found"
	} else if cause == "SUBSCRIPTION_NOT_FOUND" {
		title = "Subscription not found"
	} else if cause == "AMFSUBSCRIPTION_NOT_FOUND" {
		title = "AMF Subscription not found"
	} else {
		title = "Data not found"
	}
	return &models.ProblemDetails{
		Title:  title,
		Status: http.StatusNotFound,
		Cause:  cause,
	}
}
