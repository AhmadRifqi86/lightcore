package misc

import (
	"context"
	"fmt"
	"net/http"
	"reflect"

	"github.com/mohae/deepcopy"

	pcf_context "github.com/free5gc/amf/internal/context"
	"github.com/free5gc/amf/internal/logger"

	//"github.com/free5gc/amf/internal/logger"
	//	"github.com/free5gc/amf/internal/sbi/consumer"
	"github.com/free5gc/amf/internal/util"
	"github.com/free5gc/amf/pkg/factory"
	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	//"github.com/free5gc/pcf/internal/util"
	//	"github.com/free5gc/util/httpwrapper"
)

// polAssoId di PCF dibuat di mana ya? apakah di respons atau di request?
// func PostPoliciesProcedure(polAssoId string,
// 	policyAssociationRequest models.PolicyAssociationRequest,
// ) (*models.PolicyAssociation, string, *models.ProblemDetails) {
// 	fmt.Println("polAssoId is")
// 	fmt.Println(polAssoId) //harusnya print nothing
// 	var response models.PolicyAssociation
// 	pcfSelf := pcf_context.GetSelf()
// 	var ue *pcf_context.UeContext
// 	if val, ok := pcfSelf.UePool.Load(policyAssociationRequest.Supi); ok {
// 		ue = val.(*pcf_context.UeContext)
// 	}
// 	if ue == nil {
// 		if newUe, err := pcfSelf.NewPCFUe(policyAssociationRequest.Supi); err != nil {
// 			// supi format dose not match "imsi-..."
// 			problemDetail := util.GetProblemDetail("Supi Format Error", util.ERROR_REQUEST_PARAMETERS)
// 			logger.AmPolicyLog.Errorln(err.Error())
// 			return nil, "", &problemDetail
// 		} else {
// 			ue = newUe
// 		}
// 	}
// 	fmt.Println("get UDR URI")
// 	udrUri := getUdrUri(ue)
// 	if udrUri == "" {
// 		// Can't find any UDR support this Ue
// 		pcfSelf.UePool.Delete(ue.Supi)
// 		problemDetail := util.GetProblemDetail("Ue is not supported in PCF", util.USER_UNKNOWN)
// 		logger.AmPolicyLog.Errorf("Ue[%s] is not supported in PCF", ue.Supi)
// 		return nil, "", &problemDetail
// 	}
// 	ue.UdrUri = udrUri //is this needed
// 	fmt.Println("Put Policy Data to Context")
// 	response.Request = deepcopy.Copy(&policyAssociationRequest).(*models.PolicyAssociationRequest)
// 	assolId := fmt.Sprintf("%s-%d", ue.Supi, ue.PolAssociationIDGenerator)
// 	amPolicy := ue.AMPolicyData[assolId]

// 	if amPolicy == nil || amPolicy.AmPolicyData == nil {
// 		client := util.GetNudrClient(udrUri)
// 		var response *http.Response
// 		amData, response, err := client.DefaultApi.PolicyDataUesUeIdAmDataGet(context.Background(), ue.Supi)
// 		if err != nil || response == nil || response.StatusCode != http.StatusOK {
// 			problemDetail := util.GetProblemDetail("Can't find UE AM Policy Data in UDR", util.USER_UNKNOWN)
// 			logger.AmPolicyLog.Errorf("Can't find UE[%s] AM Policy Data in UDR", ue.Supi)
// 			return nil, "", &problemDetail
// 		}
// 		defer func() {
// 			if rspCloseErr := response.Body.Close(); rspCloseErr != nil {
// 				logger.AmPolicyLog.Errorf("PolicyDataUesUeIdAmDataGet response cannot close: %+v", rspCloseErr)
// 			}
// 		}()
// 		if amPolicy == nil {
// 			amPolicy = ue.NewUeAMPolicyData(assolId, policyAssociationRequest)
// 		}
// 		amPolicy.AmPolicyData = &amData
// 	}

// 	// TODO: according to PCF Policy to determine ServAreaRes, Rfsp, SuppFeat
// 	// amPolicy.ServAreaRes =
// 	// amPolicy.Rfsp =
// 	var requestSuppFeat openapi.SupportedFeature
// 	if suppFeat, err := openapi.NewSupportedFeature(policyAssociationRequest.SuppFeat); err != nil {
// 		logger.AmPolicyLog.Warnln(err)
// 	} else {
// 		requestSuppFeat = suppFeat
// 	}
// 	amPolicy.SuppFeat = pcfSelf.PcfSuppFeats[models.ServiceName_NPCF_AM_POLICY_CONTROL].NegotiateWith(requestSuppFeat).String()
// 	if amPolicy.Rfsp != 0 {
// 		response.Rfsp = amPolicy.Rfsp
// 	}
// 	response.SuppFeat = amPolicy.SuppFeat
// 	// TODO: add Reports
// 	// rsp.Triggers
// 	// rsp.Pras
// 	ue.PolAssociationIDGenerator++
// 	// Create location header for update, delete, get
// 	locationHeader := util.GetResourceUri(models.ServiceName_NPCF_AM_POLICY_CONTROL, assolId)
// 	logger.AmPolicyLog.Tracef("AMPolicy association Id[%s] Create", assolId)

// 	// if consumer is AMF then subscribe this AMF Status, block if ini perlu di comment ga?
// 	if policyAssociationRequest.Guami != nil {
// 		// if policyAssociationRequest.Guami has been subscribed, then no need to subscribe again
// 		needSubscribe := true
// 		pcfSelf.AMFStatusSubsData.Range(func(key, value interface{}) bool {
// 			data := value.(pcf_context.AMFStatusSubscriptionData)
// 			for _, guami := range data.GuamiList {
// 				if reflect.DeepEqual(guami, *policyAssociationRequest.Guami) {
// 					needSubscribe = false
// 					break
// 				}
// 			}
// 			// if no need to subscribe => stop iteration
// 			return needSubscribe
// 		})
// 		//need to resolve this
// 		if needSubscribe {
// 			logger.AmPolicyLog.Debugf("Subscribe AMF status change[GUAMI: %+v]", *policyAssociationRequest.Guami)
// 			//how to get URI
// 			fmt.Println("Calling AMFStatusChangeSubscribeProcedure")
// 			//how is this data under AMF
// 			subscriptionDataReq := models.SubscriptionData{
// 				AmfStatusUri: fmt.Sprintf("%s"+factory.AmfCallbackResUriPrefix+"/amfstatus", pcfSelf.GetIPv4Uri()),
// 				GuamiList:    pcf_context.AMFStatusSubscriptionData.GuamiList,
// 			}
// 			subscriptionDataRsp, locationHeader, problemDetails := AMFStatusChangeSubscribeProcedure(subscriptionDataReq)
// 			// amfUri := consumer.SendNFInstancesAMF(pcfSelf.NrfUri, *policyAssociationRequest.Guami, models.ServiceName_NAMF_COMM)
// 			// if amfUri != "" {
// 			// 	problemDetails, err := consumer.AmfStatusChangeSubscribe(amfUri, []models.Guami{*policyAssociationRequest.Guami})
// 			// 	if err != nil {
// 			// 		logger.AmPolicyLog.Errorf("Subscribe AMF status change error[%+v]", err)
// 			// 	} else if problemDetails != nil {
// 			// 		logger.AmPolicyLog.Errorf("Subscribe AMF status change failed[%+v]", problemDetails)
// 			// 	} else {
// 			// 		amPolicy.Guami = policyAssociationRequest.Guami
// 			// 	}
// 			// }
// 		} else {
// 			logger.AmPolicyLog.Debugf("AMF status[GUAMI: %+v] has been subscribed", *policyAssociationRequest.Guami)
// 		}
// 	}
// 	return &response, locationHeader, nil
// }

func PostPoliciesProcedure(polAssoId string,
	policyAssociationRequest models.PolicyAssociationRequest,
) (*models.PolicyAssociation, string, *models.ProblemDetails) {
	var response models.PolicyAssociation
	pcfSelf := pcf_context.GetSelf()
	var ue *pcf_context.UeContext
	if val, ok := pcfSelf.UePool.Load(policyAssociationRequest.Supi); ok {
		ue = val.(*pcf_context.UeContext)
	}
	fmt.Println("CREATE NEW UE")
	if ue == nil {
		if newUe, err := pcfSelf.NewPCFUe(policyAssociationRequest.Supi); err != nil {
			// supi format dose not match "imsi-..."
			problemDetail := util.GetProblemDetail("Supi Format Error", util.ERROR_REQUEST_PARAMETERS)
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
		pcfSelf.UePool.Delete(ue.Supi)
		problemDetail := util.GetProblemDetail("Ue is not supported in PCF", util.USER_UNKNOWN)
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
		client := util.GetNudrClient(udrUri)
		var response *http.Response
		amData, response, err := client.DefaultApi.PolicyDataUesUeIdAmDataGet(context.Background(), ue.Supi)
		if err != nil || response == nil || response.StatusCode != http.StatusOK {
			problemDetail := util.GetProblemDetail("Can't find UE AM Policy Data in UDR", util.USER_UNKNOWN)
			logger.AmPolicyLog.Errorf("Can't find UE[%s] AM Policy Data in UDR", ue.Supi)
			return nil, "", &problemDetail
		}
		defer func() {
			if rspCloseErr := response.Body.Close(); rspCloseErr != nil {
				logger.AmPolicyLog.Errorf("PolicyDataUesUeIdAmDataGet response cannot close: %+v", rspCloseErr)
			}
		}()
		if amPolicy == nil {
			amPolicy = ue.NewUeAMPolicyData(assolId, policyAssociationRequest)
		}
		amPolicy.AmPolicyData = &amData
	}

	// TODO: according to PCF Policy to determine ServAreaRes, Rfsp, SuppFeat
	// amPolicy.ServAreaRes =
	// amPolicy.Rfsp =
	var requestSuppFeat openapi.SupportedFeature
	if suppFeat, err := openapi.NewSupportedFeature(policyAssociationRequest.SuppFeat); err != nil {
		logger.AmPolicyLog.Warnln(err)
	} else {
		requestSuppFeat = suppFeat
	}
	fmt.Println("ASSIGN SUPPFEAT")
	amPolicy.SuppFeat = pcfSelf.PcfSuppFeats[models.ServiceName_NPCF_AM_POLICY_CONTROL].NegotiateWith(requestSuppFeat).String()
	if amPolicy.Rfsp != 0 {
		response.Rfsp = amPolicy.Rfsp
	}
	response.SuppFeat = amPolicy.SuppFeat
	// TODO: add Reports
	// rsp.Triggers
	// rsp.Pras
	fmt.Println("INCREMENT ID GENERATOR")
	ue.PolAssociationIDGenerator++
	// Create location header for update, delete, get
	locationHeader := util.GetResourceUri(models.ServiceName_NPCF_AM_POLICY_CONTROL, assolId)
	fmt.Println("CREATE LOCATION HEADER")
	fmt.Println(locationHeader)
	logger.AmPolicyLog.Tracef("AMPolicy association Id[%s] Create", assolId)

	// if consumer is AMF then subscribe this AMF Status
	fmt.Println("ASSIGN needSubscribe")
	if policyAssociationRequest.Guami != nil {
		// if policyAssociationRequest.Guami has been subscribed, then no need to subscribe again
		needSubscribe := true
		pcfSelf.AMFStatusSubsData.Range(func(key, value interface{}) bool {
			data := value.(pcf_context.AMFStatusSubscriptionData)
			for _, guami := range data.GuamiList {
				if reflect.DeepEqual(guami, *policyAssociationRequest.Guami) {
					needSubscribe = false
					break
				}
			}
			// if no need to subscribe => stop iteration
			return needSubscribe
		})

		if needSubscribe {
			logger.AmPolicyLog.Debugf("Subscribe AMF status change[GUAMI: %+v]", *policyAssociationRequest.Guami)

			// Implement AMFStatusChangeSubscribeProcedure logic here
			amfSelf := pcf_context.GetSelf()
			subscriptionDataReq := models.SubscriptionData{
				GuamiList:    []models.Guami{*policyAssociationRequest.Guami},
				AmfStatusUri: fmt.Sprintf("%s"+factory.AmfCallbackResUriPrefix+"/amfstatus", pcfSelf.GetIPv4Uri()), // You need to set this properly
			}

			var subscriptionDataRsp models.SubscriptionData
			for _, guami := range subscriptionDataReq.GuamiList {
				for _, servedGuami := range amfSelf.ServedGuamiList {
					if reflect.DeepEqual(guami, servedGuami) {
						// AMF status is available
						subscriptionDataRsp.GuamiList = append(subscriptionDataRsp.GuamiList, guami)
					}
				}
			}

			if subscriptionDataRsp.GuamiList != nil {
				newSubscriptionID := amfSelf.NewAMFStatusSubscription(subscriptionDataReq)
				//locationHeader = subscriptionDataReq.AmfStatusUri + "/" + newSubscriptionID
				logger.CommLog.Infof("new AMF Status Subscription[%s]", newSubscriptionID)
				amPolicy.Guami = policyAssociationRequest.Guami
			} else {
				problemDetail := &models.ProblemDetails{
					Status: http.StatusForbidden,
					Cause:  "UNSPECIFIED",
				}
				return nil, "", problemDetail
			}
		} else {
			logger.AmPolicyLog.Debugf("AMF status[GUAMI: %+v] has been subscribed", *policyAssociationRequest.Guami)
		}
	}
	fmt.Println("OUT FROM POSTPROCEDURE")
	fmt.Println(locationHeader)
	return &response, locationHeader, nil
}

func getUdrUri(ue *pcf_context.UeContext) string {
	if ue.UdrUri != "" {
		return ue.UdrUri
	}
	return SendNFInstancesUDR(pcf_context.GetSelf().NrfUri, ue.Supi)
}

func AMFStatusChangeSubscribeProcedure(subscriptionDataReq models.SubscriptionData) (
	subscriptionDataRsp models.SubscriptionData, locationHeader string, problemDetails *models.ProblemDetails,
) {
	amfSelf := pcf_context.GetSelf()

	for _, guami := range subscriptionDataReq.GuamiList {
		for _, servedGumi := range amfSelf.ServedGuamiList {
			if reflect.DeepEqual(guami, servedGumi) {
				// AMF status is available
				subscriptionDataRsp.GuamiList = append(subscriptionDataRsp.GuamiList, guami)
			}
		}
	}
	fmt.Println("NEW AMF STATUS SUBSCRIPTION")
	if subscriptionDataRsp.GuamiList != nil {
		newSubscriptionID := amfSelf.NewAMFStatusSubscription(subscriptionDataReq)
		locationHeader = subscriptionDataReq.AmfStatusUri + "/" + newSubscriptionID
		logger.CommLog.Infof("new AMF Status Subscription[%s]", newSubscriptionID)
		return
	} else {
		problemDetails = &models.ProblemDetails{
			Status: http.StatusForbidden,
			Cause:  "UNSPECIFIED",
		}
		return
	}
}
