package consumer

//create AM Policy, this file definitely communicate with PCF, this file will be removed
import (
	"context"
	"fmt"

	//"net/http"

	amf_context "github.com/AhmadRifqi86/lightcore/lightcore/NFs/amf/internal/context"
	//amf_context "github.com/AhmadRifqi86/lightcore/lightcore/amf/internal/context"
	"github.com/AhmadRifqi86/lightcore/lightcore/NFs/amf/internal/logger"
	//"github.com/AhmadRifqi86/lightcore/lightcore/NFs/amf/internal/sbi/misc"
	"github.com/AhmadRifqi86/lightcore/lightcore/NFs/amf/internal/sbi/misc"
	"github.com/AhmadRifqi86/lightcore/lightcore/NFs/amf/pkg/factory"
	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/Npcf_AMPolicy"
	"github.com/free5gc/openapi/models"
	//"github.com/free5gc/util/httpwrapper"
)

//old AMPolicy
// func AMPolicyControlCreate(ue *amf_context.AmfUe, anType models.AccessType) (*models.ProblemDetails, error) {
// 	configuration := Npcf_AMPolicy.NewConfiguration()
// 	configuration.SetBasePath(ue.PcfUri)
// 	client := Npcf_AMPolicy.NewAPIClient(configuration)

// 	amfSelf := amf_context.GetSelf()

// 	policyAssociationRequest := models.PolicyAssociationRequest{
// 		NotificationUri: amfSelf.GetIPv4Uri() + factory.AmfCallbackResUriPrefix + "/am-policy/",
// 		Supi:            ue.Supi,
// 		Pei:             ue.Pei,
// 		Gpsi:            ue.Gpsi,
// 		AccessType:      anType,
// 		ServingPlmn: &models.NetworkId{
// 			Mcc: ue.PlmnId.Mcc,
// 			Mnc: ue.PlmnId.Mnc,
// 		},
// 		Guami: &amfSelf.ServedGuamiList[0],
// 	}

// 	if ue.AccessAndMobilitySubscriptionData != nil {
// 		policyAssociationRequest.Rfsp = ue.AccessAndMobilitySubscriptionData.RfspIndex
// 	}

// 	res, httpResp, localErr := client.DefaultApi.PoliciesPost(context.Background(), policyAssociationRequest)
// 	defer func() {
// 		if httpResp != nil {
// 			if rspCloseErr := httpResp.Body.Close(); rspCloseErr != nil {
// 				logger.ConsumerLog.Errorf("PoliciesPost response body cannot close: %+v",
// 					rspCloseErr)
// 			}
// 		}
// 	}()
// 	if localErr == nil {
// 		locationHeader := httpResp.Header.Get("Location")
// 		logger.ConsumerLog.Debugf("location header: %+v", locationHeader)
// 		ue.AmPolicyUri = locationHeader

// 		re := regexp.MustCompile("/policies/.*")
// 		match := re.FindStringSubmatch(locationHeader)

// 		ue.PolicyAssociationId = match[0][10:]
// 		ue.AmPolicyAssociation = &res

// 		if res.Triggers != nil {
// 			for _, trigger := range res.Triggers {
// 				if trigger == models.RequestTrigger_LOC_CH {
// 					ue.RequestTriggerLocationChange = true
// 				}
// 				//if trigger == models.RequestTrigger_PRA_CH {
// 				// TODO: Presence Reporting Area handling (TS 23.503 6.1.2.5, TS 23.501 5.6.11)
// 				//}
// 			}
// 		}

// 			logger.ConsumerLog.Debugf("UE AM Policy Association ID: %s", ue.PolicyAssociationId)
// 			logger.ConsumerLog.Debugf("AmPolicyAssociation: %+v", ue.AmPolicyAssociation)
// 		} else if httpResp != nil {
// 			if httpResp.Status != localErr.Error() {
// 				return nil, localErr
// 			}
// 			problem := localErr.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails)
// 			return &problem, nil
// 		} else {
// 			return nil, openapi.ReportError("server no response")
// 		}
// 		return nil, nil
// 	}

// Create AMPolicy
func AMPolicyControlCreate(ue *amf_context.AmfUe, anType models.AccessType) (*models.ProblemDetails, error) {
	amfSelf := amf_context.GetSelf()
	fmt.Println("AM POLICY CREATE REQUEST")
	policyAssociationRequest := models.PolicyAssociationRequest{
		NotificationUri: amfSelf.GetIPv4Uri() + factory.AmfCallbackResUriPrefix + "/am-policy/",
		Supi:            ue.Supi,
		Pei:             ue.Pei,
		Gpsi:            ue.Gpsi,
		AccessType:      anType,
		ServingPlmn: &models.NetworkId{
			Mcc: ue.PlmnId.Mcc,
			Mnc: ue.PlmnId.Mnc,
		},
		Guami: &amfSelf.ServedGuamiList[0],
	}

	if ue.AccessAndMobilitySubscriptionData != nil {
		policyAssociationRequest.Rfsp = ue.AccessAndMobilitySubscriptionData.RfspIndex
	}
	fmt.Println("CALL postPoliciesProcedure")
	// Simulate PostPoliciesProcedure logic locally
	response, locationHeader, problemDetails := amfSelf.PostPoliciesProcedure("", policyAssociationRequest)
	fmt.Println("Response")
	fmt.Println(response)
	fmt.Println("locationHeader")
	fmt.Println(locationHeader) //harus mengandung /policies/imsi-
	fmt.Println("problemDetails")
	fmt.Println(problemDetails)
	if response != nil {
		//ue.AmPolicyUri = locationHeader
		// fmt.Println("CREATE REGEX")
		// re := regexp.MustCompile("/policies/.*")
		// match := re.FindStringSubmatch(locationHeader)
		fmt.Println("PUT RESPONSE TO UE CONTEXT")
		//ue.PolicyAssociationId = match[0][10:]
		ue.PolicyAssociationId = locationHeader
		fmt.Println("MATCH REGEX")

		ue.AmPolicyAssociation = response
		fmt.Println("CHECKING RESPONSE.TRIGGERS")
		if response.Triggers != nil {
			for _, trigger := range response.Triggers {
				if trigger == models.RequestTrigger_LOC_CH {
					ue.RequestTriggerLocationChange = true
				}
				//if trigger == models.RequestTrigger_PRA_CH {
				// TODO: Presence Reporting Area handling (TS 23.503 6.1.2.5, TS 23.501 5.6.11)
				//}
			}
		}
		fmt.Println("PRINT POLICY ASSIC ID TO LOG")
		logger.ConsumerLog.Debugf("UE AM Policy Association ID: %s", ue.PolicyAssociationId)
		logger.ConsumerLog.Debugf("AmPolicyAssociation: %+v", ue.AmPolicyAssociation)
	} else if problemDetails != nil {
		return problemDetails, nil
	} else {
		return nil, fmt.Errorf("unknown error")
	}

	return nil, nil
}

// AM Policy Update
func AMPolicyControlUpdate(ue *amf_context.AmfUe, updateRequest models.PolicyAssociationUpdateRequest) (
	problemDetails *models.ProblemDetails, err error,
) {
	configuration := Npcf_AMPolicy.NewConfiguration()
	configuration.SetBasePath(ue.PcfUri)
	client := Npcf_AMPolicy.NewAPIClient(configuration)

	res, httpResp, localErr := client.DefaultApi.PoliciesPolAssoIdUpdatePost(
		context.Background(), ue.PolicyAssociationId, updateRequest)
	defer func() {
		if httpResp != nil {
			if rspCloseErr := httpResp.Body.Close(); rspCloseErr != nil {
				logger.ConsumerLog.Errorf("PoliciesPolAssoIdUpdatePost response body cannot close: %+v",
					rspCloseErr)
			}
		}
	}()
	if localErr == nil {
		if res.ServAreaRes != nil {
			ue.AmPolicyAssociation.ServAreaRes = res.ServAreaRes
		}
		if res.Rfsp != 0 {
			ue.AmPolicyAssociation.Rfsp = res.Rfsp
		}
		ue.AmPolicyAssociation.Triggers = res.Triggers
		ue.RequestTriggerLocationChange = false
		for _, trigger := range res.Triggers {
			if trigger == models.RequestTrigger_LOC_CH {
				ue.RequestTriggerLocationChange = true
			}
			// if trigger == models.RequestTrigger_PRA_CH {
			// TODO: Presence Reporting Area handling (TS 23.503 6.1.2.5, TS 23.501 5.6.11)
			// }
		}
		return
	} else if httpResp != nil {
		if httpResp.Status != localErr.Error() {
			err = localErr
			return
		}
		problem := localErr.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails)
		problemDetails = &problem
	} else {
		err = openapi.ReportError("server no response")
	}
	return problemDetails, err
}

// AMPolicy Delete
func AMPolicyControlDelete(ue *amf_context.AmfUe) (problemDetails *models.ProblemDetails, err error) {
	configuration := Npcf_AMPolicy.NewConfiguration()
	configuration.SetBasePath(ue.PcfUri)
	client := Npcf_AMPolicy.NewAPIClient(configuration)

	httpResp, localErr := client.DefaultApi.PoliciesPolAssoIdDelete(context.Background(), ue.PolicyAssociationId)
	defer func() {
		if httpResp != nil {
			if rspCloseErr := httpResp.Body.Close(); rspCloseErr != nil {
				logger.ConsumerLog.Errorf("PoliciesPolAssoIdDelete response body cannot close: %+v",
					rspCloseErr)
			}
		}
	}()
	if localErr == nil {
		ue.RemoveAmPolicyAssociation()
	} else if httpResp != nil {
		if httpResp.Status != localErr.Error() {
			err = localErr
			return
		}
		problem := localErr.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails)
		problemDetails = &problem
	} else {
		err = openapi.ReportError("server no response")
	}

	return
}
