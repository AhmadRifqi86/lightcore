package context

// import (
// 	"context"
// 	"net/http"

// 	"github.com/antihax/optional"

// 	"github.com/free5gc/openapi"
// 	Nudr "github.com/free5gc/openapi/Nudr_DataRepository"
// 	"github.com/free5gc/openapi/models"
// 	"github.com/free5gc/smf/internal/logger"
// )

// func GetSmDataProcedure(supi string, plmnID string, Dnn string, Snssai string, supportedFeatures string) (
// 	response interface{}, problemDetails *models.ProblemDetails,
// ) {
// 	logger.SdmLog.Infof("getSmDataProcedure: SUPI[%s] PLMNID[%s] DNN[%s] SNssai[%s]", supi, plmnID, Dnn, Snssai)

// 	clientAPI, err := createUDMClientToUDR(supi)
// 	if err != nil {
// 		return nil, openapi.ProblemDetailsSystemFailure(err.Error())
// 	}

// 	var querySmDataParamOpts Nudr.QuerySmDataParamOpts
// 	querySmDataParamOpts.SingleNssai = optional.NewInterface(Snssai)

// 	sessionManagementSubscriptionDataResp, res, err := clientAPI.SessionManagementSubscriptionDataApi.
// 		QuerySmData(context.Background(), supi, plmnID, &querySmDataParamOpts)
// 	if err != nil {
// 		if res == nil {
// 			logger.SdmLog.Warnln(err)
// 		} else if err.Error() != res.Status {
// 			logger.SdmLog.Warnln(err)
// 		} else {
// 			logger.SdmLog.Warnln(err)
// 			problemDetails = &models.ProblemDetails{
// 				Status: int32(res.StatusCode),
// 				Cause:  err.(openapi.GenericOpenAPIError).Model().(models.ProblemDetails).Cause,
// 				Detail: err.Error(),
// 			}

// 			return nil, problemDetails
// 		}
// 	}
// 	defer func() {
// 		if rspCloseErr := res.Body.Close(); rspCloseErr != nil {
// 			logger.SdmLog.Errorf("QuerySmData response body cannot close: %+v", rspCloseErr)
// 		}
// 	}()

// 	if res.StatusCode == http.StatusOK {
// 		udmUe, ok := GetSelf().UdmUeFindBySupi(supi)
// 		if !ok {
// 			udmUe = GetSelf().NewUdmUe(supi)
// 		}
// 		smData, snssaikey, AllDnnConfigsbyDnn, AllDnns := udm_context.Getself().ManageSmData(
// 			sessionManagementSubscriptionDataResp, Snssai, Dnn)
// 		udmUe.SetSMSubsData(smData)

// 		rspSMSubDataList := make([]models.SessionManagementSubscriptionData, 0, 4)

// 		udmUe.SmSubsDataLock.RLock()
// 		for _, eachSMSubData := range udmUe.SessionManagementSubsData {
// 			rspSMSubDataList = append(rspSMSubDataList, eachSMSubData)
// 		}
// 		udmUe.SmSubsDataLock.RUnlock()

// 		switch {
// 		case Snssai == "" && Dnn == "":
// 			return AllDnns, nil
// 		case Snssai != "" && Dnn == "":
// 			udmUe.SmSubsDataLock.RLock()
// 			defer udmUe.SmSubsDataLock.RUnlock()
// 			return udmUe.SessionManagementSubsData[snssaikey].DnnConfigurations, nil
// 		case Snssai == "" && Dnn != "":
// 			return AllDnnConfigsbyDnn, nil
// 		case Snssai != "" && Dnn != "":
// 			return rspSMSubDataList, nil
// 		default:
// 			udmUe.SmSubsDataLock.RLock()
// 			defer udmUe.SmSubsDataLock.RUnlock()
// 			return udmUe.SessionManagementSubsData, nil
// 		}
// 	} else {
// 		problemDetails = &models.ProblemDetails{
// 			Status: http.StatusNotFound,
// 			Cause:  "DATA_NOT_FOUND",
// 		}

// 		return nil, problemDetails
// 	}
// }
