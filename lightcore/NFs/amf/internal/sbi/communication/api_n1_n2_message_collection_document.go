/*
 * Namf_Communication
 *
 * AMF Communication Service
 *
 * API version: 1.0.0
 * Generated by: OpenAPI Generator (https://openapi-generator.tech)
 */

package communication

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"lightcore/lightcore/lightcore/NFs/amf/internal/logger"
	"lightcore/lightcore/lightcore/NFs/amf/internal/sbi/producer"
	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/util/httpwrapper"
)

// N1N2MessageTransfer - Namf_Communication N1N2 Message Transfer (UE Specific) service Operation
func HTTPN1N2MessageTransfer(c *gin.Context) {
	var n1n2MessageTransferRequest models.N1N2MessageTransferRequest
	n1n2MessageTransferRequest.JsonData = new(models.N1N2MessageTransferReqData)

	requestBody, err := c.GetRawData()
	if err != nil {
		problemDetail := models.ProblemDetails{
			Title:  "System failure",
			Status: http.StatusInternalServerError,
			Detail: err.Error(),
			Cause:  "SYSTEM_FAILURE",
		}
		logger.CommLog.Errorf("Get Request Body error: %+v", err)
		c.JSON(http.StatusInternalServerError, problemDetail)
		return
	}

	contentType := c.GetHeader("Content-Type")
	s := strings.Split(contentType, ";")
	switch s[0] {
	case "application/json":
		err = fmt.Errorf("N1 and N2 datas are both Empty in N1N2MessgeTransfer")
	case "multipart/related":
		err = openapi.Deserialize(&n1n2MessageTransferRequest, requestBody, contentType)
	default:
		err = fmt.Errorf("Wrong content type")
	}

	if err != nil {
		problemDetail := "[Request Body] " + err.Error()
		rsp := models.ProblemDetails{
			Title:  "Malformed request syntax",
			Status: http.StatusBadRequest,
			Detail: problemDetail,
		}
		logger.CommLog.Errorln(problemDetail)
		c.JSON(http.StatusBadRequest, rsp)
		return
	}

	req := httpwrapper.NewRequest(c.Request, n1n2MessageTransferRequest)
	req.Params["ueContextId"] = c.Params.ByName("ueContextId")
	req.Params["reqUri"] = c.Request.RequestURI

	rsp := producer.HandleN1N2MessageTransferRequest(req)

	for key, val := range rsp.Header {
		c.Header(key, val[0])
	}
	responseBody, err := openapi.Serialize(rsp.Body, "application/json")
	if err != nil {
		logger.CommLog.Errorln(err)
		problemDetails := models.ProblemDetails{
			Status: http.StatusInternalServerError,
			Cause:  "SYSTEM_FAILURE",
			Detail: err.Error(),
		}
		c.JSON(http.StatusInternalServerError, problemDetails)
	} else {
		c.Data(rsp.Status, "application/json", responseBody)
	}
}

func HTTPN1N2MessageTransferStatus(c *gin.Context) {
	req := httpwrapper.NewRequest(c.Request, nil)
	req.Params["ueContextId"] = c.Params.ByName("ueContextId")
	req.Params["reqUri"] = c.Request.RequestURI

	rsp := producer.HandleN1N2MessageTransferStatusRequest(req)

	responseBody, err := openapi.Serialize(rsp.Body, "application/json")
	if err != nil {
		logger.CommLog.Errorln(err)
		problemDetails := models.ProblemDetails{
			Status: http.StatusInternalServerError,
			Cause:  "SYSTEM_FAILURE",
			Detail: err.Error(),
		}
		c.JSON(http.StatusInternalServerError, problemDetails)
	} else {
		c.Data(rsp.Status, "application/json", responseBody)
	}
}
