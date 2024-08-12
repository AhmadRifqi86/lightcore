package context

import (
	"encoding/json"
	"fmt"
	"math"
	"net"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/mohae/deepcopy"
	"go.mongodb.org/mongo-driver/bson"

	"github.com/AhmadRifqi86/lightcore/lightcore/NFs/amf/internal/logger"
	//"github.com/AhmadRifqi86/lightcore/lightcore/NFs/amf/internal/sbi/misc"

	//"github.com/AhmadRifqi86/lightcore/lightcore/NFs/amf/internal/util"
	"github.com/AhmadRifqi86/lightcore/lightcore/NFs/amf/pkg/factory"
	"github.com/free5gc/nas/security"
	"github.com/free5gc/openapi"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/util/idgenerator"
	"github.com/free5gc/util/mongoapi"
)

var (
	amfContext                       AMFContext
	tmsiGenerator                    *idgenerator.IDGenerator = nil
	amfUeNGAPIDGenerator             *idgenerator.IDGenerator = nil
	amfStatusSubscriptionIDGenerator *idgenerator.IDGenerator = nil
)

func init() {
	GetSelf().LadnPool = make(map[string]factory.Ladn)
	GetSelf().EventSubscriptionIDGenerator = idgenerator.NewGenerator(1, math.MaxInt32)
	GetSelf().Name = "amf"
	GetSelf().UriScheme = models.UriScheme_HTTPS
	GetSelf().RelativeCapacity = 0xff
	GetSelf().ServedGuamiList = make([]models.Guami, 0, MaxNumOfServedGuamiList)
	GetSelf().PlmnSupportList = make([]factory.PlmnSupportItem, 0, MaxNumOfPLMNs)
	GetSelf().NfService = make(map[models.ServiceName]models.NfService)
	GetSelf().NetworkName.Full = "free5GC"
	tmsiGenerator = idgenerator.NewGenerator(1, math.MaxInt32)
	amfStatusSubscriptionIDGenerator = idgenerator.NewGenerator(1, math.MaxInt32)
	amfUeNGAPIDGenerator = idgenerator.NewGenerator(1, MaxValueOfAmfUeNgapId)
}

type AMFContext struct {
	EventSubscriptionIDGenerator *idgenerator.IDGenerator
	EventSubscriptions           sync.Map
	UePool                       sync.Map                // map[supi]*AmfUe
	RanUePool                    sync.Map                // map[AmfUeNgapID]*RanUe
	AmfRanPool                   sync.Map                // map[net.Conn]*AmfRan
	LadnPool                     map[string]factory.Ladn // dnn as key
	SupportTaiLists              []models.Tai
	ServedGuamiList              []models.Guami
	PlmnSupportList              []factory.PlmnSupportItem
	RelativeCapacity             int64
	NfId                         string
	Name                         string
	NfService                    map[models.ServiceName]models.NfService // nfservice that amf support
	UriScheme                    models.UriScheme
	BindingIPv4                  string
	SBIPort                      int
	RegisterIPv4                 string
	HttpIPv6Address              string
	TNLWeightFactor              int64
	SupportDnnLists              []string
	AMFStatusSubscriptions       sync.Map // map[subscriptionID]models.SubscriptionData
	NrfUri                       string
	SecurityAlgorithm            SecurityAlgorithm
	NetworkName                  factory.NetworkName
	NgapIpList                   []string // NGAP Server IP
	NgapPort                     int
	T3502Value                   int // unit is second
	T3512Value                   int // unit is second
	Non3gppDeregTimerValue       int // unit is second
	// read-only fields
	T3513Cfg          factory.TimerValue
	T3522Cfg          factory.TimerValue
	T3550Cfg          factory.TimerValue
	T3560Cfg          factory.TimerValue
	T3565Cfg          factory.TimerValue
	T3570Cfg          factory.TimerValue
	Locality          string
	PcfServiceUris    map[models.ServiceName]string
	PcfSuppFeats      map[models.ServiceName]openapi.SupportedFeature
	AppSessionPool    sync.Map //from PCF context.go   init nya dimana?
	AMFStatusSubsData sync.Map //from PCF context.go init nya dimana?
	pcfUePool         sync.Map
}

type AMFContextEventSubscription struct {
	IsAnyUe           bool
	IsGroupUe         bool
	UeSupiList        []string
	Expiry            *time.Time
	EventSubscription models.AmfEventSubscription
}

type SecurityAlgorithm struct {
	IntegrityOrder []uint8 // slice of security.AlgIntegrityXXX
	CipheringOrder []uint8 // slice of security.AlgCipheringXXX
}

type AMFStatusSubscriptionData struct {
	AmfUri       string
	AmfStatusUri string         //ada di AMF Context, tapi itu sync.map
	GuamiList    []models.Guami //ada di AMF context: servedGuamiList
}

type AppSessionData struct {
	AppSessionId      string
	AppSessionContext *models.AppSessionContext
	// (compN/compN-subCompN/appId-%s) map to PccRule
	RelatedPccRuleIds    map[string]string
	PccRuleIdMapToCompId map[string]string
	// EventSubscription
	Events   map[models.AfEvent]models.AfNotifMethod
	EventUri string
	// related Session
	SmPolicyData *UeSmPolicyData
}

func InitAmfContext(context *AMFContext) {
	config := factory.AmfConfig
	logger.UtilLog.Infof("amfconfig Info: Version[%s]", config.GetVersion())
	configuration := config.Configuration
	context.NfId = uuid.New().String()
	if configuration.AmfName != "" {
		context.Name = configuration.AmfName
	}
	//mongodb := config.Configuration.Mongodb
	//if err := mongoapi.SetMongoDB(mongodb.Name, mongodb.Url>                logger.UtilLog.Errorf("InitpcfContext err: %+v">
	//return
	//}
	if configuration.NgapIpList != nil {
		context.NgapIpList = configuration.NgapIpList
	} else {
		context.NgapIpList = []string{"127.0.0.1"} // default localhost
	}
	context.NgapPort = config.GetNgapPort()
	context.UriScheme = models.UriScheme(config.GetSbiScheme())
	context.RegisterIPv4 = config.GetSbiRegisterIP()
	context.SBIPort = config.GetSbiPort()
	context.BindingIPv4 = config.GetSbiBindingIP()

	context.InitNFService(config.GetServiceNameList(), config.GetVersion())
	context.ServedGuamiList = configuration.ServedGumaiList
	context.SupportTaiLists = configuration.SupportTAIList
	context.PlmnSupportList = configuration.PlmnSupportList
	context.SupportDnnLists = configuration.SupportDnnList
	for _, ladn := range configuration.SupportLadnList {
		context.LadnPool[ladn.Dnn] = ladn
	}
	context.NrfUri = config.GetNrfUri()
	security := configuration.Security
	if security != nil {
		context.SecurityAlgorithm.IntegrityOrder = getIntAlgOrder(security.IntegrityOrder)
		context.SecurityAlgorithm.CipheringOrder = getEncAlgOrder(security.CipheringOrder)
	}
	context.NetworkName = configuration.NetworkName
	context.T3502Value = configuration.T3502Value
	context.T3512Value = configuration.T3512Value
	context.Non3gppDeregTimerValue = configuration.Non3gppDeregTimerValue
	context.T3513Cfg = configuration.T3513
	context.T3522Cfg = configuration.T3522
	context.T3550Cfg = configuration.T3550
	context.T3560Cfg = configuration.T3560
	context.T3565Cfg = configuration.T3565
	context.T3570Cfg = configuration.T3570
	context.Locality = configuration.Locality
	context.PcfServiceUris = make(map[models.ServiceName]string)
	context.PcfSuppFeats = make(map[models.ServiceName]openapi.SupportedFeature)
	//context.pcfUePool =
}

func getIntAlgOrder(integrityOrder []string) (intOrder []uint8) {
	for _, intAlg := range integrityOrder {
		switch intAlg {
		case "NIA0":
			intOrder = append(intOrder, security.AlgIntegrity128NIA0)
		case "NIA1":
			intOrder = append(intOrder, security.AlgIntegrity128NIA1)
		case "NIA2":
			intOrder = append(intOrder, security.AlgIntegrity128NIA2)
		case "NIA3":
			intOrder = append(intOrder, security.AlgIntegrity128NIA3)
		default:
			logger.UtilLog.Errorf("Unsupported algorithm: %s", intAlg)
		}
	}
	return
}

func getEncAlgOrder(cipheringOrder []string) (encOrder []uint8) {
	for _, encAlg := range cipheringOrder {
		switch encAlg {
		case "NEA0":
			encOrder = append(encOrder, security.AlgCiphering128NEA0)
		case "NEA1":
			encOrder = append(encOrder, security.AlgCiphering128NEA1)
		case "NEA2":
			encOrder = append(encOrder, security.AlgCiphering128NEA2)
		case "NEA3":
			encOrder = append(encOrder, security.AlgCiphering128NEA3)
		default:
			logger.UtilLog.Errorf("Unsupported algorithm: %s", encAlg)
		}
	}
	return
}

func NewPlmnSupportItem() (item factory.PlmnSupportItem) {
	item.SNssaiList = make([]models.Snssai, 0, MaxNumOfSlice)
	return
}

func (context *AMFContext) TmsiAllocate() int32 {
	tmsi, err := tmsiGenerator.Allocate()
	if err != nil {
		logger.CtxLog.Errorf("Allocate TMSI error: %+v", err)
		return -1
	}
	return int32(tmsi)
}

func (context *AMFContext) FreeTmsi(tmsi int64) {
	tmsiGenerator.FreeID(tmsi)
}

func (context *AMFContext) AllocateAmfUeNgapID() (int64, error) {
	return amfUeNGAPIDGenerator.Allocate()
}

func (context *AMFContext) AllocateGutiToUe(ue *AmfUe) {
	servedGuami := context.ServedGuamiList[0]
	ue.Tmsi = context.TmsiAllocate()

	plmnID := servedGuami.PlmnId.Mcc + servedGuami.PlmnId.Mnc
	tmsiStr := fmt.Sprintf("%08x", ue.Tmsi)
	ue.Guti = plmnID + servedGuami.AmfId + tmsiStr
}

func (context *AMFContext) AllocateRegistrationArea(ue *AmfUe, anType models.AccessType) {
	// clear the previous registration area if need
	if len(ue.RegistrationArea[anType]) > 0 {
		ue.RegistrationArea[anType] = nil
	}

	// allocate a new tai list as a registration area to ue
	// TODO: algorithm to choose TAI list
	for _, supportTai := range context.SupportTaiLists {
		if reflect.DeepEqual(supportTai, ue.Tai) {
			ue.RegistrationArea[anType] = append(ue.RegistrationArea[anType], supportTai)
			break
		}
	}
}

func (context *AMFContext) NewAMFStatusSubscription(subscriptionData models.SubscriptionData) (subscriptionID string) {
	id, err := amfStatusSubscriptionIDGenerator.Allocate()
	if err != nil {
		logger.CtxLog.Errorf("Allocate subscriptionID error: %+v", err)
		return ""
	}

	subscriptionID = strconv.Itoa(int(id))
	context.AMFStatusSubscriptions.Store(subscriptionID, subscriptionData)
	return
}

// Return Value: (subscriptionData *models.SubScriptionData, ok bool)
func (context *AMFContext) FindAMFStatusSubscription(subscriptionID string) (*models.SubscriptionData, bool) {
	if value, ok := context.AMFStatusSubscriptions.Load(subscriptionID); ok {
		subscriptionData := value.(models.SubscriptionData)
		return &subscriptionData, ok
	} else {
		return nil, false
	}
}

func (context *AMFContext) DeleteAMFStatusSubscription(subscriptionID string) {
	context.AMFStatusSubscriptions.Delete(subscriptionID)
	if id, err := strconv.ParseInt(subscriptionID, 10, 64); err != nil {
		logger.CtxLog.Error(err)
	} else {
		amfStatusSubscriptionIDGenerator.FreeID(id)
	}
}

func (context *AMFContext) NewEventSubscription(subscriptionID string, subscription *AMFContextEventSubscription) {
	context.EventSubscriptions.Store(subscriptionID, subscription)
}

func (context *AMFContext) FindEventSubscription(subscriptionID string) (*AMFContextEventSubscription, bool) {
	if value, ok := context.EventSubscriptions.Load(subscriptionID); ok {
		return value.(*AMFContextEventSubscription), ok
	} else {
		return nil, false
	}
}

func (context *AMFContext) DeleteEventSubscription(subscriptionID string) {
	context.EventSubscriptions.Delete(subscriptionID)
	if id, err := strconv.ParseInt(subscriptionID, 10, 32); err != nil {
		logger.CtxLog.Error(err)
	} else {
		context.EventSubscriptionIDGenerator.FreeID(id)
	}
}

func (context *AMFContext) AddAmfUeToUePool(ue *AmfUe, supi string) {
	if len(supi) == 0 {
		logger.CtxLog.Errorf("Supi is nil")
	}
	ue.Supi = supi
	context.UePool.Store(ue.Supi, ue)
}

func (context *AMFContext) NewAmfUe(supi string) *AmfUe {
	ue := AmfUe{}
	ue.init()

	if supi != "" {
		context.AddAmfUeToUePool(&ue, supi)
	}

	context.AllocateGutiToUe(&ue)

	logger.CtxLog.Infof("New AmfUe [supi:%s][guti:%s]", supi, ue.Guti)
	return &ue
}

func (context *AMFContext) AmfUeFindByUeContextID(ueContextID string) (*AmfUe, bool) {
	if strings.HasPrefix(ueContextID, "imsi") {
		return context.AmfUeFindBySupi(ueContextID)
	}
	if strings.HasPrefix(ueContextID, "imei") {
		return context.AmfUeFindByPei(ueContextID)
	}
	if strings.HasPrefix(ueContextID, "5g-guti") {
		guti := ueContextID[strings.LastIndex(ueContextID, "-")+1:]
		return context.AmfUeFindByGuti(guti)
	}
	return nil, false
}

func (context *AMFContext) AmfUeFindBySupi(supi string) (*AmfUe, bool) {
	if value, ok := context.UePool.Load(supi); ok {
		return value.(*AmfUe), ok
	}
	return nil, false
}

func (context *AMFContext) AmfUeFindBySuci(suci string) (ue *AmfUe, ok bool) {
	context.UePool.Range(func(key, value interface{}) bool {
		candidate := value.(*AmfUe)
		if ok = (candidate.Suci == suci); ok {
			ue = candidate
			return false
		}
		return true
	})
	return
}

func (context *AMFContext) AmfUeFindByPei(pei string) (*AmfUe, bool) {
	var ue *AmfUe
	var ok bool
	context.UePool.Range(func(key, value interface{}) bool {
		candidate := value.(*AmfUe)
		if ok = (candidate.Pei == pei); ok {
			ue = candidate
			return false
		}
		return true
	})
	return ue, ok
}

func (context *AMFContext) NewAmfRan(conn net.Conn) *AmfRan {
	ran := AmfRan{}
	ran.SupportedTAList = make([]SupportedTAI, 0, MaxNumOfTAI*MaxNumOfBroadcastPLMNs)
	ran.Conn = conn
	ran.Log = logger.NgapLog.WithField(logger.FieldRanAddr, conn.RemoteAddr().String())
	context.AmfRanPool.Store(conn, &ran)
	return &ran
}

// use net.Conn to find RAN context, return *AmfRan and ok bit
func (context *AMFContext) AmfRanFindByConn(conn net.Conn) (*AmfRan, bool) {
	if value, ok := context.AmfRanPool.Load(conn); ok {
		return value.(*AmfRan), ok
	}
	return nil, false
}

// use ranNodeID to find RAN context, return *AmfRan and ok bit
func (context *AMFContext) AmfRanFindByRanID(ranNodeID models.GlobalRanNodeId) (*AmfRan, bool) {
	var ran *AmfRan
	var ok bool
	context.AmfRanPool.Range(func(key, value interface{}) bool {
		amfRan := value.(*AmfRan)
		if amfRan.RanId == nil {
			return true
		}

		switch amfRan.RanPresent {
		case RanPresentGNbId:
			if amfRan.RanId.GNbId != nil && ranNodeID.GNbId != nil &&
				amfRan.RanId.GNbId.GNBValue == ranNodeID.GNbId.GNBValue {
				ran = amfRan
				ok = true
				return false
			}
		case RanPresentNgeNbId:
			if amfRan.RanId.NgeNbId == ranNodeID.NgeNbId {
				ran = amfRan
				ok = true
				return false
			}
		case RanPresentN3IwfId:
			if amfRan.RanId.N3IwfId == ranNodeID.N3IwfId {
				ran = amfRan
				ok = true
				return false
			}
		}
		return true
	})
	return ran, ok
}

func (context *AMFContext) DeleteAmfRan(conn net.Conn) {
	context.AmfRanPool.Delete(conn)
}

func (context *AMFContext) InSupportDnnList(targetDnn string) bool {
	for _, dnn := range context.SupportDnnLists {
		if dnn == targetDnn {
			return true
		}
	}
	return false
}

func (context *AMFContext) InPlmnSupportList(snssai models.Snssai) bool {
	for _, plmnSupportItem := range context.PlmnSupportList {
		for _, supportSnssai := range plmnSupportItem.SNssaiList {
			if reflect.DeepEqual(supportSnssai, snssai) {
				return true
			}
		}
	}
	return false
}

func (context *AMFContext) AmfUeFindByGuti(guti string) (*AmfUe, bool) {
	var ue *AmfUe
	var ok bool
	context.UePool.Range(func(key, value interface{}) bool {
		candidate := value.(*AmfUe)
		if ok = (candidate.Guti == guti); ok {
			ue = candidate
			return false
		}
		return true
	})
	return ue, ok
}

func (context *AMFContext) AmfUeFindByPolicyAssociationID(polAssoId string) (*AmfUe, bool) {
	var ue *AmfUe
	var ok bool
	context.UePool.Range(func(key, value interface{}) bool {
		candidate := value.(*AmfUe)
		if ok = (candidate.PolicyAssociationId == polAssoId); ok {
			ue = candidate
			return false
		}
		return true
	})
	return ue, ok
}

func (context *AMFContext) RanUeFindByAmfUeNgapID(amfUeNgapID int64) *RanUe {
	if value, ok := context.RanUePool.Load(amfUeNgapID); ok {
		return value.(*RanUe)
	}
	return nil
}

func (context *AMFContext) GetIPv4Uri() string {
	return fmt.Sprintf("%s://%s:%d", context.UriScheme, context.RegisterIPv4, context.SBIPort)
}

// from PCF
func GetUri(name models.ServiceName) string {
	return amfContext.PcfServiceUris[name]
}

//NfService

func (context *AMFContext) InitNFService(serivceName []string, version string) {
	tmpVersion := strings.Split(version, ".")
	versionUri := "v" + tmpVersion[0]
	for index, nameString := range serivceName {
		name := models.ServiceName(nameString)
		context.NfService[name] = models.NfService{
			ServiceInstanceId: strconv.Itoa(index),
			ServiceName:       name,
			Versions: &[]models.NfServiceVersion{
				{
					ApiFullVersion:  version,
					ApiVersionInUri: versionUri,
				},
			},
			Scheme:          context.UriScheme,
			NfServiceStatus: models.NfServiceStatus_REGISTERED,
			ApiPrefix:       context.GetIPv4Uri(),
			IpEndPoints: &[]models.IpEndPoint{
				{
					Ipv4Address: context.RegisterIPv4,
					Transport:   models.TransportProtocol_TCP,
					Port:        int32(context.SBIPort),
				},
			},
		}
	}
}

// Reset AMF Context
func (context *AMFContext) Reset() {
	context.AmfRanPool.Range(func(key, value interface{}) bool {
		context.UePool.Delete(key)
		return true
	})
	for key := range context.LadnPool {
		delete(context.LadnPool, key)
	}
	context.RanUePool.Range(func(key, value interface{}) bool {
		context.RanUePool.Delete(key)
		return true
	})
	context.UePool.Range(func(key, value interface{}) bool {
		context.UePool.Delete(key)
		return true
	})
	context.EventSubscriptions.Range(func(key, value interface{}) bool {
		context.DeleteEventSubscription(key.(string))
		return true
	})
	for key := range context.NfService {
		delete(context.NfService, key)
	}
	context.SupportTaiLists = context.SupportTaiLists[:0]
	context.PlmnSupportList = context.PlmnSupportList[:0]
	context.ServedGuamiList = context.ServedGuamiList[:0]
	context.RelativeCapacity = 0xff
	context.NfId = ""
	context.UriScheme = models.UriScheme_HTTPS
	context.SBIPort = 0
	context.BindingIPv4 = ""
	context.RegisterIPv4 = ""
	context.HttpIPv6Address = ""
	context.Name = "amf"
	context.NrfUri = ""
}

// Create new AMF context
func GetSelf() *AMFContext {
	return &amfContext
}

// Function defined at /pcf/internal/context/context.go
func (c *AMFContext) NewPCFUe(Supi string) (*UeContext, error) {
	if strings.HasPrefix(Supi, "imsi-") {
		newUeContext := &UeContext{}
		newUeContext.SmPolicyData = make(map[string]*UeSmPolicyData)
		newUeContext.AMPolicyData = make(map[string]*UeAMPolicyData)
		newUeContext.PolAssociationIDGenerator = 1
		newUeContext.AppSessionIDGenerator = idgenerator.NewGenerator(1, math.MaxInt64)
		newUeContext.Supi = Supi
		c.pcfUePool.Store(Supi, newUeContext)
		return newUeContext, nil
	} else {
		return nil, fmt.Errorf(" add Ue context fail ")
	}
}

func (c *AMFContext) PCFUeFindByPolicyId(PolicyId string) *UeContext {
	index := strings.LastIndex(PolicyId, "-")
	if index == -1 {
		return nil
	}
	supi := PolicyId[:index]
	if supi != "" {
		if value, ok := c.pcfUePool.Load(supi); ok {
			ueContext := value.(*UeContext)
			return ueContext
		}
	}
	return nil
}

func (c *AMFContext) PCFUeFindByAppSessionId(appSessionId string) *UeContext {
	index := strings.LastIndex(appSessionId, "-")
	if index == -1 {
		return nil
	}
	supi := appSessionId[:index]
	if supi != "" {
		if value, ok := c.pcfUePool.Load(supi); ok {
			ueContext := value.(*UeContext)
			return ueContext
		}
	}
	return nil
}

func (c *AMFContext) PcfUeFindByIPv4(v4 string) *UeContext {
	var ue *UeContext
	c.pcfUePool.Range(func(key, value interface{}) bool {
		ue = value.(*UeContext)
		if ue.SMPolicyFindByIpv4(v4) != nil {
			return false
		} else {
			return true
		}
	})

	return ue
}

func (c *AMFContext) PcfUeFindByIPv6(v6 string) *UeContext {
	var ue *UeContext
	c.pcfUePool.Range(func(key, value interface{}) bool {
		ue = value.(*UeContext)
		if ue.SMPolicyFindByIpv6(v6) != nil {
			return false
		} else {
			return true
		}
	})

	return ue
}

//func (c *PCFContext) NewAmfStatusSubscription(subscriptionID st>        c.AMFStatusSubsData.Store(subscriptionID, subscriptionD>}
//IP address allocation defined at PCF

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
	amPolicy.SuppFeat = "3fff"
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
