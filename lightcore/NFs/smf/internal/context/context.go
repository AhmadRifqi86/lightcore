package context

import (
	"context"
	"fmt"
        "math"
	"net"
	"os"
        "sync"
	"sync/atomic"
	"time"
        "strconv"
        "strings"

	"github.com/google/uuid"
        "github.com/free5gc/openapi"
	"github.com/free5gc/openapi/Nnrf_NFDiscovery"
	"github.com/free5gc/openapi/Nnrf_NFManagement"
	"github.com/free5gc/openapi/Nudm_SubscriberDataManagement"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/pfcp/pfcpType"
	"github.com/free5gc/smf/internal/logger"
	"github.com/free5gc/smf/pkg/factory"
        "github.com/free5gc/util/idgenerator"
  //      "github.com/free5gc/util/mongoapi"
)

func Init() {
	smfContext.NfInstanceID = uuid.New().String()
}

var smfContext SMFContext

type SMFContext struct {
	Name         string
	NfInstanceID string

	URIScheme    models.UriScheme
	BindingIPv4  string
	RegisterIPv4 string
	SBIPort      int

	// N4 interface-related
	CPNodeID     pfcpType.NodeID
	ExternalAddr string
	ListenAddr   string

	UDMProfile models.NfProfile

	Key    string
	PEM    string
	KeyLog string

	SnssaiInfos []*SnssaiSmfInfo

	NrfUri                         string
	NFManagementClient             *Nnrf_NFManagement.APIClient
	NFDiscoveryClient              *Nnrf_NFDiscovery.APIClient
	SubscriberDataManagementClient *Nudm_SubscriberDataManagement.APIClient //Defined here, 
	Locality                       string
	AssocFailAlertInterval         time.Duration
	AssocFailRetryInterval         time.Duration

	UserPlaneInformation  *UserPlaneInformation
	Ctx                   context.Context
	PFCPCancelFunc        context.CancelFunc
	PfcpHeartbeatInterval time.Duration

	// Now only "IPv4" supported
	// TODO: support "IPv6", "IPv4v6", "Ethernet"
	SupportedPDUSessionType string

	//*** For ULCL ** //
	ULCLSupport         bool
	ULCLGroups          map[string][]string
	UEPreConfigPathPool map[string]*UEPreConfigPaths
	UEDefaultPathPool   map[string]*UEDefaultPaths
	LocalSEIDCount      uint64
        // SM Policy 
        NfService       map[models.ServiceName]models.NfService
        PcfServiceUris  map[models.ServiceName]string
        PcfSuppFeats    map[models.ServiceName]openapi.SupportedFeature
//        pcfUePool       sync.Map
        AppSessionPool  sync.Map
        PcfUePool       sync.Map
      //From UDM
        UdmUePool       sync.Map
}

type AMFStatusSubscriptionData struct {
        AmfUri       string
        AmfStatusUri string
        GuamiList    []models.Guami
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

type UdmUeContext struct {
	Supi                              string
	Gpsi                              string
	ExternalGroupID                   string
	Nssai                             *models.Nssai
	Amf3GppAccessRegistration         *models.Amf3GppAccessRegistration
	AmfNon3GppAccessRegistration      *models.AmfNon3GppAccessRegistration
	AccessAndMobilitySubscriptionData *models.AccessAndMobilitySubscriptionData
	SmfSelSubsData                    *models.SmfSelectionSubscriptionData
	UeCtxtInSmfData                   *models.UeContextInSmfData
	TraceDataResponse                 models.TraceDataResponse
	TraceData                         *models.TraceData
	SessionManagementSubsData         map[string]models.SessionManagementSubscriptionData
	SubsDataSets                      *models.SubscriptionDataSets
	SubscribeToNotifChange            map[string]*models.SdmSubscription
	SubscribeToNotifSharedDataChange  *models.SdmSubscription
	PduSessionID                      string
	UdrUri                            string
	UdmSubsToNotify                   map[string]*models.SubscriptionDataSubscriptions
	EeSubscriptions                   map[string]*models.EeSubscription // subscriptionID as key
	amSubsDataLock                    sync.Mutex
	smfSelSubsDataLock                sync.Mutex
	SmSubsDataLock                    sync.RWMutex
}

var InfluenceDataUpdateNotifyUri=factory.PcfCallbackResUriPrefix + "/nudr-notify/influence-data"

func ResolveIP(host string) net.IP {
	if addr, err := net.ResolveIPAddr("ip", host); err != nil {
		return nil
	} else {
		return addr.IP
	}
}

func (s *SMFContext) ExternalIP() net.IP {
	return ResolveIP(s.ExternalAddr)
}

func (s *SMFContext) ListenIP() net.IP {
	return ResolveIP(s.ListenAddr)
}

// RetrieveDnnInformation gets the corresponding dnn info from S-NSSAI and DNN
func RetrieveDnnInformation(Snssai *models.Snssai, dnn string) *SnssaiSmfDnnInfo {
	for _, snssaiInfo := range GetSelf().SnssaiInfos {
		if snssaiInfo.Snssai.Sst == Snssai.Sst && snssaiInfo.Snssai.Sd == Snssai.Sd {
			return snssaiInfo.DnnInfos[dnn]
		}
	}
	return nil
}

func AllocateLocalSEID() uint64 {
	return atomic.AddUint64(&smfContext.LocalSEIDCount, 1)
}

func InitSmfContext(config *factory.Config) {
	if config == nil {
		logger.CtxLog.Error("Config is nil")
		return
	}

	logger.CtxLog.Infof("smfconfig Info: Version[%s] Description[%s]", config.Info.Version, config.Info.Description)
	configuration := config.Configuration
	if configuration.SmfName != "" {
		smfContext.Name = configuration.SmfName
	}

	sbi := configuration.Sbi
	if sbi == nil {
		logger.CtxLog.Errorln("Configuration needs \"sbi\" value")
		return
	} else {
		smfContext.URIScheme = models.UriScheme(sbi.Scheme)
		smfContext.RegisterIPv4 = factory.SmfSbiDefaultIPv4 // default localhost
		smfContext.SBIPort = factory.SmfSbiDefaultPort      // default port
		if sbi.RegisterIPv4 != "" {
			smfContext.RegisterIPv4 = sbi.RegisterIPv4
		}
		if sbi.Port != 0 {
			smfContext.SBIPort = sbi.Port
		}

		if tls := sbi.Tls; tls != nil {
			smfContext.Key = tls.Key
			smfContext.PEM = tls.Pem
		}

		smfContext.BindingIPv4 = os.Getenv(sbi.BindingIPv4)
		if smfContext.BindingIPv4 != "" {
			logger.CtxLog.Info("Parsing ServerIPv4 address from ENV Variable.")
		} else {
			smfContext.BindingIPv4 = sbi.BindingIPv4
			if smfContext.BindingIPv4 == "" {
				logger.CtxLog.Warn("Error parsing ServerIPv4 address as string. Using the 0.0.0.0 address as default.")
				smfContext.BindingIPv4 = "0.0.0.0"
			}
		}
	}

	if configuration.NrfUri != "" {
		smfContext.NrfUri = configuration.NrfUri
	} else {
		logger.CtxLog.Warn("NRF Uri is empty! Using localhost as NRF IPv4 address.")
		smfContext.NrfUri = fmt.Sprintf("%s://%s:%d", smfContext.URIScheme, "127.0.0.1", 29510)
	}

	if pfcp := configuration.PFCP; pfcp != nil {
		smfContext.ListenAddr = pfcp.ListenAddr
		smfContext.ExternalAddr = pfcp.ExternalAddr

		if ip := net.ParseIP(pfcp.NodeID); ip == nil {
			smfContext.CPNodeID = pfcpType.NodeID{
				NodeIdType: pfcpType.NodeIdTypeFqdn,
				FQDN:       pfcp.NodeID,
			}
		} else {
			ipv4 := ip.To4()
			if ipv4 != nil {
				smfContext.CPNodeID = pfcpType.NodeID{
					NodeIdType: pfcpType.NodeIdTypeIpv4Address,
					IP:         ipv4,
				}
			} else {
				smfContext.CPNodeID = pfcpType.NodeID{
					NodeIdType: pfcpType.NodeIdTypeIpv6Address,
					IP:         ip,
				}
			}
		}

		smfContext.PfcpHeartbeatInterval = pfcp.HeartbeatInterval

		if pfcp.AssocFailAlertInterval == 0 {
			smfContext.AssocFailAlertInterval = 5 * time.Minute
		} else {
			smfContext.AssocFailAlertInterval = pfcp.AssocFailAlertInterval
		}
		if pfcp.AssocFailRetryInterval == 0 {
			smfContext.AssocFailRetryInterval = 5 * time.Second
		} else {
			smfContext.AssocFailRetryInterval = pfcp.AssocFailRetryInterval
		}
	}

	smfContext.SnssaiInfos = make([]*SnssaiSmfInfo, 0, len(configuration.SNssaiInfo))

	for _, snssaiInfoConfig := range configuration.SNssaiInfo {
		snssaiInfo := SnssaiSmfInfo{}
		snssaiInfo.Snssai = SNssai{
			Sst: snssaiInfoConfig.SNssai.Sst,
			Sd:  snssaiInfoConfig.SNssai.Sd,
		}

		snssaiInfo.DnnInfos = make(map[string]*SnssaiSmfDnnInfo)

		for _, dnnInfoConfig := range snssaiInfoConfig.DnnInfos {
			dnnInfo := SnssaiSmfDnnInfo{}
			if dnnInfoConfig.DNS != nil {
				dnnInfo.DNS.IPv4Addr = net.ParseIP(dnnInfoConfig.DNS.IPv4Addr).To4()
				dnnInfo.DNS.IPv6Addr = net.ParseIP(dnnInfoConfig.DNS.IPv6Addr).To16()
			}
			if dnnInfoConfig.PCSCF != nil {
				dnnInfo.PCSCF.IPv4Addr = net.ParseIP(dnnInfoConfig.PCSCF.IPv4Addr).To4()
			}
			snssaiInfo.DnnInfos[dnnInfoConfig.Dnn] = &dnnInfo
		}
		smfContext.SnssaiInfos = append(smfContext.SnssaiInfos, &snssaiInfo)
	}

	// Set client and set url
	ManagementConfig := Nnrf_NFManagement.NewConfiguration()
	ManagementConfig.SetBasePath(GetSelf().NrfUri)
	smfContext.NFManagementClient = Nnrf_NFManagement.NewAPIClient(ManagementConfig)

	NFDiscovryConfig := Nnrf_NFDiscovery.NewConfiguration()
	NFDiscovryConfig.SetBasePath(GetSelf().NrfUri)
	smfContext.NFDiscoveryClient = Nnrf_NFDiscovery.NewAPIClient(NFDiscovryConfig)

	smfContext.ULCLSupport = configuration.ULCL

	smfContext.SupportedPDUSessionType = "IPv4"

	smfContext.UserPlaneInformation = NewUserPlaneInformation(&configuration.UserPlaneInformation)

	SetupNFProfile(config)
        //serviceList := configuration.ServiceList
        //smfContext.InitNFService(serviceList, config.Info.Version)
	smfContext.Locality = configuration.Locality
        smfContext.PcfServiceUris = make(map[models.ServiceName]string)
        smfContext.PcfSuppFeats = make(map[models.ServiceName]openapi.SupportedFeature)
}

//InitNFService  func (c *SMFContext) InitNFService(serviceList []factory.Service, version string)
func (c *SMFContext) InitNFService(serviceList []factory.Service, version string) {
        tmpVersion := strings.Split(version, ".")
        versionUri := "v" + tmpVersion[0]
        for index, service := range serviceList {
                name := models.ServiceName(service.ServiceName)
                c.NfService[name] = models.NfService{
                        ServiceInstanceId: strconv.Itoa(index),
                        ServiceName:       name,
                        Versions: &[]models.NfServiceVersion{
                                {
                                        ApiFullVersion:  version,
                                        ApiVersionInUri: versionUri,
                                },
                        },
                        Scheme:          c.URIScheme,
                        NfServiceStatus: models.NfServiceStatus_REGISTERED,
                        ApiPrefix:       c.GetIPv4Uri(),
                        IpEndPoints: &[]models.IpEndPoint{
                                {
                                        Ipv4Address: c.RegisterIPv4,
                                        Transport:   models.TransportProtocol_TCP,
                                        Port:        int32(c.SBIPort),
                                },
                        },
                        SupportedFeatures: service.SuppFeat,
                }
        }
}

func InitSMFUERouting(routingConfig *factory.RoutingConfig) {
	if !smfContext.ULCLSupport {
		return
	}

	if routingConfig == nil {
		logger.CtxLog.Error("configuration needs the routing config")
		return
	}

	logger.CtxLog.Infof("ue routing config Info: Version[%s] Description[%s]",
		routingConfig.Info.Version, routingConfig.Info.Description)

	UERoutingInfo := routingConfig.UERoutingInfo
	smfContext.UEPreConfigPathPool = make(map[string]*UEPreConfigPaths)
	smfContext.UEDefaultPathPool = make(map[string]*UEDefaultPaths)
	smfContext.ULCLGroups = make(map[string][]string)

	for groupName, routingInfo := range UERoutingInfo {
		logger.CtxLog.Debugln("Set context for ULCL group: ", groupName)
		smfContext.ULCLGroups[groupName] = routingInfo.Members
		uePreConfigPaths, err := NewUEPreConfigPaths(routingInfo.SpecificPaths)
		if err != nil {
			logger.CtxLog.Warnln(err)
		} else {
			smfContext.UEPreConfigPathPool[groupName] = uePreConfigPaths
		}
		ueDefaultPaths, err := NewUEDefaultPaths(smfContext.UserPlaneInformation, routingInfo.Topology)
		if err != nil {
			logger.CtxLog.Warnln(err)
		} else {
			smfContext.UEDefaultPathPool[groupName] = ueDefaultPaths
		}
	}
}

func GetSelf() *SMFContext {
	return &smfContext
}

func GetUserPlaneInformation() *UserPlaneInformation {
	return smfContext.UserPlaneInformation
}

func GetUEDefaultPathPool(groupName string) *UEDefaultPaths {
	return smfContext.UEDefaultPathPool[groupName]
}

func GetUri(name models.ServiceName) string {
        return smfContext.PcfServiceUris[name]
}

// defined at PCF
func (c *SMFContext) NewPCFUe(Supi string) (*UeContext, error) {
        if strings.HasPrefix(Supi, "imsi-") {
                newUeContext := &UeContext{}
                newUeContext.SmPolicyData = make(map[string]*UeSmPolicyData)
                newUeContext.AMPolicyData = make(map[string]*UeAMPolicyData)
                newUeContext.PolAssociationIDGenerator = 1
                newUeContext.AppSessionIDGenerator = idgenerator.NewGenerator(1, math.MaxInt64)
                newUeContext.Supi = Supi
                c.PcfUePool.Store(Supi, newUeContext)
                return newUeContext, nil
        } else {
                return nil, fmt.Errorf(" add Ue context fail ")
        }
}



func (c *SMFContext) PCFUeFindByPolicyId(PolicyId string) *UeContext {
        index := strings.LastIndex(PolicyId, "-")
        if index == -1 {
                return nil
        }
        supi := PolicyId[:index]
        if supi != "" {
                if value, ok := c.PcfUePool.Load(supi); ok {
                        ueContext := value.(*UeContext)
                        return ueContext
                }
        }
        return nil
}


func (c *SMFContext) PCFUeFindByAppSessionId(appSessionId string) *UeContext {
        index := strings.LastIndex(appSessionId, "-")
        if index == -1 {
                return nil
        }
        supi := appSessionId[:index]
        if supi != "" {
                if value, ok := c.PcfUePool.Load(supi); ok {
                        ueContext := value.(*UeContext)
                        return ueContext
                }
        }
        return nil
}


func ueSMPolicyFindByAppSessionContext(ue *UeContext, req *models.AppSessionContextReqData) (*UeSmPolicyData, error) {
        var policy *UeSmPolicyData
        var err error

        if req.UeIpv4 != "" {
                policy = ue.SMPolicyFindByIdentifiersIpv4(req.UeIpv4, req.SliceInfo, req.Dnn, req.IpDomain)
                if policy == nil {
                        err = fmt.Errorf("Can't find Ue with Ipv4[%s]", req.UeIpv4)
                }
        } else if req.UeIpv6 != "" {
                policy = ue.SMPolicyFindByIdentifiersIpv6(req.UeIpv6, req.SliceInfo, req.Dnn)
                if policy == nil {
                        err = fmt.Errorf("Can't find Ue with Ipv6 prefix[%s]", req.UeIpv6)
                }
        } else {
                // TODO: find by MAC address
                err = fmt.Errorf("Ue finding by MAC address does not support")
        }
        return policy, err
}


func (c *SMFContext) SessionBinding(req *models.AppSessionContextReqData) (*UeSmPolicyData, error) {
        var selectedUE *UeContext
        var policy *UeSmPolicyData
        var err error

        if req.Supi != "" {
                if val, exist := c.PcfUePool.Load(req.Supi); exist {
                        selectedUE = val.(*UeContext)
                }
        }

        if req.Gpsi != "" && selectedUE == nil {
                c.PcfUePool.Range(func(key, value interface{}) bool {
                        ue := value.(*UeContext)
                        if ue.Gpsi == req.Gpsi {
                                selectedUE = ue
                                return false
                        } else {
                                return true
                        }
                })
        }

        if selectedUE != nil {
                policy, err = ueSMPolicyFindByAppSessionContext(selectedUE, req)
        } else {
                c.PcfUePool.Range(func(key, value interface{}) bool {
                        ue := value.(*UeContext)
                        policy, err = ueSMPolicyFindByAppSessionContext(ue, req)
                        return true
                })
        }
        if policy == nil && err == nil {
                err = fmt.Errorf("No SM policy found")
        }
        return policy, err
}


func (c *SMFContext) GetIPv4Uri() string {
        return fmt.Sprintf("%s://%s:%d", c.URIScheme, c.RegisterIPv4, c.SBIPort)
}



//Where is my UDM function? NewUdmUe and UdmUeFindBySupi
