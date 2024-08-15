package logger

import (
	"github.com/sirupsen/logrus"

	logger_util "github.com/free5gc/util/logger"
)

const (
	FieldSupi         = "supi"
	FieldPDUSessionID = "pdu_session_id"
)

var (
	Log           *logrus.Logger
	NfLog         *logrus.Entry
	MainLog       *logrus.Entry
	InitLog       *logrus.Entry
	CfgLog        *logrus.Entry
	CtxLog        *logrus.Entry
	GinLog        *logrus.Entry
	ConsumerLog   *logrus.Entry
	GsmLog        *logrus.Entry
	PfcpLog       *logrus.Entry
	PduSessLog    *logrus.Entry
	SmPolicyLog   *logrus.Entry
	UtilLog       *logrus.Entry
	PolicyAuthLog *logrus.Entry
	SdmLog        *logrus.Entry
	DataRepoLog   *logrus.Entry
)

func init() {
	fieldsOrder := []string{
		logger_util.FieldNF,
		logger_util.FieldCategory,
	}

	Log = logger_util.New(fieldsOrder)
	NfLog = Log.WithField(logger_util.FieldNF, "SMF")
	MainLog = NfLog.WithField(logger_util.FieldCategory, "Main")
	InitLog = NfLog.WithField(logger_util.FieldCategory, "Init")
	CfgLog = NfLog.WithField(logger_util.FieldCategory, "CFG")
	CtxLog = NfLog.WithField(logger_util.FieldCategory, "CTX")
	GinLog = NfLog.WithField(logger_util.FieldCategory, "GIN")
	ConsumerLog = NfLog.WithField(logger_util.FieldCategory, "Consumer")
	GsmLog = NfLog.WithField(logger_util.FieldCategory, "GSM")
	PfcpLog = NfLog.WithField(logger_util.FieldCategory, "PFCP")
	PduSessLog = NfLog.WithField(logger_util.FieldCategory, "PduSess")
	SmPolicyLog = NfLog.WithField(logger_util.FieldCategory, "SmPol")
	UtilLog = NfLog.WithField(logger_util.FieldCategory, "Util")
	PolicyAuthLog = NfLog.WithField(logger_util.FieldCategory, "PolAuth")
	SdmLog = NfLog.WithField(logger_util.FieldCategory, "Sdm")
	DataRepoLog = NfLog.WithField(logger_util.FieldCategory, "DataRepo")
}
