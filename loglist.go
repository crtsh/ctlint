package ctlint

import (
	"crypto/sha256"
	"embed"

	ctgo "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/loglist3"
	"github.com/google/certificate-transparency-go/x509"
)

const gstaticV3AllLogsListFilename = "files/gstatic/v3/all_logs_list.json"
const appleCurrentLogListFilename = "files/apple/current_log_list.json"
const crtshV3AllLogsListFilename = "files/crtsh/v3/all_logs_list.json"

//go:embed files/*
var files embed.FS
var gstaticV3AllLogsList, appleCurrentLogList, crtshV3AllLogsList *loglist3.LogList
var logSignatureVerifierMap map[[sha256.Size]byte]*ctgo.SignatureVerifier
var temporalIntervalMap map[[sha256.Size]byte]*loglist3.TemporalInterval

func init() {
	logSignatureVerifierMap = make(map[[sha256.Size]byte]*ctgo.SignatureVerifier)
	temporalIntervalMap = make(map[[sha256.Size]byte]*loglist3.TemporalInterval)
}

func LoadLogLists() error {
	var err error

	if gstaticV3AllLogsList, err = loadLogList(gstaticV3AllLogsListFilename); err != nil {
		return err
	} else if err = addSignatureVerifiersForLogList(gstaticV3AllLogsList); err != nil {
		return err
	}

	if appleCurrentLogList, err = loadLogList(appleCurrentLogListFilename); err != nil {
		return err
	} else if err = addSignatureVerifiersForLogList(appleCurrentLogList); err != nil {
		return err
	}

	if crtshV3AllLogsList, err = loadLogList(crtshV3AllLogsListFilename); err != nil {
		return err
	} else if err = addSignatureVerifiersForLogList(crtshV3AllLogsList); err != nil {
		return err
	}

	return nil
}

func loadLogList(logListFilename string) (*loglist3.LogList, error) {
	if data, err := files.ReadFile(logListFilename); err != nil {
		return nil, err
	} else {
		return loglist3.NewFromJSON(data)
	}
}

func populateMaps(logPublicKey []byte, ti *loglist3.TemporalInterval) error {
	publicKey, err := x509.ParsePKIXPublicKey(logPublicKey)
	if err != nil {
		return err
	}

	logID := sha256.Sum256(logPublicKey)
	if logSignatureVerifierMap[logID] == nil {
		sv, err := ctgo.NewSignatureVerifier(publicKey)
		if err != nil {
			return err
		}
		logSignatureVerifierMap[logID] = sv
	}

	if ti != nil {
		if temporalIntervalMap[logID] == nil {
			temporalIntervalMap[logID] = ti
		} else {
			if ti.StartInclusive.After(temporalIntervalMap[logID].StartInclusive) {
				temporalIntervalMap[logID].StartInclusive = ti.StartInclusive
			}
			if ti.EndExclusive.Before(temporalIntervalMap[logID].EndExclusive) {
				temporalIntervalMap[logID].EndExclusive = ti.EndExclusive
			}
		}
	}

	return nil
}

func addSignatureVerifiersForLogList(logList *loglist3.LogList) error {
	for _, operator := range logList.Operators {
		for _, log := range operator.Logs {
			if err := populateMaps(log.Key, log.TemporalInterval); err != nil {
				return err
			}
		}
		for _, tiledLog := range operator.TiledLogs {
			if err := populateMaps(tiledLog.Key, tiledLog.TemporalInterval); err != nil {
				return err
			}
		}
	}

	return nil
}
