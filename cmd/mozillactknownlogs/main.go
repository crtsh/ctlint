package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strconv"
	"time"

	"github.com/google/certificate-transparency-go/loglist3"

	"software.sslmate.com/src/certspotter/loglist/mozilla"
)

func main() {
	exitCode := -1
	defer func() { os.Exit(int(exitCode)) }()

	if len(os.Args) != 3 {
		fmt.Printf("Usage: %s <Log List JSON File> <CTKnownLogs.h URL>\n", os.Args[0])
		return
	}

	// We can only parse CTKnownLogs.h since Firefox 142.
	re1 := regexp.MustCompile(`[0-9]+`)
	match := re1.FindStringSubmatch(os.Args[2])
	if len(match) < 1 || match[0] == "" {
		log.Fatalf("Could not determine Firefox version from URL: %s\n", os.Args[2])
	}
	firefoxVersion, err := strconv.Atoi(match[0])
	if err != nil {
		log.Fatalf("Could not parse Firefox version from string %s: %v\n", match[0], err)
	}
	if firefoxVersion < 142 {
		log.Fatalf("CTKnownLogs.h parsing only supported since Firefox 142; got version %d\n", firefoxVersion)
	}

	// Open previous JSON log list file if it exists; else create a new, empty JSON log list timestamped with the Firefox 141.0.3 list's expiry timestamp minus 70 days.
	var logList *loglist3.LogList
	if data, err := os.ReadFile(os.Args[1]); err != nil {
		logList = &loglist3.LogList{}
		logList.LogListTimestamp = time.UnixMicro(1758540558000000).Add(-70 * 24 * time.Hour)
	} else if logList, err = loglist3.NewFromJSON(data); err != nil {
		log.Fatal(err)
	}

	// Fetch CTKnownLogs.h from the specified URL.
	fmt.Printf("%s:\n", os.Args[2])
	resp, err := http.Get(os.Args[2])
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Fatal(resp.Status)
	}

	// Copy the fetched CTKnownLogs.h, because it needs to be parsed twice.
	var bodyCopy bytes.Buffer
	tee := io.TeeReader(resp.Body, &bodyCopy)
	io.ReadAll(&bodyCopy)

	// Parse CTKnownLogs.h to extract the lists of logs and operators.
	mozillaLogs, mozillaOperators, err := mozilla.Parse(tee)
	if err != nil {
		log.Fatalf("mozilla.Parse => %v", err)
	}

	// Derive the log list timestamp from the expiration timestamp, which is defined as follows:
	// https://wiki.mozilla.org/SecurityEngineering/Certificate_Transparency#Known_CT_Logs
	// "This information has a 10 week expiration time. That is, if 10 weeks have passed since the information has been updated (typically by updating Firefox itself), the implementation will no longer enforce certificate transparency."
	re2 := regexp.MustCompile(`static const PRTime kCTExpirationTime = INT64_C\(([^}]*)\);`)
	match = re2.FindStringSubmatch(bodyCopy.String())
	var expirationTime int
	if len(match) < 2 || match[1] == "" {
		log.Printf("kCTExpirationTime not present in Mozilla CTKnownLogs.h; using current time minus 70 days")
		expirationTime = int(time.Now().Add(-70 * 24 * time.Hour).UnixMicro())
	} else {
		expirationTime, err = strconv.Atoi(match[1])
		if err != nil {
			log.Fatalf("Could not parse kCTExpirationTime: %v\n", err)
		}
	}

	// Ensure the fetched CTKnownLogs.h is newer than the existing JSON log list.
	if logList.LogListTimestamp.After(time.UnixMicro(int64(expirationTime)).Add(-70 * 24 * time.Hour)) {
		log.Fatal("Fetched CTKnownLogs.h is older than the existing JSON log list")
	}
	previousLogListExpirationTime := logList.LogListTimestamp.Add(70 * 24 * time.Hour)
	logList.LogListTimestamp = time.UnixMicro(int64(expirationTime)).Add(-70 * 24 * time.Hour)

	// Ensure all operators from CTKnownLogs.h are present in the JSON log list.
label_nextOperator1:
	for _, mo := range mozillaOperators {
		for _, jo := range logList.Operators {
			if mo.Name == jo.Name {
				continue label_nextOperator1
			}
		}
		fmt.Printf("- Adding new operator: %s\n", mo.Name)
		logList.Operators = append(logList.Operators, &loglist3.Operator{
			Name:      mo.Name,
			Email:     []string{},
			Logs:      []*loglist3.Log{},
			TiledLogs: []*loglist3.TiledLog{},
		})
	}

	// Remove operators from the JSON log list that are no longer present in CTKnownLogs.h.
label_nextOperator2:
	for i, jo := range logList.Operators {
		for _, mo := range mozillaOperators {
			if mo.Name == jo.Name {
				continue label_nextOperator2
			}
		}
		fmt.Printf("- Removing operator: %s\n", jo.Name)
		logList.Operators = slices.Delete(logList.Operators, i, i+1)
		goto label_nextOperator2 // Delete modifies slice; restart loop.
	}

	// Add each new log from CTKnownLogs.h, and each new transition to Retired, to the JSON log list.
	for i, mo := range mozillaOperators {
		for _, ml := range mozillaLogs {
			if ml.OperatorIndex == i {
				// Find the same operator in the JSON log list.
				var operator *loglist3.Operator
				for _, jo := range logList.Operators {
					if mo.Name == jo.Name {
						operator = jo
						break
					}
				}
				if operator == nil {
					log.Fatalf("Operator %s not found in JSON log list", mo.Name)
				}

				// Calculate the LogID.
				logID := sha256.Sum256(ml.Key)

				// Prepare the log states and associated timestamps.
				var logStates loglist3.LogStates
				switch ml.State {
				case "Admissible":
					logStates.Qualified = &loglist3.LogState{Timestamp: logList.LogListTimestamp}
					logStates.Usable = &loglist3.LogState{Timestamp: previousLogListExpirationTime}
				case "Retired":
					logStates.Retired = &loglist3.LogState{Timestamp: ml.Timestamp}
				}

				switch ml.Protocol {
				case "RFC6962":
					var log *loglist3.Log
					for _, jl := range operator.Logs {
						if bytes.Equal(jl.LogID, logID[:]) {
							log = jl
							break
						}
					}
					if log == nil {
						fmt.Printf("- Adding new RFC6962 log: %s\n", ml.Name)
						operator.Logs = append(operator.Logs, &loglist3.Log{
							Description: ml.Name,
							LogID:       logID[:],
							Key:         ml.Key,
							State:       &logStates,
						})
					} else if logStates.Retired != nil {
						log.State.Qualified = nil
						log.State.Usable = nil
						if log.State.Retired == nil {
							fmt.Printf("- Marking RFC6962 log as Retired: %s\n", ml.Name)
							log.State.Retired = logStates.Retired
						} else if logStates.Retired.Timestamp.Before(log.State.Retired.Timestamp) {
							fmt.Printf("- Backdating RFC6962 log Retired timestamp: %s\n", ml.Name)
							log.State.Retired = logStates.Retired
						}
					}
				case "Tiled":
					var tiledLog *loglist3.TiledLog
					for _, jtl := range operator.TiledLogs {
						if bytes.Equal(jtl.LogID, logID[:]) {
							tiledLog = jtl
							break
						}
					}
					if tiledLog == nil {
						fmt.Printf("- Adding new Tiled log: %s\n", ml.Name)
						operator.TiledLogs = append(operator.TiledLogs, &loglist3.TiledLog{
							Description: ml.Name,
							LogID:       logID[:],
							Key:         ml.Key,
							State:       &logStates,
						})
					} else if logStates.Retired != nil {
						tiledLog.State.Qualified = nil
						tiledLog.State.Usable = nil
						if tiledLog.State.Retired == nil {
							fmt.Printf("- Marking RFC6962 log as Retired: %s\n", ml.Name)
							tiledLog.State.Retired = logStates.Retired
						} else if logStates.Retired.Timestamp.Before(tiledLog.State.Retired.Timestamp) {
							fmt.Printf("- Backdating RFC6962 log Retired timestamp: %s\n", ml.Name)
							tiledLog.State.Retired = logStates.Retired
						}
					}
				}
			}
		}
	}

	// Remove any log from the JSON log list that is no longer present in CTKnownLogs.h.
	for _, jo := range logList.Operators {
	label_nextLog1:
		for i, jl := range jo.Logs {
			var found bool
			for _, ml := range mozillaLogs {
				logID := sha256.Sum256(ml.Key)
				if bytes.Equal(jl.LogID, logID[:]) {
					found = true
					break
				}
			}
			if !found {
				fmt.Printf("- Removing RFC6962 log: %s\n", jl.Description)
				jo.Logs = slices.Delete(jo.Logs, i, i+1)
				goto label_nextLog1 // Delete modifies slice; restart loop.
			}
		}

	label_nextLog2:
		for i, jtl := range jo.TiledLogs {
			var found bool
			for _, ml := range mozillaLogs {
				logID := sha256.Sum256(ml.Key)
				if bytes.Equal(jtl.LogID, logID[:]) {
					found = true
					break
				}
			}
			if !found {
				fmt.Printf("- Removing Tiled log: %s\n", jtl.Description)
				jo.TiledLogs = slices.Delete(jo.TiledLogs, i, i+1)
				goto label_nextLog2 // Delete modifies slice; restart loop.
			}
		}
	}

	// Write the updated JSON log list back to file.
	encoded, err := json.Marshal(logList)
	if err != nil {
		log.Fatal(err)
	}
	var indented bytes.Buffer
	json.Indent(&indented, encoded, "", "  ")
	err = os.WriteFile(os.Args[1], indented.Bytes(), 0644)
	if err != nil {
		log.Fatal(err)
	}

	exitCode = 0
}
