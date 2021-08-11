package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io/ioutil"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/neo4j/neo4j-go-driver/v4/neo4j"
)

func parseFile(file string) (*bloodHoundRawData, error) {
	jsonFile, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer jsonFile.Close()

	fileByte, err := ioutil.ReadAll(jsonFile)
	if err != nil {
		return nil, err
	}

	var bloodHoundData bloodHoundRawData

	// remove UTF-8 BOM!!
	fileByte = bytes.TrimPrefix(fileByte, []byte("\xef\xbb\xbf"))

	if err := json.Unmarshal(fileByte, &bloodHoundData); err != nil {
		return nil, err
	}
	return &bloodHoundData, nil
}

func processData(
	ctx context.Context,
	wc *sync.WaitGroup,
	file string,
	cypherChan chan<- map[string]*cypher,
	deleteJsonFile bool,
) error {
	defer wc.Done()

	log.Debugf("processing file %s ... ", file)

	data, err := parseFile(file)
	if err != nil {
		return err
	}
	batch := 10

	defer cleanUp(data.Meta.Type, time.Now(), file, deleteJsonFile)

	switch strings.ToLower(data.Meta.Type) {
	case "computers":
		slice := data.Computers
		for i := 0; i < len(slice); i += batch {
			j := i + batch
			if j > len(slice) {
				j = len(slice)
			}
			select {
			case <-ctx.Done():
				return nil
			case cypherChan <- buildComputerCyphers(slice[i:j]):
			}

		}
	case "users":
		slice := data.Users
		for i := 0; i < len(slice); i += batch {
			j := i + batch
			if j > len(slice) {
				j = len(slice)
			}
			select {
			case <-ctx.Done():
				return nil
			case cypherChan <- buildUserCyphers(slice[i:j]):
			}

		}
	case "groups":
		slice := data.Groups
		for i := 0; i < len(slice); i += batch {
			j := i + batch
			if j > len(slice) {
				j = len(slice)
			}
			select {
			case <-ctx.Done():
				return nil
			case cypherChan <- buildGroupCyphers(slice[i:j]):
			}

		}
	case "ous":
		slice := data.OUs
		for i := 0; i < len(slice); i += batch {
			j := i + batch
			if j > len(slice) {
				j = len(slice)
			}
			select {
			case <-ctx.Done():
				return nil
			case cypherChan <- buildOUCyphers(slice[i:j]):
			}

		}
	case "gpos":
		slice := data.Gpos
		for i := 0; i < len(slice); i += batch {
			j := i + batch
			if j > len(slice) {
				j = len(slice)
			}
			select {
			case <-ctx.Done():
				return nil
			case cypherChan <- buildGPOCyphers(slice[i:j]):
			}

		}
	case "domains":
		slice := data.Domains
		for i := 0; i < len(slice); i += batch {
			j := i + batch
			if j > len(slice) {
				j = len(slice)
			}
			select {
			case <-ctx.Done():
				return nil
			case cypherChan <- buildDomainCyphers(slice[i:j]):
			}
		}
	}

	return nil
}

func cleanUp(object string, start time.Time, file string, deleteJsonFile bool) {
	log.Infof("finished uploading %s data in %.2f min", object, time.Since(start).Minutes())

	if deleteJsonFile {
		if err := os.Remove(file); err != nil {
			log.Errorf("unable to delete %s err:%s", file, err)
		}
	}
}

func uploadData(wc *sync.WaitGroup, driver neo4j.Driver, cypherChan <-chan map[string]*cypher) error {
	defer wc.Done()

	session := driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer session.Close()

	timeout := 1 * time.Minute

	for cyphers := range cypherChan {
		for _, c := range cyphers {
			if len(c.list) == 0 {
				continue
			}
			_, err := session.Run(c.statement, map[string]interface{}{"list": c.list}, neo4j.WithTxTimeout(timeout))
			if err != nil {
				return err
			}
		}
	}

	return nil
}
