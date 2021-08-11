package main

import (
	"context"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/neo4j/neo4j-go-driver/v4/neo4j"
	"github.com/sirupsen/logrus"
	"github.com/urfave/cli/v2"
)

var log = logrus.New()

func main() {
	app := cli.NewApp()
	app.Version = "0.1.0"
	app.Name = "bloodhound-import"
	app.Description = "This app will run Sharphound collector in memory and upload Bloodhound json data to neo4j graph database"

	// 'bhi-' prefix is required to filter out importer flags from Sharphound flags
	app.Flags = []cli.Flag{
		// Importer Flags
		&cli.StringFlag{
			Name:    "bhi-neo4j-url",
			EnvVars: []string{"BHI_NEO4J_URL"},
			Value:   "bolt://localhost:7687",
		},
		&cli.StringFlag{
			Name:    "bhi-neo4j-username",
			EnvVars: []string{"BHI_NEO4J_USERNAME"},
			Value:   "neo4j",
		},
		&cli.StringFlag{
			Name:     "bhi-neo4j-password",
			EnvVars:  []string{"BHI_NEO4J_PASSWORD"},
			Required: true,
		},
		&cli.StringFlag{
			Name:     "bhi-target-directory",
			EnvVars:  []string{"BHI_TARGET_DIRECTORY"},
			Usage:    "folder used as 'OutputDirectory' for sharphound or as target for uploading Bloodhound json file",
			Required: true,
		},
		&cli.BoolFlag{
			Name:  "bhi-upload-only",
			Usage: "use upload only mode without running sharphound collector. specify data folder with '--bhi-target-directory' flag",
		},
		&cli.BoolFlag{
			Name:  "bhi-delete-exiting-data",
			Usage: "before uploading new data ALL existing data from database will be deleted",
		},
		&cli.BoolFlag{
			Name:  "bhi-delete-json-file",
			Usage: "delete sharphound json file after upload",
		},
		&cli.StringFlag{
			Name:  "bhi-logfile",
			Usage: "location of log file",
		},
		&cli.StringFlag{
			Name:  "bhi-log-level",
			Value: "info",
		},
	}
	// Add sharpHound Flags
	app.Flags = append(app.Flags, sharpHoundFlags...)

	app.Action = func(c *cli.Context) (err error) {
		wp := &sync.WaitGroup{}
		wc := &sync.WaitGroup{}
		cypherChan := make(chan map[string]*cypher)

		ctx, cancel := context.WithCancel(c.Context)
		defer cancel()

		log.SetFormatter(&logrus.TextFormatter{
			FullTimestamp: true,
			DisableQuote:  true,
		})

		if c.String("bhi-logfile") != "" {
			file, err := os.OpenFile(c.String("bhi-logfile"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
			if err == nil {
				log.Out = file
			} else {
				log.Info("Failed to log to file, using default stdout")
			}
		}

		level, err := logrus.ParseLevel(c.String("bhi-log-level"))
		if err != nil {
			log.Error("unable to parse loglevel argument, setting loglevel to 'Info'")
			log.SetLevel(logrus.InfoLevel)
		} else {
			log.SetLevel(level)
		}

		log.Infof("connecting to %s", c.String("bhi-neo4j-url"))
		driver, err := neo4j.NewDriver(c.String("bhi-neo4j-url"),
			neo4j.BasicAuth(c.String("bhi-neo4j-username"), c.String("bhi-neo4j-password"), ""),
			func(config *neo4j.Config) {
				config.Log = neo4j.ConsoleLogger(neo4j.ERROR)
			},
		)
		if err != nil {
			return err
		}
		defer driver.Close()

		if err := driver.VerifyConnectivity(); err != nil {
			log.Error("unable to verify connectivity")
			return err
		}

		// Delete existing data from DB if flag is set
		if c.Bool("bhi-delete-exiting-data") {
			total, err := deleteExistingData(driver)
			if err != nil {
				log.Errorf("unable to delete existing data from database %s", err)
			}
			log.Infof("deleted %d existing nodes from database", total)
		}

		// graceful shutdown when terminate signal received.
		go gracefulShutdown(cancel)

		if !c.Bool("bhi-upload-only") {
			log.Infof("loading and running sharphound...")
			err = execSharpHound(ctx, c)
			if err != nil {
				return err
			}
		}

		log.Infof("starting DB upload...")
		// Get all json file from source folder
		files, err := getFileNames(c.String("bhi-target-directory"))
		if err != nil {
			return err
		}

		// start uploader
		// since user's and computer's nodes are mixed in many files only one uploader is used
		// multiple uploader will cause conflicts while adding nodes on neo4j
		wc.Add(1)
		go func() {
			err := uploadData(wc, driver, cypherChan)
			if err != nil {
				log.Fatalf("error uploading data %s", err)
			}
		}()

		// start data/file processors
		for _, f := range files {
			wp.Add(1)
			go func(f string) {
				err := processData(ctx, wp, f, cypherChan, c.Bool("bhi-delete-json-file"))
				if err != nil {
					log.Errorf("error processing %s - %s", f, err)
				}
			}(f)
		}

		// wait for producer and uploader to finish
		wp.Wait()
		// close channel and wait for uploader
		close(cypherChan)
		wc.Wait()
		return nil
	}

	if err := app.Run(os.Args); err != nil {
		log.Error(err)
		os.Exit(1)
	}
}

func getFileNames(dir string) ([]string, error) {
	files, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var jsonFiles []string
	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".json") {
			jsonFiles = append(jsonFiles, dir+"/"+file.Name())
		}
	}
	return jsonFiles, nil
}

func gracefulShutdown(cancel context.CancelFunc) {
	sCh := make(chan os.Signal, 1)
	signal.Notify(sCh, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	<-sCh
	log.Info("Shutting down...")
	// cancel context
	cancel()
}

func deleteExistingData(driver neo4j.Driver) (int64, error) {
	session := driver.NewSession(neo4j.SessionConfig{
		AccessMode: neo4j.AccessModeWrite,
	})
	defer session.Close()

	cypher := `MATCH (n)
			  WITH n LIMIT 1000
			  DETACH DELETE n
			  RETURN count(n) as deletedNodeCount`

	var total int64
	timeout := 1 * time.Minute

	for {
		record, err := neo4j.AsRecord(session.WriteTransaction(func(tx neo4j.Transaction) (interface{}, error) {
			return neo4j.Single(tx.Run(cypher, nil))
		}, neo4j.WithTxTimeout(timeout)))
		if err != nil {
			return 0, err
		}

		if c, ok := record.Get("deletedNodeCount"); ok {
			if c.(int64) == 0 {
				return total, nil
			}
			total += c.(int64)
		}
	}
}
