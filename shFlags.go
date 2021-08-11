package main

import "github.com/urfave/cli/v2"

// https://github.com/BloodHoundAD/SharpHound3/blob/32e663cc7a35bebf65b7b72bf2ad26c88e755266/SharpHound3/Options.cs
// https://bloodhound.readthedocs.io/en/latest/data-collection/sharphound-all-flags.html
var (
	sharpHoundFlags = []cli.Flag{
		&cli.StringFlag{
			Name:  "CollectionMethod",
			Usage: "Specifies the CollectionMethod being used. ",
		},
		&cli.StringFlag{
			Name:  "OutputPrefix",
			Usage: "Prefix to add to output files",
		},
		&cli.BoolFlag{
			Name:  "Stealth",
			Usage: "Use stealth collection options, will sacrifice data quality in favour of much reduced",
		},
		&cli.StringFlag{
			Name:  "Domain",
			Usage: "Specifies the domain to enumerate. If not specified, will enumerate the current domain your user context specifies.",
		},
		&cli.BoolFlag{
			Name:  "WindowsOnly",
			Usage: "Limits computer collection to systems that have an operating system attribute that matches *Windows*",
		},
		&cli.StringFlag{
			Name:  "ComputerFile",
			Usage: "A file containing a list of computers to enumerate.",
		},
		&cli.StringFlag{
			Name:  "LdapFilter",
			Usage: "Append this ldap filter to the search filter to further filter the results enumerated",
		},
		&cli.StringFlag{
			Name:  "SearchBase",
			Usage: "DistinguishedName to start LDAP searches at. Equivalent to the old --OU option",
		},
		&cli.BoolFlag{
			Name:  "PrettyJSON",
			Usage: "Output 'pretty' json with formatting for readability",
		},
		&cli.StringFlag{
			Name:  "CacheFilename",
			Usage: "Name for the cache file dropped to disk (default: unique hash generated per machine)",
		},
		&cli.BoolFlag{
			Name:  "RandomizeFilenames",
			Usage: "Randomize file names completely",
		},
		&cli.BoolFlag{
			Name:  "NoSaveCache",
			Usage: "Don't write the cache file to disk. Caching will still be performed in memory.",
		},
		&cli.BoolFlag{
			Name:  "InvalidateCache",
			Usage: "Invalidate and rebuild the cache file",
		},
		&cli.StringFlag{
			Name:  "DomainController",
			Usage: "Domain Controller to connect too. Specifying this can result in data loss",
		},
		&cli.StringFlag{
			Name:  "LdapPort",
			Usage: "Port LDAP is running on. Defaults to 389/686 for LDAPS",
		},
		&cli.BoolFlag{
			Name:  "SecureLDAP",
			Usage: "Connect to LDAPS (LDAP SSL) instead of regular LDAP",
		},
		&cli.BoolFlag{
			Name:  "DisableKerberosSigning",
			Usage: "Disables keberos signing/sealing, making LDAP traffic viewable",
		},
		&cli.StringFlag{
			Name:  "LdapUsername",
			Usage: "Username for connecting to LDAP. Use this if you're using a non-domain account for connecting to computers",
		},
		&cli.StringFlag{
			Name:  "LdapPassword",
			Usage: "Password for connecting to LDAP. Use this if you're using a non-domain account for connecting to computers",
		},
		&cli.BoolFlag{
			Name:  "SkipPortScan",
			Usage: "Skip SMB port checks when connecting to computers",
		},
		&cli.StringFlag{
			Name:  "PortScanTimeout",
			Usage: "Timeout for SMB port checks",
			Value: "2000",
		},
		&cli.BoolFlag{
			Name:  "ExcludeDomainControllers",
			Usage: "Exclude domain controllers from enumeration (useful to avoid Microsoft ATP/ATA)",
		},
		&cli.StringFlag{
			Name:  "Throttle",
			Usage: "Throttle requests to computers (in milliseconds)",
		},
		&cli.StringFlag{
			Name:  "Jitter",
			Usage: "Add jitter to throttle",
		},
		&cli.StringFlag{
			Name:  "OverrideUserName",
			Usage: "Override username to filter for NetSessionEnum",
		},
		&cli.BoolFlag{
			Name:  "NoRegistryLoggedOn",
			Usage: "Disable remote registry check in LoggedOn collection",
		},
		&cli.BoolFlag{
			Name:  "DumpComputerStatus",
			Usage: "Dumps error codes from attempts to connect to computers",
		},
		&cli.StringFlag{
			Name:  "RealDNSName",
			Usage: "Overrides the DNS name used for API calls",
		},
		&cli.BoolFlag{
			Name:  "CollectAllProperties",
			Usage: "Collect all string LDAP properties on objects",
		},
		&cli.StringFlag{
			Name:  "StatusInterval",
			Usage: "Interval for displaying status in milliseconds",
		},

		// Not supported in bloodhound-import

		// &cli.StringFlag{
		// 	Name:     "OutputDirectory",
		// 	Usage:    "Folder to output files too",
		// 	Required: true,
		// }

		// &cli.BoolFlag{
		// 	Name:  "EncryptZip",
		// 	Usage: "Encrypt the zip file with a random password",
		// },
		// &cli.StringFlag{
		// 	Name:  "ZipFilename",
		// 	Usage: "Name for the zip file output by data collection",
		// },
		// &cli.BoolFlag{
		// 	Name:  "NoZip",
		// 	Usage: "Do NOT zip the json files, set to True as zip files are not supported",
		// 	Value: true,
		// },

		// &cli.StringFlag{
		// 	Name:  "Loop",
		// 	Usage: "Perform looping for computer collection",
		// },
		// &cli.StringFlag{
		// 	Name:  "LoopDuration",
		// 	Usage: "Duration to perform looping (Default 02:00:00)",
		// },
		// &cli.StringFlag{
		// 	Name:  "LoopInterval",
		// 	Usage: "Interval to sleep between loops (Default 00:05:00)",
		// },
	}
)
