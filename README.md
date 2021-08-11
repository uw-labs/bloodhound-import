# bloodhound-import

`bloodhound-import` is a tool to run [SharpHound](https://github.com/BloodHoundAD/BloodHound) collector and import json data to Neo4j DB used by Bloodhound. 

`sharphound` binary is embed in to this app and its gets executed in-memory using [go-donut](https://github.com/Binject/go-donut)([donut](https://github.com/TheWover/donut)). 
bloodhound-import can also be used to just upload existing bloodhound json file to db using `--bhi-upload-only` flag.


Note: AzureAD data is not supported.


## usage
* execute and upload (windows only)

  Following command will execute sharphound with flag `--CollectionMethod All --SkipPortScan` and once its completed, it will parse and upload json data to neo4j db at `localhost:7687`.
        
   ```powershell
   $env:BHI_NEO4J_PASSWORD="P@ssw0rd"

   .\bloodhound-import.exe `
                --bhi-neo4j-url "bolt://localhost:7687" `
                --bhi-neo4j-username "neo4j" `
                --bhi-target-directory "C:\temp\bloodhound-import-output" `
                --CollectionMethod All `
                --SkipPortScan
   ```

* upload only
  
  Following command will only upload Bloodhound data to neo4j

  ```bash
  export BHI_NEO4J_URL="bolt+s://neo-db-url:443"
  export BHI_NEO4J_PASSWORD="P@ssw0rd"

  ./bloodhound-import --bhi-upload-only --bhi-delete-exiting-data --bhi-target-directory ./data
  ```

## Configuration

### Bloodhound-import configs

| ARGS | ENV variable  | example / explanation |
|-|-|-|
| --bhi-neo4j-url      | BHI_NEO4J_URL | neo4j db URL, it should include schema and port. 'bolt://[IP/Host]:7687', 'bolt+s://[IP/Host]:443' _default:`bolt://localhost:7687`_ |
| --bhi-neo4j-username | BHI_NEO4J_USERNAME | DB username for basic auth _default:`neo4j`_ |
| --bhi-neo4j-password | BHI_NEO4J_PASSWORD | DB password for basic auth |
| --bhi-target-directory  | BHI_NEO4J_PASSWORD  | folder where all unzipped SharpHound json files are exported and then uploaded to neo4j. Its also location of json data in `upload-only` mode |
| --bhi-upload-only |  | use upload only mode without running sharphound collector _default:`false`_ |
| --bhi-delete-exiting-data |  | when specified ALL existing data from database will be deleted before uploading new data _default:`false`_ |
| --bhi-delete-json-file |  | delete json files from target folder after upload is completed _default:`false`_ |
| --bhi-logfile |  | location of log file |
| --bhi-log-level |  | set logging level _default:`info`_ |
### supported SharpHound config flags
| ARGS  | example / explanation |
|-|-|
| --CollectionMethod | Specifies the CollectionMethod being used. |
| --OutputPrefix | Prefix to add to output files |
| --Stealth | Use stealth collection options, will sacrifice data quality in favour of much reduced _default: false_ |
| --Domain | Specifies the domain to enumerate. If not specified, will enumerate the current domain your user context specifies. |
| --WindowsOnly | Limits computer collection to systems that have an operating system attribute that matches *Windows* _default: false_ |
| --ComputerFile | A file containing a list of computers to enumerate. |
| --LdapFilter | Append this ldap filter to the search filter to further filter the results enumerated |
| --SearchBase | DistinguishedName to start LDAP searches at. Equivalent to the old --OU option |
| --PrettyJSON | Output 'pretty' json with formatting for readability _default: false_ |
| --CacheFilename |  Name for the cache file dropped to disk _default: uniqu_ hash generated per machine) |
| --RandomizeFilenames |  Randomize file names completely _default: false_ |
| --NoSaveCache | Don't write the cache file to disk. Caching will still be performed in memory. _default: false_ |
| --InvalidateCache | Invalidate and rebuild the cache file _default: false_ |
| --DomainController | Domain Controller to connect too. Specifying this can result in data loss |
| --LdapPort | Port LDAP is running on. Defaults to 389/686 for LDAPS |
| --SecureLDAP | Connect to LDAPS (LDAP SSL) instead of regular LDAP _default: false_ |
| --DisableKerberosSigning | Disables keberos signing/sealing, making LDAP traffic viewable _default: false_ |
| --LdapUsername | Username for connecting to LDAP. Use this if you're using a non-domain account for connecting to computers |
| --LdapPassword | Password for connecting to LDAP. Use this if you're using a non-domain account for connecting to computers |
| --SkipPortScan | Skip SMB port checks when connecting to computers _default: false_ |
| --PortScanTimeout |  Timeout for SMB port checks _default: "2000"_ |
| --ExcludeDomainControllers |  Exclude domain controllers from enumeration (useful to avoid Microsoft ATP/ATA) _default: false_ |
| --Throttle | Throttle requests to computers (in milliseconds) |
| --Jitter | Add jitter to throttle |
| --OverrideUserName | Override username to filter for NetSessionEnum |
| --NoRegistryLoggedOn |  Disable remote registry check in LoggedOn collection _default: false_ |
| --DumpComputerStatus |  Dumps error codes from attempts to connect to computers _default: false_ |
| --RealDNSName |  Overrides the DNS name used for API calls |
| --CollectAllProperties |  Collect all string LDAP properties on objects _default: false_ |
| --StatusInterval | Interval for displaying status in milliseconds |

### Unsupported SharpHound config flags
Following sharphound config flags are not supported by `bloodhound-import`

OutputDirectory¹, EncryptZip, ZipFilename, NoZip, Loop, LoopDuration, LoopInterval

¹ --OutputDirectory is set to `--bhi-target-directory`

## Node Types and Relationship
While importing data to neo4j app will create following types of nodes and relationships based on Bloodhound json data.

#### Node

```
(:Base :$objectType {objectid: $objectid} {$object.properties})  
```

#### Relationships

```
(:User|Computer) -- [:MemberOf] --> (:Group)
(:User|Computer) -- [:AllowedToDelegate] --> (:Computer)

(:User) -- [:HasSIDHistory] --> (:MemberType)
(:User) -- [:service,  {port: item.port}] --> (:Computer)

(:MemberType) -- [:AllowedToAct] --> (:Computer)
(:Computer) --- [:HasSession] ---> (:User)


(:MemberType) -- [:AdminTo {fromgpo: false|true}] --> (:Computer)
(:MemberType) -- [:CanRDP {fromgpo: false|true}] --> (:Computer)
(:MemberType) -- [:ExecuteDCOM {fromgpo: false|true}] --> (:Computer)
(:MemberType) -- [:CanPSRemote {fromgpo: false|true}] --> (:Computer)

(:GPO) -- [:GpLink {enforced: item.enforced}] --> (:OU|Domain)

(:OU|Domain) -- [:Contains] --> (:User|Computer|OU)

(:Domain) -- [:TrustedBy {sidfiltering: x, trusttype: y, transitive: z}] --> (:Domain)
```

#### ACE RelationShips
```
(n)-[r:TYPE {isacl: true, isinherited: false|true}]->(m)

where
TYPE =  AllExtendedRights
        ForceChangePassword
        AddMember
        AddAllowedToAct
        GenericAll
        WriteDacl
        WriteOwner
        GenericWrite
        Owns
        ReadLAPSPassword
        ReadGMSAPassword
        AceTyp
```
