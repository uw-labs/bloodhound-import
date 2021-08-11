package main

import (
	// #nosec G505
	"crypto/sha1"
	"fmt"
	"strings"
)

type cypher struct {
	statement string
	list      []map[string]interface{}
}

// used to create hash for cypher statement
// bypassing gosec as sha1 is only used to generate unique key in map
// #nosec G401
func hash(s string) string {
	return fmt.Sprintf("%x", sha1.Sum([]byte(s)))
}

func buildNodeStatement(objectType string) string {
	return fmt.Sprintf(`UNWIND $list AS item MERGE (n:Base {objectid: item.objectid}) SET n:%s SET n += item.properties`, objectType)
}

func buildRelStatement(sourceLabel, targetLabel, edgeType, edgeProp string) string {
	return fmt.Sprintf(`UNWIND $list AS item MERGE (n:Base {objectid: item.source}) ON CREATE SET n:%s MERGE (m:Base {objectid: item.target}) ON CREATE SET m:%s MERGE (n)-[r:%s %s]->(m)`,
		sourceLabel, targetLabel, edgeType, edgeProp)
}

func buildACEStatement(sourceType, targetType, label string) string {
	return fmt.Sprintf(
		`UNWIND $list AS item MERGE (n:Base {objectid: item.source}) ON CREATE SET n:%s MERGE (m:Base {objectid: item.target}) ON CREATE SET m:%s MERGE (n)-[r:%s {isacl: true, isinherited: item.isinherited}]->(m)`,
		sourceType, targetType, label)
}

func addACECyphers(cyphers map[string]*cypher, aces []ace, identifier, idType string) {
	for _, ace := range aces {
		if identifier == ace.PrincipalSID {
			continue
		}

		switch ace.AceType {
		case "All":
			buildAECCyphers(cyphers, ace, identifier, idType, "AllExtendedRights")
		case "User-Force-Change-Password":
			buildAECCyphers(cyphers, ace, identifier, idType, "ForceChangePassword")
		case "AddMember":
			buildAECCyphers(cyphers, ace, identifier, idType, "AddMember")
		case "AllowedToAct":
			buildAECCyphers(cyphers, ace, identifier, idType, "AddAllowedToAct")
		default:
			if ace.AceType != "" && ace.RightName == "ExtendedRight" {
				buildAECCyphers(cyphers, ace, identifier, idType, ace.AceType)
			}
		}

		switch ace.RightName {
		case "GenericAll":
			buildAECCyphers(cyphers, ace, identifier, idType, "GenericAll")
		case "WriteDacl":
			buildAECCyphers(cyphers, ace, identifier, idType, "WriteDacl")
		case "WriteOwner":
			buildAECCyphers(cyphers, ace, identifier, idType, "WriteOwner")
		case "GenericWrite":
			buildAECCyphers(cyphers, ace, identifier, idType, "GenericWrite")
		case "Owner":
			buildAECCyphers(cyphers, ace, identifier, idType, "Owns")
		case "ReadLAPSPassword":
			buildAECCyphers(cyphers, ace, identifier, idType, "ReadLAPSPassword")
		case "ReadGMSAPassword":
			buildAECCyphers(cyphers, ace, identifier, idType, "ReadGMSAPassword")
		}

	}
}

func buildAECCyphers(cyphers map[string]*cypher, ace ace, identifier, idType, aceType string) {
	var item = map[string]interface{}{
		"source":      ace.PrincipalSID,
		"target":      identifier,
		"isinherited": ace.IsInherited,
	}

	st := buildACEStatement(ace.PrincipalType, idType, aceType)
	ht := hash(st)
	if _, ok := cyphers[ht]; !ok {
		cyphers[ht] = new(cypher)
		cyphers[ht].statement = st
	}
	cyphers[ht].list = append(cyphers[ht].list, item)
}

func buildUserCyphers(users []user) map[string]*cypher {
	cyphers := make(map[string]*cypher)

	for _, u := range users {
		var identifier = u.ObjectIdentifier

		// Build node Cypher
		st := buildNodeStatement("User")
		ht := hash(st)
		if _, ok := cyphers[ht]; !ok {
			cyphers[ht] = new(cypher)
			cyphers[ht].statement = st
		}
		cyphers[ht].list = append(cyphers[ht].list, map[string]interface{}{"objectid": identifier, "properties": u.Properties})

		// create ACEs transactions
		addACECyphers(cyphers, u.Aces, identifier, "User")

		// Build primaryGroup Cypher
		st = buildRelStatement("User", "Group", "MemberOf", "{isacl:false}")
		ht = hash(st)
		if _, ok := cyphers[ht]; !ok {
			cyphers[ht] = new(cypher)
			cyphers[ht].statement = st
		}
		cyphers[ht].list = append(cyphers[ht].list, map[string]interface{}{"source": identifier, "target": u.PrimaryGroupSid})

		// Build allowedToDelegate Cypher
		if len(u.AllowedToDelegate) > 0 {
			st = buildRelStatement("User", "Computer", "AllowedToDelegate", "{isacl:false}")
			ht = hash(st)
			if _, ok := cyphers[ht]; !ok {
				cyphers[ht] = new(cypher)
				cyphers[ht].statement = st
			}
			for _, delegate := range u.AllowedToDelegate {
				cyphers[ht].list = append(cyphers[ht].list, map[string]interface{}{"source": identifier, "target": delegate})
			}
		}

		// Build HasSIDHistory Cypher
		for _, m := range u.HasSIDHistory {
			st = buildRelStatement("User", m.MemberType, "HasSIDHistory", "{isacl:false}")
			ht = hash(st)
			if _, ok := cyphers[ht]; !ok {
				cyphers[ht] = new(cypher)
				cyphers[ht].statement = st
			}
			cyphers[ht].list = append(cyphers[ht].list, map[string]interface{}{"source": identifier, "target": m.MemberID})
		}

		// Build SPNtargets Cypher
		for _, spn := range u.SPNTargets {
			st = buildRelStatement("User", "Computer", spn.Service, "{isacl:false, port: item.port}")
			ht = hash(st)
			if _, ok := cyphers[ht]; !ok {
				cyphers[ht] = new(cypher)
				cyphers[ht].statement = st
			}
			cyphers[ht].list = append(cyphers[ht].list, map[string]interface{}{
				"source": identifier,
				"target": spn.ComputerSid,
				"port":   spn.Port})
		}

	}

	return cyphers
}

func buildComputerCyphers(computers []computer) map[string]*cypher {
	cyphers := make(map[string]*cypher)

	for _, o := range computers {
		var identifier = o.ObjectIdentifier

		// Build node Cypher
		st := buildNodeStatement("Computer")
		ht := hash(st)
		if _, ok := cyphers[ht]; !ok {
			cyphers[ht] = new(cypher)
			cyphers[ht].statement = st
		}
		cyphers[ht].list = append(cyphers[ht].list, map[string]interface{}{"objectid": identifier, "properties": o.Properties})

		// create ACEs transactions
		addACECyphers(cyphers, o.Aces, identifier, "Computer")

		// Build primaryGroup Cypher
		st = buildRelStatement("Computer", "Group", "MemberOf", "{isacl:false}")
		ht = hash(st)
		if _, ok := cyphers[ht]; !ok {
			cyphers[ht] = new(cypher)
			cyphers[ht].statement = st
		}
		cyphers[ht].list = append(cyphers[ht].list, map[string]interface{}{"source": identifier, "target": o.PrimaryGroupSid})

		// Build allowedToDelegate Cypher
		// if len(o.AllowedToDelegate) > 0 {
		st = buildRelStatement("Computer", "Computer", "AllowedToDelegate", "{isacl:false}")
		ht = hash(st)
		if _, ok := cyphers[ht]; !ok {
			cyphers[ht] = new(cypher)
			cyphers[ht].statement = st
		}
		for _, delegate := range o.AllowedToDelegate {
			cyphers[ht].list = append(cyphers[ht].list, map[string]interface{}{"source": identifier, "target": delegate})
		}
		// }

		// check for AllowedToAct
		for _, act := range o.AllowedToAct {
			st = buildRelStatement(act.MemberType, "Computer", "AllowedToAct", "{isacl:false}")
			ht = hash(st)
			if _, ok := cyphers[ht]; !ok {
				cyphers[ht] = new(cypher)
				cyphers[ht].statement = st
			}
			cyphers[ht].list = append(cyphers[ht].list, map[string]interface{}{"source": act.MemberID, "target": identifier})
		}

		// check for HasSession
		for _, s := range o.Sessions {
			st = buildRelStatement("Computer", "User", "HasSession", "{isacl:false}")
			ht = hash(st)
			if _, ok := cyphers[ht]; !ok {
				cyphers[ht] = new(cypher)
				cyphers[ht].statement = st
			}
			cyphers[ht].list = append(cyphers[ht].list, map[string]interface{}{"source": s.ComputerID, "target": s.UserID})
		}

		// check for localAdmins
		for _, a := range o.LocalAdmins {
			st = buildRelStatement(a.MemberType, "Computer", "AdminTo", "{isacl:false, fromgpo: false}")
			ht = hash(st)
			if _, ok := cyphers[ht]; !ok {
				cyphers[ht] = new(cypher)
				cyphers[ht].statement = st
			}
			cyphers[ht].list = append(cyphers[ht].list, map[string]interface{}{"source": a.MemberID, "target": identifier})
		}

		// check for rdp
		for _, a := range o.RemoteDesktopUsers {
			st = buildRelStatement(a.MemberType, "Computer", "CanRDP", "{isacl:false, fromgpo: false}")
			ht = hash(st)
			if _, ok := cyphers[ht]; !ok {
				cyphers[ht] = new(cypher)
				cyphers[ht].statement = st
			}
			cyphers[ht].list = append(cyphers[ht].list, map[string]interface{}{"source": a.MemberID, "target": identifier})
		}

		// check for dcom
		for _, a := range o.DcomUsers {
			st = buildRelStatement(a.MemberType, "Computer", "ExecuteDCOM", "{isacl:false, fromgpo: false}")
			ht = hash(st)
			if _, ok := cyphers[ht]; !ok {
				cyphers[ht] = new(cypher)
				cyphers[ht].statement = st
			}
			cyphers[ht].list = append(cyphers[ht].list, map[string]interface{}{"source": a.MemberID, "target": identifier})
		}

		// check for psremote
		for _, a := range o.PSRemoteUsers {
			st = buildRelStatement(a.MemberType, "Computer", "CanPSRemote", "{isacl:false, fromgpo: false}")
			ht = hash(st)
			if _, ok := cyphers[ht]; !ok {
				cyphers[ht] = new(cypher)
				cyphers[ht].statement = st
			}
			cyphers[ht].list = append(cyphers[ht].list, map[string]interface{}{"source": a.MemberID, "target": identifier})

		}

	}

	return cyphers
}

func buildGroupCyphers(groups []group) map[string]*cypher {
	cyphers := make(map[string]*cypher)

	for _, o := range groups {
		var identifier = o.ObjectIdentifier

		// Build node Cypher
		st := buildNodeStatement("Group")
		ht := hash(st)
		if _, ok := cyphers[ht]; !ok {
			cyphers[ht] = new(cypher)
			cyphers[ht].statement = st
		}
		cyphers[ht].list = append(cyphers[ht].list, map[string]interface{}{"objectid": identifier, "properties": o.Properties})

		// create ACEs transactions
		addACECyphers(cyphers, o.Aces, identifier, "Group")

		for _, mem := range o.Members {
			if mem.MemberID == "" {
				continue
			}
			st = buildRelStatement(mem.MemberType, "Group", "MemberOf", "{isacl:false}")
			ht = hash(st)
			if _, ok := cyphers[ht]; !ok {
				cyphers[ht] = new(cypher)
				cyphers[ht].statement = st
			}
			cyphers[ht].list = append(cyphers[ht].list, map[string]interface{}{"source": mem.MemberID, "target": identifier})
		}
	}
	return cyphers
}

func buildGPOCyphers(gpos []gpo) map[string]*cypher {
	cyphers := make(map[string]*cypher)

	for _, o := range gpos {
		var identifier = o.ObjectIdentifier

		// Build node Cypher
		st := buildNodeStatement("GPO")
		ht := hash(st)
		if _, ok := cyphers[ht]; !ok {
			cyphers[ht] = new(cypher)
			cyphers[ht].statement = st
		}
		cyphers[ht].list = append(cyphers[ht].list, map[string]interface{}{"objectid": identifier, "properties": o.Properties})

		// create ACEs transactions
		addACECyphers(cyphers, o.Aces, identifier, "GPO")

	}
	return cyphers
}

func buildOUCyphers(ous []ou) map[string]*cypher {
	cyphers := make(map[string]*cypher)

	for _, o := range ous {
		var identifier = o.ObjectIdentifier

		// Build node Cypher
		st := buildNodeStatement("OU")
		ht := hash(st)
		if _, ok := cyphers[ht]; !ok {
			cyphers[ht] = new(cypher)
			cyphers[ht].statement = st
		}
		cyphers[ht].list = append(cyphers[ht].list, map[string]interface{}{"objectid": identifier, "properties": o.Properties})

		// create ACEs transactions
		addACECyphers(cyphers, o.Aces, identifier, "OU")

		// users
		st = buildRelStatement("OU", "User", "Contains", "{isacl: false}")
		ht = hash(st)
		if _, ok := cyphers[ht]; !ok {
			cyphers[ht] = new(cypher)
			cyphers[ht].statement = st
		}
		for _, u := range o.Users {
			cyphers[ht].list = append(cyphers[ht].list, map[string]interface{}{
				"source": identifier, "target": u})
		}

		// computer
		st = buildRelStatement("OU", "Computer", "Contains", "{isacl: false}")
		ht = hash(st)
		if _, ok := cyphers[ht]; !ok {
			cyphers[ht] = new(cypher)
			cyphers[ht].statement = st
		}
		for _, c := range o.Computers {
			cyphers[ht].list = append(cyphers[ht].list, map[string]interface{}{
				"source": identifier, "target": c})
		}

		// childOUs
		st = buildRelStatement("OU", "OU", "Contains", "{isacl: false}")
		ht = hash(st)
		if _, ok := cyphers[ht]; !ok {
			cyphers[ht] = new(cypher)
			cyphers[ht].statement = st
		}
		for _, co := range o.ChildOus {
			cyphers[ht].list = append(cyphers[ht].list, map[string]interface{}{
				"source": identifier, "target": co})
		}

		// Linked GPOs
		st = buildRelStatement("GPO", "OU", "GpLink", "{isacl: false, enforced: item.enforced}")
		ht = hash(st)
		if _, ok := cyphers[ht]; !ok {
			cyphers[ht] = new(cypher)
			cyphers[ht].statement = st
		}
		for _, l := range o.Links {
			cyphers[ht].list = append(cyphers[ht].list, map[string]interface{}{
				"source":   strings.ToUpper(l.GUID),
				"target":   identifier,
				"enforced": l.IsEnforced})
		}

		// check for localAdmins
		for _, a := range o.LocalAdmins {
			for _, c := range o.Computers {
				st = buildRelStatement(a.MemberType, "Computer", "AdminTo", "{isacl:false, fromgpo: true}")
				ht = hash(st)
				if _, ok := cyphers[ht]; !ok {
					cyphers[ht] = new(cypher)
					cyphers[ht].statement = st
				}
				cyphers[ht].list = append(cyphers[ht].list, map[string]interface{}{"source": a.MemberID, "target": c})
			}
		}

		// check for rdp
		for _, a := range o.RemoteDesktopUsers {
			for _, c := range o.Computers {
				st = buildRelStatement(a.MemberType, "Computer", "CanRDP", "{isacl:false, fromgpo: true}")
				ht = hash(st)
				if _, ok := cyphers[ht]; !ok {
					cyphers[ht] = new(cypher)
					cyphers[ht].statement = st
				}
				cyphers[ht].list = append(cyphers[ht].list, map[string]interface{}{"source": a.MemberID, "target": c})
			}
		}

		// check for dcom
		for _, a := range o.DcomUsers {
			for _, c := range o.Computers {
				st = buildRelStatement(a.MemberType, "Computer", "ExecuteDCOM", "{isacl:false, fromgpo: true}")
				ht = hash(st)
				if _, ok := cyphers[ht]; !ok {
					cyphers[ht] = new(cypher)
					cyphers[ht].statement = st
				}
				cyphers[ht].list = append(cyphers[ht].list, map[string]interface{}{"source": a.MemberID, "target": c})
			}
		}

		// check for psremote
		for _, a := range o.PSRemoteUsers {
			for _, c := range o.Computers {
				st = buildRelStatement(a.MemberType, "Computer", "CanPSRemote", "{isacl:false, fromgpo: true}")
				ht = hash(st)
				if _, ok := cyphers[ht]; !ok {
					cyphers[ht] = new(cypher)
					cyphers[ht].statement = st
				}
				cyphers[ht].list = append(cyphers[ht].list, map[string]interface{}{"source": a.MemberID, "target": c})
			}
		}

	}

	return cyphers
}

func buildDomainCyphers(domains []domain) map[string]*cypher {
	cyphers := make(map[string]*cypher)

	for _, o := range domains {
		var identifier = o.ObjectIdentifier

		// Build node Cypher
		st := buildNodeStatement("Domain")
		ht := hash(st)
		if _, ok := cyphers[ht]; !ok {
			cyphers[ht] = new(cypher)
			cyphers[ht].statement = st
		}
		cyphers[ht].list = append(cyphers[ht].list, map[string]interface{}{"objectid": identifier, "properties": o.Properties})

		// create ACEs transactions
		addACECyphers(cyphers, o.Aces, identifier, "Domain")

		// users
		st = buildRelStatement("Domain", "User", "Contains", "{isacl: false}")
		ht = hash(st)
		if _, ok := cyphers[ht]; !ok {
			cyphers[ht] = new(cypher)
			cyphers[ht].statement = st
		}
		for _, u := range o.Users {
			cyphers[ht].list = append(cyphers[ht].list, map[string]interface{}{
				"source": identifier, "target": u})
		}

		// computer
		st = buildRelStatement("Domain", "Computer", "Contains", "{isacl: false}")
		ht = hash(st)
		if _, ok := cyphers[ht]; !ok {
			cyphers[ht] = new(cypher)
			cyphers[ht].statement = st
		}
		for _, c := range o.Computers {
			cyphers[ht].list = append(cyphers[ht].list, map[string]interface{}{
				"source": identifier, "target": c})
		}

		// childOUs
		st = buildRelStatement("Domain", "OU", "Contains", "{isacl: false}")
		ht = hash(st)
		if _, ok := cyphers[ht]; !ok {
			cyphers[ht] = new(cypher)
			cyphers[ht].statement = st
		}
		for _, co := range o.ChildOus {
			cyphers[ht].list = append(cyphers[ht].list, map[string]interface{}{
				"source": identifier, "target": co})
		}

		// Linked GPOs
		st = buildRelStatement("GPO", "Domain", "GpLink", "{isacl: false, enforced: item.enforced}")
		ht = hash(st)
		if _, ok := cyphers[ht]; !ok {
			cyphers[ht] = new(cypher)
			cyphers[ht].statement = st
		}
		for _, l := range o.Links {
			cyphers[ht].list = append(cyphers[ht].list, map[string]interface{}{
				"source":   strings.ToUpper(l.GUID),
				"target":   identifier,
				"enforced": l.IsEnforced})
		}

		// check for localAdmins
		for _, a := range o.LocalAdmins {
			for _, c := range o.Computers {
				st = buildRelStatement(a.MemberType, "Computer", "AdminTo", "{isacl:false, fromgpo: true}")
				ht = hash(st)
				if _, ok := cyphers[ht]; !ok {
					cyphers[ht] = new(cypher)
					cyphers[ht].statement = st
				}
				cyphers[ht].list = append(cyphers[ht].list, map[string]interface{}{"source": a.MemberID, "target": c})
			}
		}

		// check for rdp
		for _, a := range o.RemoteDesktopUsers {
			for _, c := range o.Computers {
				st = buildRelStatement(a.MemberType, "Computer", "CanRDP", "{isacl:false, fromgpo: true}")
				ht = hash(st)
				if _, ok := cyphers[ht]; !ok {
					cyphers[ht] = new(cypher)
					cyphers[ht].statement = st
				}
				cyphers[ht].list = append(cyphers[ht].list, map[string]interface{}{"source": a.MemberID, "target": c})
			}
		}

		// check for dcom
		for _, a := range o.DcomUsers {
			for _, c := range o.Computers {
				st = buildRelStatement(a.MemberType, "Computer", "ExecuteDCOM", "{isacl:false, fromgpo: true}")
				ht = hash(st)
				if _, ok := cyphers[ht]; !ok {
					cyphers[ht] = new(cypher)
					cyphers[ht].statement = st
				}
				cyphers[ht].list = append(cyphers[ht].list, map[string]interface{}{"source": a.MemberID, "target": c})
			}
		}

		// check for psremote
		for _, a := range o.PSRemoteUsers {
			for _, c := range o.Computers {
				st = buildRelStatement(a.MemberType, "Computer", "CanPSRemote", "{isacl:false, fromgpo: true}")
				ht = hash(st)
				if _, ok := cyphers[ht]; !ok {
					cyphers[ht] = new(cypher)
					cyphers[ht].statement = st
				}
				cyphers[ht].list = append(cyphers[ht].list, map[string]interface{}{"source": a.MemberID, "target": c})
			}
		}

		// Domain Trust
		/*
			        TrustDirection
			        Disabled = 0
			        Inbound = 1,
			        Outbound = 2,
			        Bidirectional = 3

			        TrustType
			        ParentChild = 0,
			        CrossLink = 1,
			        Forest = 2,
			        External = 3,
					Unknown = 4
		*/
		for _, trust := range o.Trusts {
			var trustType string
			switch trust.TrustType {
			case 0:
				trustType = "ParentChild"
			case 1:
				trustType = "CrossLink"
			case 2:
				trustType = "Forest"
			case 3:
				trustType = "External"
			case 4:
				trustType = "Unknown"
			default:
				continue
			}

			target := trust.TargetDomainSid
			targetName := trust.TargetDomainName

			// create node for target domain
			st := buildNodeStatement("Domain")
			ht := hash(st)
			if _, ok := cyphers[ht]; !ok {
				cyphers[ht] = new(cypher)
				cyphers[ht].statement = st
			}
			cyphers[ht].list = append(cyphers[ht].list, map[string]interface{}{"objectid": target, "properties": map[string]interface{}{"name": targetName}})

			st = buildRelStatement("Domain", "Domain", "TrustedBy", "{sidfiltering: item.sidfiltering, trusttype: item.trusttype, transitive: item.transitive, isacl: false}")
			ht = hash(st)
			if _, ok := cyphers[ht]; !ok {
				cyphers[ht] = new(cypher)
				cyphers[ht].statement = st
			}
			if trust.TrustDirection == 1 || trust.TrustDirection == 3 {
				cyphers[ht].list = append(cyphers[ht].list, map[string]interface{}{
					"source":       identifier,
					"target":       target,
					"trusttype":    trustType,
					"transitive":   trust.IsTransitive,
					"sidfiltering": trust.SidFilteringEnabled,
				})

			}

			if trust.TrustDirection == 2 || trust.TrustDirection == 3 {
				cyphers[ht].list = append(cyphers[ht].list, map[string]interface{}{
					"source":       target,
					"target":       identifier,
					"trusttype":    trustType,
					"transitive":   trust.IsTransitive,
					"sidfiltering": trust.SidFilteringEnabled,
				})
			}
		}
	}
	return cyphers
}
