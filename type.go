package main

type bloodHoundRawData struct {
	Gpos      []gpo      `json:"gpos"`
	Domains   []domain   `json:"domains"`
	Computers []computer `json:"computers"`
	Groups    []group    `json:"groups"`
	OUs       []ou       `json:"ous"`
	Users     []user     `json:"users"`

	Meta struct {
		// Possible types are: users, groups, ous, computers, gpos, domains
		Type    string `json:"type"`
		Count   int    `json:"count"`
		Version int    `json:"version"`
	} `json:"meta"`
}

type domain struct {
	ObjectIdentifier string                 `json:"ObjectIdentifier"`
	Properties       map[string]interface{} `json:"Properties"`
	Users            []string               `json:"Users"`
	Computers        []string               `json:"Computers"`
	ChildOus         []string               `json:"ChildOus"`
	Trusts           []struct {
		TargetDomainSid     string `json:"TargetDomainSid"`
		IsTransitive        bool   `json:"IsTransitive"`
		TrustDirection      int    `json:"TrustDirection"`
		TrustType           int    `json:"TrustType"`
		SidFilteringEnabled bool   `json:"SidFilteringEnabled"`
		TargetDomainName    string `json:"TargetDomainName"`
	} `json:"Trusts"`
	Links              []link   `json:"Links"`
	RemoteDesktopUsers []member `json:"RemoteDesktopUsers"`
	LocalAdmins        []member `json:"LocalAdmins"`
	DcomUsers          []member `json:"DcomUsers"`
	PSRemoteUsers      []member `json:"PSRemoteUsers"`
	Aces               []ace    `json:"Aces"`
}

type computer struct {
	ObjectIdentifier   string                 `json:"ObjectIdentifier"`
	Properties         map[string]interface{} `json:"Properties"`
	AllowedToDelegate  []string               `json:"AllowedToDelegate"`
	AllowedToAct       []member               `json:"AllowedToAct"`
	PrimaryGroupSid    string                 `json:"PrimaryGroupSid"`
	Sessions           []session              `json:"Sessions"`
	LocalAdmins        []member               `json:"LocalAdmins"`
	RemoteDesktopUsers []member               `json:"RemoteDesktopUsers"`
	DcomUsers          []member               `json:"DcomUsers"`
	PSRemoteUsers      []member               `json:"PSRemoteUsers"`
	Aces               []ace                  `json:"Aces"`
}

type user struct {
	ObjectIdentifier  string                 `json:"ObjectIdentifier"`
	Properties        map[string]interface{} `json:"Properties"`
	AllowedToDelegate []string               `json:"AllowedToDelegate"`
	SPNTargets        []spnTarget            `json:"SPNTargets"`
	PrimaryGroupSid   string                 `json:"PrimaryGroupSid"`
	HasSIDHistory     []member               `json:"HasSIDHistory"`
	Aces              []ace                  `json:"Aces"`
}

type gpo struct {
	ObjectIdentifier string                 `json:"ObjectIdentifier"`
	Properties       map[string]interface{} `json:"Properties"`
	Aces             []ace                  `json:"Aces"`
}

type group struct {
	ObjectIdentifier string `json:"ObjectIdentifier"`

	Properties map[string]interface{} `json:"Properties"`
	Members    []member               `json:"Members"`
	Aces       []ace                  `json:"Aces"`
}

type ou struct {
	ObjectIdentifier   string                 `json:"ObjectIdentifier"`
	Properties         map[string]interface{} `json:"Properties"`
	Links              []link                 `json:"Links"`
	ACLProtected       bool                   `json:"ACLProtected"`
	Users              []string               `json:"Users"`
	Computers          []string               `json:"Computers"`
	ChildOus           []string               `json:"ChildOus"`
	RemoteDesktopUsers []member               `json:"RemoteDesktopUsers"`
	LocalAdmins        []member               `json:"LocalAdmins"`
	DcomUsers          []member               `json:"DcomUsers"`
	PSRemoteUsers      []member               `json:"PSRemoteUsers"`
	Aces               []ace                  `json:"Aces"`
}

type session struct {
	UserID     string `json:"UserId"`
	ComputerID string `json:"ComputerId"`
}

type ace struct {
	PrincipalSID  string `json:"PrincipalSID"`
	PrincipalType string `json:"PrincipalType"`
	RightName     string `json:"RightName"`
	AceType       string `json:"AceType"`
	IsInherited   bool   `json:"IsInherited"`
}

type member struct {
	MemberID   string `json:"MemberId"`
	MemberType string `json:"MemberType"`
}

type link struct {
	IsEnforced bool   `json:"IsEnforced"`
	GUID       string `json:"Guid"`
}

type spnTarget struct {
	ComputerSid string `json:"ComputerSid"`
	Port        int    `json:"Port"`
	Service     string `json:"Service"`
}
