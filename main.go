package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"golang.org/x/exp/slices"
)

type IptablesRule struct {
	FragmentName    string `json:"fragment_name,omitempty"`
	Chain           string `json:"chain,omitempty"`
	Source          string `json:"source,omitempty"`
	Protocol        string `json:"protocol,omitempty"`
	Match           string `json:"match,omitempty"`
	DestinationPort string `json:"destination_port,omitempty"`
	SourcePort      string `json:"source_port,omitempty"`
	State           string `json:"state,omitempty"`
	Jump            string `json:"jump"`
}

// debug flag used to turn on debug messages
var debug bool

// log function that only prints if debug is true
func dlog(debugString string) {
	if debug {
		log.Println(debugString)
	}
}

var usageString = `Usage: iptables-parser [options]
Parse iptables rules and output them as JSON.
All top-level files in the directory will be parsed. Subdirectories are ignored.
See github.com/pkmollman/iptables-parser for more information.
`

var Usage = func() {
	fmt.Fprint(flag.CommandLine.Output(), usageString)
	flag.PrintDefaults()
}

func main() {
	// setting up flags and usage
	flag.Usage = Usage

	var iptablesFragmentDir string
	flag.StringVar(&iptablesFragmentDir, "dir", "/etc/iptables.d", "Directory containing iptables fragments")

	flag.BoolVar(&debug, "debug", false, "Turn on debug messages")

	var nsxJson bool
	flag.BoolVar(&nsxJson, "nsx", false, "Output NSX API rule objects instead of generic iptables-parser JSON")

	flag.Parse()

	files, err := os.ReadDir(iptablesFragmentDir)
	if err != nil {
		log.Fatalln(err)
	}

	rules := []IptablesRule{}
	nsxRules := []nsxRule{}

	for _, file := range files {
		if !file.IsDir() {
			iptFile, err := os.ReadFile(iptablesFragmentDir + "/" + file.Name())
			if err != nil {
				panic(err)
			}

			fileString := string(iptFile)

			for lineIndex, line := range strings.Split(fileString, "\n") {
				cleanLine := strings.TrimSpace(line)
				if len(cleanLine) > 0 && cleanLine[0] == '-' {
					dlog(fmt.Sprintf("Parsing Line %d of Fragment %s:", lineIndex, file.Name()))
					rule, err := parseIptablesRule(cleanLine)
					if err == nil {
						rule.FragmentName = file.Name()
						rules = append(rules, rule)
						if nsxJson {
							nsxRules = append(nsxRules, nsxRule{}.NewFromIptablesRule(rule))
						}
					}
				}
			}
		}
	}

	if nsxJson {
		nsxRules = collapseNsxRules(nsxRules)
		nsxJson, err := json.Marshal(nsxRules)
		if err != nil {
			panic(err)
		}
		fmt.Println(string(nsxJson))
		return
	}

	rulesJson, err := json.Marshal(rules)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(rulesJson))
}

// parseIptablesRule parses a single iptables rule and returns an IptablesRule struct
func parseIptablesRule(rule string) (IptablesRule, error) {
	iptflags := flag.NewFlagSet("iptflags", flag.ContinueOnError)

	var policyFlag string
	iptflags.StringVar(&policyFlag, "P", "", "Policy")
	iptflags.StringVar(&policyFlag, "policy", "", "Policy")

	var newChainFlag string
	iptflags.StringVar(&newChainFlag, "N", "", "new")
	iptflags.StringVar(&newChainFlag, "new-chain", "", "new")

	var appendChainFlag string
	iptflags.StringVar(&appendChainFlag, "A", "", "chain to append to")
	iptflags.StringVar(&appendChainFlag, "append", "", "chain to append to")

	var sourceFlag string
	iptflags.StringVar(&sourceFlag, "s", "", "source address")
	iptflags.StringVar(&sourceFlag, "source", "", "source address")
	iptflags.StringVar(&sourceFlag, "src", "", "source address")

	var destinationFlag string
	iptflags.StringVar(&destinationFlag, "d", "", "destination address")
	iptflags.StringVar(&destinationFlag, "destination", "", "destination address")
	iptflags.StringVar(&destinationFlag, "dst", "", "destination address")

	var protocol_flag string
	iptflags.StringVar(&protocol_flag, "p", "", "protocol")
	iptflags.StringVar(&protocol_flag, "protocol", "", "protocol")

	var match_flag string
	iptflags.StringVar(&match_flag, "m", "", "match")
	iptflags.StringVar(&match_flag, "match", "", "match")

	var destination_port_flag string
	iptflags.StringVar(&destination_port_flag, "dport", "", "destination port")
	iptflags.StringVar(&destination_port_flag, "dports", "", "destination port")

	var source_port_flag string
	iptflags.StringVar(&source_port_flag, "sport", "", "source port")

	var state_flag string
	iptflags.StringVar(&state_flag, "state", "", "state")

	var jump_flag string
	iptflags.StringVar(&jump_flag, "j", "", "jump")

	var tcpFlag string
	iptflags.StringVar(&tcpFlag, "tcp-flags", "", "tcp flags")

	var icmpTypeFlag string
	iptflags.StringVar(&icmpTypeFlag, "icmp-type", "", "tcp flags")

	var interface_flag string
	iptflags.StringVar(&interface_flag, "i", "", "interface")
	iptflags.StringVar(&interface_flag, "in-interface", "", "interface")

	var out_interface_flag string
	iptflags.StringVar(&out_interface_flag, "o", "", "out interface")
	iptflags.StringVar(&out_interface_flag, "out-interface", "", "out interface")

	var rejectWithFlag string
	iptflags.StringVar(&rejectWithFlag, "reject-with", "", "tcp flags")

	var toPorts string
	iptflags.StringVar(&toPorts, "to-ports", "", "remapped ports for NAT stuff")

	var synFlag bool
	iptflags.BoolVar(&synFlag, "syn", false, "syn flag")

	var packetType string
	iptflags.StringVar(&packetType, "pkt-type", "", "packet type")

	split_line := strings.Split(rule, " ")

	dlog(rule)

	lineArgs := []string{}

	for i, arg := range split_line {
		if arg == "" {
			continue
		}
		if i == 0 || arg[0] == '-' {
			lineArgs = append(lineArgs, arg)
		} else if lineArgs[len(lineArgs)-1][0] == '-' {
			lineArgs = append(lineArgs, arg)
		} else {
			lineArgs[len(lineArgs)-1] = lineArgs[len(lineArgs)-1] + " " + arg
		}
	}

	err := iptflags.Parse(lineArgs)
	if err != nil {
		log.Fatalln("Error parsing iptables rule: ", rule)
	}

	iptRule := IptablesRule{
		Chain:           appendChainFlag,
		Source:          sourceFlag,
		Protocol:        protocol_flag,
		DestinationPort: destination_port_flag,
		SourcePort:      source_port_flag,
		Jump:            jump_flag,
	}

	// these ignores should probably be handled by another tool, instead of being hardcoded here
	if policyFlag != "" {
		return iptRule, errors.New("ignored")
	}

	if newChainFlag != "" {
		return iptRule, errors.New("ignored")
	}

	if appendChainFlag == "INPUT" && jump_flag == "PUPPET-INPUT" {
		return iptRule, errors.New("ignored")
	}

	if appendChainFlag == "PUPPET-INPUT" && interface_flag == "lo" && jump_flag == "ACCEPT" {
		return iptRule, errors.New("ignored")
	}

	if appendChainFlag == "PUPPET-INPUT" && protocol_flag == "icmp" && icmpTypeFlag == "any" && jump_flag == "ACCEPT" {
		return iptRule, errors.New("ignored")
	}

	if appendChainFlag == "PUPPET-INPUT" && protocol_flag == "" && state_flag == "RELATED,ESTABLISHED" && jump_flag == "ACCEPT" {
		return iptRule, errors.New("ignored")
	}

	if appendChainFlag == "PUPPET-INPUT" && protocol_flag == "" && rejectWithFlag == "icmp-host-prohibited" && jump_flag == "REJECT" {
		return iptRule, errors.New("ignored")
	}

	if source_port_flag == "53" {
		return iptRule, errors.New("ignored")
	}

	return iptRule, nil
}

type L4PortSetServiceEntry struct {
	// TCP or UDP
	Protocol         string   `json:"l4_protocol"`
	SourcePorts      []string `json:"source_ports,omitempty"`
	DestinationPorts []string `json:"destination_ports,omitempty"`
	// single port or port range (e.g. 80 or 80-90)
	ResourceType string `json:"resource_type"`
}

type nsxRule struct {
	Name              string                  `json:"display_name,omitempty"`
	SourceGroups      []string                `json:"source_groups,omitempty"`
	DestinationGroups []string                `json:"destination_groups,omitempty"`
	Scope             string                  `json:"scope,omitempty"`
	Services          []string                `json:"services,omitempty"`
	ServiceEntries    []L4PortSetServiceEntry `json:"service_entries,omitempty"`
	// ACCEPT, REJECT, DROP
	Action       string `json:"action,omitempty"`
	Logged       bool   `json:"logged,omitempty"`
	ResourceType string `json:"resource_type"`
}

func (nsxRule) NewFromIptablesRule(iptRule IptablesRule) nsxRule {
	newRule := nsxRule{Name: fmt.Sprintf("%s-%s_%s", iptRule.FragmentName, iptRule.Protocol, iptRule.DestinationPort), ResourceType: "Rule", Logged: true}

	if iptRule.Source != "" {
		newRule.SourceGroups = []string{iptRule.Source}
	} else {
		newRule.SourceGroups = []string{"ANY"}
	}

	destPorts := stringToPorts(iptRule.DestinationPort)
	sourcePorts := stringToPorts(iptRule.SourcePort)
	serviceProtocol := strings.ToUpper(iptRule.Protocol)

	if serviceProtocol != "TCP" && serviceProtocol != "UDP" && serviceProtocol != "" {
		log.Println(iptRule)
		log.Fatalln("Unsupported protocol: ", iptRule.Protocol)
	}

	if serviceProtocol != "" {
		newRule.ServiceEntries = []L4PortSetServiceEntry{
			{
				Protocol:         serviceProtocol,
				SourcePorts:      sourcePorts,
				DestinationPorts: destPorts,
				ResourceType:     "L4PortSetServiceEntry",
			},
		}
	}
	newRule.Services = []string{"ANY"}

	switch iptRule.Jump {
	case "ALLOW", "ACCEPT":
		newRule.Action = "ALLOW"
	case "REJECT":
		newRule.Action = "REJECT"
	case "DROP":
		newRule.Action = "DROP"
	default:
		log.Fatalln("Unsupported jump: ", iptRule.Jump)
	}

	return newRule
}

func stringToPorts(portString string) []string {
	ports := []string{}
	splitPorts := strings.Split(portString, ",")
	for _, port := range splitPorts {
		if port == "" {
			continue
		}
		if strings.Contains(port, ":") {
			portRange := strings.Split(port, ":")
			ports = append(ports, portRange[0]+"-"+portRange[1])
		} else {
			ports = append(ports, port)
		}
	}
	return ports
}

// combine rules with the same action and name, and the same destination service entries
func collapseNsxRules(rules []nsxRule) []nsxRule {
	collapsedRules := []nsxRule{}
	handledIndexes := []int{}

	for mainIndex, mainRule := range rules {
		if !slices.Contains(handledIndexes, mainIndex) {
			for subIndex, subRule := range rules {
				if mainIndex != subIndex && !slices.Contains(handledIndexes, subIndex) {
					if mainRule.Action == subRule.Action && mainRule.Name == subRule.Name {
						for _, mainRuleService := range mainRule.ServiceEntries {
							for _, subRuleService := range subRule.ServiceEntries {
								if slices.Compare(mainRuleService.SourcePorts, subRuleService.SourcePorts) == 0 && slices.Compare(mainRuleService.DestinationPorts, subRuleService.DestinationPorts) == 0 && mainRuleService.Protocol == subRuleService.Protocol {
									mainRule.SourceGroups = append(mainRule.SourceGroups, subRule.SourceGroups...)
									handledIndexes = append(handledIndexes, subIndex)
								}
							}
						}
					}
				}
			}
			collapsedRules = append(collapsedRules, mainRule)
			handledIndexes = append(handledIndexes, mainIndex)
		}
	}

	return collapsedRules

}
