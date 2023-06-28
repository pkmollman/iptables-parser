package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
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
Parse iptables rules and output them as JSON or a human readable format (TODO).
They may be parsed from a single file (TODO), or a directory. When a directory is specified,
all top-level files in the directory will be parsed. Subdirectories are ignored.
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

	flag.Parse()

	files, err := os.ReadDir(iptablesFragmentDir)
	if err != nil {
		log.Fatalln(err)
	}

	rules := []IptablesRule{}

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
					}
				}
			}
		}
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
