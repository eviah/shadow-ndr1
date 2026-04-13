package parser

import (
	"fmt"
	"sync"

	"github.com/rs/zerolog/log"
)

type ParsedData struct {
	Protocol   string                 `json:"protocol"`
	ParsedData map[string]interface{} `json:"parsed_data"`
}

type ProtocolInfo struct {
	Name      string
	Ports     []int
	Signature []byte
	Parser    func([]byte) (*ParsedData, error)
}

var (
	protocolRegistry = make(map[string]*ProtocolInfo)
	portToProtocol   = make(map[int][]string)
	registryMu       sync.RWMutex
)

func RegisterProtocol(info *ProtocolInfo) {
	registryMu.Lock()
	defer registryMu.Unlock()
	protocolRegistry[info.Name] = info
	for _, p := range info.Ports {
		portToProtocol[p] = append(portToProtocol[p], info.Name)
	}
	log.Debug().Str("protocol", info.Name).Msg("Protocol registered")
}

// Aviation stubs
func rustParseADS_B(data []byte) (*ParsedData, error) {
	return &ParsedData{
		Protocol:   "adsb",
		ParsedData: map[string]interface{}{"raw": fmt.Sprintf("%x", data)},
	}, nil
}

func rustParseARINC429(data []byte) (*ParsedData, error) {
	return &ParsedData{
		Protocol:   "arinc429",
		ParsedData: map[string]interface{}{"raw": fmt.Sprintf("%x", data)},
	}, nil
}

func rustParseACARS(data []byte) (*ParsedData, error) {
	return &ParsedData{
		Protocol:   "acars",
		ParsedData: map[string]interface{}{"raw": fmt.Sprintf("%x", data)},
	}, nil
}

func rustParseAFDX(data []byte) (*ParsedData, error) {
	return &ParsedData{
		Protocol:   "afdx",
		ParsedData: map[string]interface{}{"raw": fmt.Sprintf("%x", data)},
	}, nil
}

// Detect protocol by port
func detectByPort(port int) []string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	return portToProtocol[port]
}

// Detect by signature (ADS‑B, ARINC 429, etc.)
func detectBySignature(data []byte) string {
	if len(data) < 2 {
		return ""
	}
	// ADS‑B (Mode S) detection – simplistic, can be improved
	if len(data) >= 4 && data[0] == 0x8D && data[1] == 0x00 {
		return "adsb"
	}
	// ARINC 429 often starts with 0x01
	if len(data) >= 1 && data[0] == 0x01 {
		return "arinc429"
	}
	// ACARS often contains "ACARS"
	if len(data) > 5 && (string(data[:5]) == "ACARS" || string(data[:5]) == "acars") {
		return "acars"
	}
	// AFDX can be identified by EtherType 0x88D7 in a full frame, but for raw data we'll rely on port
	return ""
}

// Main Parse function
func Parse(data []byte, dstPort int) (*ParsedData, error) {
	possible := detectByPort(dstPort)
	if len(possible) > 0 {
		for _, proto := range possible {
			if info, ok := protocolRegistry[proto]; ok && info.Parser != nil {
				res, err := info.Parser(data)
				if err == nil {
					return res, nil
				}
				log.Debug().Err(err).Str("protocol", proto).Msg("Parser failed")
			}
		}
	}
	if sigProto := detectBySignature(data); sigProto != "" {
		if info, ok := protocolRegistry[sigProto]; ok && info.Parser != nil {
			res, err := info.Parser(data)
			if err == nil {
				return res, nil
			}
			log.Debug().Err(err).Str("protocol", sigProto).Msg("Signature parser failed")
		}
	}
	return &ParsedData{
		Protocol:   "unknown",
		ParsedData: map[string]interface{}{"raw": fmt.Sprintf("%x", data)},
	}, nil
}

// Convenience functions
func ParseADS_B(data []byte) (*ParsedData, error) {
	if info, ok := protocolRegistry["adsb"]; ok && info.Parser != nil {
		return info.Parser(data)
	}
	return rustParseADS_B(data)
}

func ParseARINC429(data []byte) (*ParsedData, error) {
	if info, ok := protocolRegistry["arinc429"]; ok && info.Parser != nil {
		return info.Parser(data)
	}
	return rustParseARINC429(data)
}

func ParseACARS(data []byte) (*ParsedData, error) {
	if info, ok := protocolRegistry["acars"]; ok && info.Parser != nil {
		return info.Parser(data)
	}
	return rustParseACARS(data)
}

func ParseAFDX(data []byte) (*ParsedData, error) {
	if info, ok := protocolRegistry["afdx"]; ok && info.Parser != nil {
		return info.Parser(data)
	}
	return rustParseAFDX(data)
}

func DetectProtocol(data []byte, dstPort int) string {
	possible := detectByPort(dstPort)
	if len(possible) > 0 {
		return possible[0]
	}
	if sig := detectBySignature(data); sig != "" {
		return sig
	}
	return "unknown"
}

func init() {
	RegisterProtocol(&ProtocolInfo{
		Name:   "adsb",
		Ports:  []int{1090},
		Parser: rustParseADS_B,
	})
	RegisterProtocol(&ProtocolInfo{
		Name:   "arinc429",
		Ports:  []int{2323},
		Parser: rustParseARINC429,
	})
	RegisterProtocol(&ProtocolInfo{
		Name:   "acars",
		Ports:  []int{13155},
		Parser: rustParseACARS,
	})
	RegisterProtocol(&ProtocolInfo{
		Name:   "afdx",
		Ports:  []int{1234},
		Parser: rustParseAFDX,
	})
}
