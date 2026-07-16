package core

import "falcon/crypto"

// Parameters holds the consensus-layer tunables for Falcon.
type Parameters struct {
	SyncTimeout   int  `json:"sync_timeout"`    // ms to wait after all peers are online before starting
	NetworkDelay  int  `json:"network_delay"`   // ms artificial delay used by the DDoS filter
	MinBlockDelay int  `json:"min_block_delay"` // ms delay after proposing a block
	DDos          bool `json:"ddos"`            // delay all RBC proposals
	Faults        int  `json:"faults"`          // nodes with height < Faults stay silent (crash faults)
	RetryDelay    int  `json:"retry_delay"`     // ms between block-sync retransmissions
	Fallback      int  `json:"fallback"`        // epoch lag before the pessimistic ABA fallback triggers
}

var DefaultParameters = Parameters{
	SyncTimeout:   500,
	NetworkDelay:  2_000,
	MinBlockDelay: 0,
	DDos:          false,
	Faults:        0,
	RetryDelay:    5_000,
	Fallback:      1,
}

type NodeID int

const NONE NodeID = -1

type Authority struct {
	Name crypto.PublickKey `json:"name"`
	Id   NodeID            `json:"node_id"`
	Addr string            `json:"addr"`
}

type Committee struct {
	Authorities map[NodeID]Authority `json:"authorities"`
}

func (c Committee) ID(name crypto.PublickKey) NodeID {
	for id, authority := range c.Authorities {
		if authority.Name.Pubkey.Equal(name.Pubkey) {
			return id
		}
	}
	return NONE
}

func (c Committee) Size() int {
	return len(c.Authorities)
}

func (c Committee) Name(id NodeID) crypto.PublickKey {
	a := c.Authorities[id]
	return a.Name
}

func (c Committee) Address(id NodeID) string {
	a := c.Authorities[id]
	return a.Addr
}

func (c Committee) BroadCast(id NodeID) []string {
	addrs := make([]string, 0)
	for nodeid, a := range c.Authorities {
		if nodeid != id {
			addrs = append(addrs, a.Addr)
		}
	}
	return addrs
}

// HightThreshold is the 2f+1 quorum.
func (c Committee) HightThreshold() int {
	n := len(c.Authorities)
	return 2*((n-1)/3) + 1
}

// LowThreshold is the f+1 quorum (also the common-coin reveal threshold).
func (c Committee) LowThreshold() int {
	n := len(c.Authorities)
	return (n-1)/3 + 1
}
