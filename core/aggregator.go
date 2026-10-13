package core

import (
	"encoding/binary"

	"falcon/crypto"
)

type slotKey struct {
	epoch  int
	height int
}

type prepareKey struct {
	epoch  int
	height int
	phase  int
}

type roundKey struct {
	epoch  int
	height int
	round  int
}

// RBCProofMaker collects echo or ready votes for one slot.
type RBCProofMaker struct {
	weight int
	votes  []ProofVote
	used   map[NodeID]struct{}
}

func newRBCProofMaker() *RBCProofMaker {
	return &RBCProofMaker{used: make(map[NodeID]struct{})}
}

// Append adds a vote and returns a proof when a threshold is crossed. Echo
// makers fire once (2f+1); ready makers fire at both f+1 and 2f+1.
func (m *RBCProofMaker) Append(epoch, height int, author NodeID, tag int, sig crypto.Signature, committee Committee) *RBCProof {
	if _, ok := m.used[author]; ok {
		return nil
	}
	m.used[author] = struct{}{}
	m.votes = append(m.votes, ProofVote{Author: author, Signature: sig})
	m.weight++

	if m.weight == committee.HightThreshold() ||
		(tag == RBC_READY && m.weight == committee.LowThreshold()) {
		votes := make([]ProofVote, len(m.votes))
		copy(votes, m.votes)
		return &RBCProof{Epoch: epoch, Height: height, Votes: votes, Tag: tag}
	}
	return nil
}

// PrepareMaker collects optimistic/pessimistic prepare votes for one phase.
type PrepareMaker struct {
	optnum int
	pesnum int
	used   map[NodeID]struct{}
}

func newPrepareMaker() *PrepareMaker {
	return &PrepareMaker{used: make(map[NodeID]struct{})}
}

// Append returns (val, flag, true) once 2f+1 prepares are gathered. flag==true
// means the votes are unanimous (val 为全票值); flag==false means mixed votes,
// val is the carried value (有 OPT 则 OPT).
func (m *PrepareMaker) Append(p *PrepareMsg, committee Committee) (int, bool, bool) {
	if _, ok := m.used[p.Author]; ok { //去重, ok = false
		return 0, false, false
	}
	m.used[p.Author] = struct{}{}
	if p.Val == OPT {
		m.optnum++
	} else {
		m.pesnum++
	}

	if m.optnum+m.pesnum == committee.HightThreshold() {
		if m.optnum >= committee.HightThreshold() {
			return OPT, true, true
		} else if m.optnum > 0 {
			return OPT, false, true
		}
		return PES, true, true
	}
	//未到2f + 1, ok = false
	return 0, false, false
}

// RandomCoinMaker collects threshold-signature shares and reconstructs the coin.
type RandomCoinMaker struct {
	weight int
	shares []crypto.SignatureShare
	used   map[NodeID]struct{}
}

func newRandomCoinMaker() *RandomCoinMaker {
	return &RandomCoinMaker{used: make(map[NodeID]struct{})}
}

// Append returns (coin, true, nil) once f+1 shares combine into the common coin.
func (m *RandomCoinMaker) Append(share *ABACoinShareMsg, committee Committee, skey crypto.SecretShareKey) (int, bool, error) {
	if _, ok := m.used[share.Author]; ok {
		return 0, false, nil
	}
	m.used[share.Author] = struct{}{}
	m.shares = append(m.shares, share.Share)
	m.weight++

	if m.weight == committee.LowThreshold() {
		sig, err := crypto.CombineIntactTSPartial(m.shares, skey, share.Hash())
		if err != nil {
			return 0, false, err
		}
		coin := int(binary.BigEndian.Uint64(sig[:8]) % 2)
		return coin, true, nil
	}
	return 0, false, nil
}

// Aggregator owns all per-slot vote/share collectors.
type Aggregator struct {
	committee     Committee
	echoMakers    map[slotKey]*RBCProofMaker
	readyMakers   map[slotKey]*RBCProofMaker
	prepareMakers map[prepareKey]*PrepareMaker
	coinMakers    map[roundKey]*RandomCoinMaker
}

func NewAggregator(committee Committee) *Aggregator {
	return &Aggregator{
		committee:     committee,
		echoMakers:    make(map[slotKey]*RBCProofMaker),
		readyMakers:   make(map[slotKey]*RBCProofMaker),
		prepareMakers: make(map[prepareKey]*PrepareMaker),
		coinMakers:    make(map[roundKey]*RandomCoinMaker),
	}
}

func (a *Aggregator) AddEchoVote(echo *EchoMsg) *RBCProof {
	key := slotKey{echo.Epoch, echo.Height}
	m, ok := a.echoMakers[key]
	if !ok {
		m = newRBCProofMaker()
		a.echoMakers[key] = m
	}
	return m.Append(echo.Epoch, echo.Height, echo.Author, RBC_ECHO, echo.Signature, a.committee)
}

func (a *Aggregator) AddReadyVote(ready *ReadyMsg) *RBCProof {
	key := slotKey{ready.Epoch, ready.Height}
	m, ok := a.readyMakers[key]
	if !ok {
		m = newRBCProofMaker()
		a.readyMakers[key] = m
	}
	return m.Append(ready.Epoch, ready.Height, ready.Author, RBC_READY, ready.Signature, a.committee)
}

func (a *Aggregator) AddPrepareVote(p *PrepareMsg) (int, bool, bool) {
	key := prepareKey{p.Epoch, p.Height, p.Phase}
	m, ok := a.prepareMakers[key]
	if !ok {
		m = newPrepareMaker()
		a.prepareMakers[key] = m
	}
	return m.Append(p, a.committee)
}

func (a *Aggregator) AddCoinShare(share *ABACoinShareMsg, skey crypto.SecretShareKey) (int, bool, error) {
	key := roundKey{share.Epoch, share.Height, share.Round}
	m, ok := a.coinMakers[key]
	if !ok {
		m = newRandomCoinMaker()
		a.coinMakers[key] = m
	}
	return m.Append(share, a.committee, skey)
}

// Cleanup drops collectors for slots at or below the monotonic rank threshold.
func (a *Aggregator) Cleanup(epoch, height int) {
	threshold := epoch*a.committee.Size() + height
	size := a.committee.Size()
	for k := range a.echoMakers {
		if k.epoch*size+k.height <= threshold {
			delete(a.echoMakers, k)
		}
	}
	for k := range a.readyMakers {
		if k.epoch*size+k.height <= threshold {
			delete(a.readyMakers, k)
		}
	}
	for k := range a.prepareMakers {
		if k.epoch*size+k.height <= threshold {
			delete(a.prepareMakers, k)
		}
	}
	for k := range a.coinMakers {
		if k.epoch*size+k.height <= threshold {
			delete(a.coinMakers, k)
		}
	}
}
