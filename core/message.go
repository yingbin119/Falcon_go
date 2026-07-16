package core

import (
	"bytes"
	"encoding/gob"
	"reflect"
	"strconv"

	"falcon/crypto"
	"falcon/pool"
)

// Protocol constants (mirrored from the Rust Falcon implementation).
const (
	RBC_ECHO  = 0
	RBC_READY = 1

	PRE_ONE = 0
	PRE_TWO = 1

	VAL_PHASE = 0
	MUX_PHASE = 1

	OPT = 1 // optimistic value (commit the block)
	PES = 0 // pessimistic value (skip the slot)
)

// ConsensusMessage is the interface carried over the network layer.
type ConsensusMessage interface {
	MsgType() int
	Hash() crypto.Digest
}

func intBytes(x int) []byte {
	return strconv.AppendInt(nil, int64(x), 2)
}

/**************************** Block ****************************/

// Block is the RBC proposal for a single (epoch, height) slot. Unlike the Rust
// version — which references mempool payloads by digest — the batch of
// transactions is embedded directly (Chimera-style pool).
type Block struct {
	Author    NodeID
	Epoch     int
	Height    int
	Batch     pool.Batch
	Signature crypto.Signature
}

func NewBlock(author NodeID, epoch, height int, batch pool.Batch, sigService *crypto.SigService) (*Block, error) {
	block := &Block{
		Author: author,
		Epoch:  epoch,
		Height: height,
		Batch:  batch,
	}
	sig, err := sigService.RequestSignature(block.Hash())
	if err != nil {
		return nil, err
	}
	block.Signature = sig
	return block, nil
}

func (b *Block) Encode() ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	if err := gob.NewEncoder(buf).Encode(b); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (b *Block) Decode(data []byte) error {
	return gob.NewDecoder(bytes.NewBuffer(data)).Decode(b)
}

func (b *Block) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(intBytes(int(b.Author)))
	hasher.Add(intBytes(b.Epoch))
	hasher.Add(intBytes(b.Height))
	for _, tx := range b.Batch.Txs {
		hasher.Add(tx)
	}
	return hasher.Sum256(nil)
}

func (b *Block) Verify(committee Committee) bool {
	return b.Signature.Verify(committee.Name(b.Author), b.Hash())
}

// Rank maps a slot to its ring-buffer index used by the commitor and store.
func (b *Block) Rank(committee Committee) int {
	return (b.Epoch*committee.Size() + b.Height) % MaxBlockBuffer
}

/**************************** RBC value ****************************/

type RBCValMsg struct {
	B *Block
}

func NewRBCValMsg(b *Block) *RBCValMsg { return &RBCValMsg{B: b} }

func (msg *RBCValMsg) Verify(committee Committee) bool { return msg.B.Verify(committee) }
func (msg *RBCValMsg) Hash() crypto.Digest             { return msg.B.Hash() }
func (msg *RBCValMsg) MsgType() int                    { return RBCValType }

/**************************** RBC echo ****************************/

type EchoMsg struct {
	Author    NodeID
	Epoch     int
	Height    int
	BlockHash crypto.Digest
	Signature crypto.Signature
}

func NewEchoMsg(author NodeID, epoch, height int, blockHash crypto.Digest, sigService *crypto.SigService) (*EchoMsg, error) {
	msg := &EchoMsg{Author: author, Epoch: epoch, Height: height, BlockHash: blockHash}
	sig, err := sigService.RequestSignature(msg.Hash())
	if err != nil {
		return nil, err
	}
	msg.Signature = sig
	return msg, nil
}

func (msg *EchoMsg) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(intBytes(int(msg.Author)))
	hasher.Add(intBytes(msg.Epoch))
	hasher.Add(intBytes(msg.Height))
	hasher.Add(msg.BlockHash[:])
	return hasher.Sum256(nil)
}

func (msg *EchoMsg) Verify(committee Committee) bool {
	return msg.Signature.Verify(committee.Name(msg.Author), msg.Hash())
}

func (msg *EchoMsg) MsgType() int { return EchoType }

/**************************** RBC ready ****************************/

type ReadyMsg struct {
	Author    NodeID
	Epoch     int
	Height    int
	BlockHash crypto.Digest
	Signature crypto.Signature
}

func NewReadyMsg(author NodeID, epoch, height int, blockHash crypto.Digest, sigService *crypto.SigService) (*ReadyMsg, error) {
	msg := &ReadyMsg{Author: author, Epoch: epoch, Height: height, BlockHash: blockHash}
	sig, err := sigService.RequestSignature(msg.Hash())
	if err != nil {
		return nil, err
	}
	msg.Signature = sig
	return msg, nil
}

func (msg *ReadyMsg) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(intBytes(int(msg.Author)))
	hasher.Add(intBytes(msg.Epoch))
	hasher.Add(intBytes(msg.Height))
	hasher.Add(msg.BlockHash[:])
	return hasher.Sum256(nil)
}

func (msg *ReadyMsg) Verify(committee Committee) bool {
	return msg.Signature.Verify(committee.Name(msg.Author), msg.Hash())
}

func (msg *ReadyMsg) MsgType() int { return ReadyType }

/**************************** Prepare ****************************/

type PrepareMsg struct {
	Author    NodeID
	Epoch     int
	Height    int
	Val       int
	Phase     int
	Signature crypto.Signature
}

func NewPrepareMsg(author NodeID, epoch, height, phase, val int, sigService *crypto.SigService) (*PrepareMsg, error) {
	msg := &PrepareMsg{Author: author, Epoch: epoch, Height: height, Phase: phase, Val: val}
	sig, err := sigService.RequestSignature(msg.Hash())
	if err != nil {
		return nil, err
	}
	msg.Signature = sig
	return msg, nil
}

func (msg *PrepareMsg) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(intBytes(int(msg.Author)))
	hasher.Add(intBytes(msg.Epoch))
	hasher.Add(intBytes(msg.Height))
	hasher.Add(intBytes(msg.Val))
	hasher.Add(intBytes(msg.Phase))
	return hasher.Sum256(nil)
}

func (msg *PrepareMsg) Verify(committee Committee) bool {
	return msg.Signature.Verify(committee.Name(msg.Author), msg.Hash())
}

func (msg *PrepareMsg) MsgType() int { return PrepareType }

/**************************** ABA value / mux ****************************/

// ABAValMsg carries both the VAL and MUX phases (distinguished by Phase). Its
// digest deliberately omits Phase and Val so the two phases from the same
// (author, epoch, height, round) share a signature, matching the Rust version.
type ABAValMsg struct {
	Author    NodeID
	Epoch     int
	Height    int
	Round     int
	Phase     int
	Val       int
	Signature crypto.Signature
}

func NewABAValMsg(author NodeID, epoch, height, round, val, phase int, sigService *crypto.SigService) (*ABAValMsg, error) {
	msg := &ABAValMsg{Author: author, Epoch: epoch, Height: height, Round: round, Val: val, Phase: phase}
	sig, err := sigService.RequestSignature(msg.Hash())
	if err != nil {
		return nil, err
	}
	msg.Signature = sig
	return msg, nil
}

func (msg *ABAValMsg) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(intBytes(int(msg.Author)))
	hasher.Add(intBytes(msg.Height))
	hasher.Add(intBytes(msg.Epoch))
	hasher.Add(intBytes(msg.Round))
	return hasher.Sum256(nil)
}

func (msg *ABAValMsg) Verify(committee Committee) bool {
	return msg.Signature.Verify(committee.Name(msg.Author), msg.Hash())
}

func (msg *ABAValMsg) MsgType() int { return ABAValType }

/**************************** ABA coin share ****************************/

type ABACoinShareMsg struct {
	Author NodeID
	Epoch  int
	Height int
	Round  int
	Share  crypto.SignatureShare
}

func NewABACoinShareMsg(author NodeID, epoch, height, round int, sigService *crypto.SigService) (*ABACoinShareMsg, error) {
	msg := &ABACoinShareMsg{Author: author, Epoch: epoch, Height: height, Round: round}
	share, err := sigService.RequestTsSugnature(msg.Hash())
	if err != nil {
		return nil, err
	}
	msg.Share = share
	return msg, nil
}

func (msg *ABACoinShareMsg) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(intBytes(msg.Round))
	hasher.Add(intBytes(msg.Height))
	hasher.Add(intBytes(msg.Epoch))
	return hasher.Sum256(nil)
}

func (msg *ABACoinShareMsg) Verify() bool { return msg.Share.Verify(msg.Hash()) }

func (msg *ABACoinShareMsg) MsgType() int { return ABACoinShareType }

/**************************** ABA output ****************************/

type ABAOutputMsg struct {
	Author    NodeID
	Epoch     int
	Height    int
	Round     int
	Val       int
	Signature crypto.Signature
}

func NewABAOutputMsg(author NodeID, epoch, height, round, val int, sigService *crypto.SigService) (*ABAOutputMsg, error) {
	msg := &ABAOutputMsg{Author: author, Epoch: epoch, Height: height, Round: round, Val: val}
	sig, err := sigService.RequestSignature(msg.Hash())
	if err != nil {
		return nil, err
	}
	msg.Signature = sig
	return msg, nil
}

func (msg *ABAOutputMsg) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(intBytes(int(msg.Author)))
	hasher.Add(intBytes(msg.Epoch))
	hasher.Add(intBytes(msg.Height))
	hasher.Add(intBytes(msg.Round))
	return hasher.Sum256(nil)
}

func (msg *ABAOutputMsg) Verify(committee Committee) bool {
	return msg.Signature.Verify(committee.Name(msg.Author), msg.Hash())
}

func (msg *ABAOutputMsg) MsgType() int { return ABAOutputType }

/**************************** Sync request / reply ****************************/

type SyncRequestMsg struct {
	Author    NodeID // requester
	Epoch     int
	Height    int
	Signature crypto.Signature
}

func NewSyncRequestMsg(author NodeID, epoch, height int, sigService *crypto.SigService) (*SyncRequestMsg, error) {
	msg := &SyncRequestMsg{Author: author, Epoch: epoch, Height: height}
	sig, err := sigService.RequestSignature(msg.Hash())
	if err != nil {
		return nil, err
	}
	msg.Signature = sig
	return msg, nil
}

func (msg *SyncRequestMsg) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(intBytes(int(msg.Author)))
	hasher.Add(intBytes(msg.Epoch))
	hasher.Add(intBytes(msg.Height))
	return hasher.Sum256(nil)
}

func (msg *SyncRequestMsg) Verify(committee Committee) bool {
	return msg.Signature.Verify(committee.Name(msg.Author), msg.Hash())
}

func (msg *SyncRequestMsg) MsgType() int { return SyncRequestType }

type SyncReplyMsg struct {
	B *Block
}

func NewSyncReplyMsg(b *Block) *SyncReplyMsg { return &SyncReplyMsg{B: b} }

func (msg *SyncReplyMsg) Verify(committee Committee) bool { return msg.B.Verify(committee) }
func (msg *SyncReplyMsg) Hash() crypto.Digest             { return msg.B.Hash() }
func (msg *SyncReplyMsg) MsgType() int                    { return SyncReplyType }

/**************************** RBCProof (internal) ****************************/

// ProofVote records one contributor to an RBC quorum certificate.
type ProofVote struct {
	Author    NodeID
	Signature crypto.Signature
}

// RBCProof is an internal quorum certificate (never sent over the wire).
type RBCProof struct {
	Epoch  int
	Height int
	Votes  []ProofVote
	Tag    int
}

/**************************** message registry ****************************/

const (
	RBCValType int = iota
	EchoType
	ReadyType
	PrepareType
	ABAValType
	ABACoinShareType
	ABAOutputType
	SyncRequestType
	SyncReplyType
	TotalNums
)

var DefaultMsgTypes = map[int]reflect.Type{
	RBCValType:       reflect.TypeOf(RBCValMsg{}),
	EchoType:         reflect.TypeOf(EchoMsg{}),
	ReadyType:        reflect.TypeOf(ReadyMsg{}),
	PrepareType:      reflect.TypeOf(PrepareMsg{}),
	ABAValType:       reflect.TypeOf(ABAValMsg{}),
	ABACoinShareType: reflect.TypeOf(ABACoinShareMsg{}),
	ABAOutputType:    reflect.TypeOf(ABAOutputMsg{}),
	SyncRequestType:  reflect.TypeOf(SyncRequestMsg{}),
	SyncReplyType:    reflect.TypeOf(SyncReplyMsg{}),
}
