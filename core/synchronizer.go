package core

import (
	"encoding/binary"
	"time"

	"falcon/crypto"
	"falcon/logger"
	"falcon/store"
)

// rankKey is the storage/ring key for a slot, matching Block.Rank.
func rankKey(epoch, height, size int) []byte {
	rank := (epoch*size + height) % MaxBlockBuffer
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(rank))
	return b
}

// Synchronizer fetches blocks that a node learned about (via RBC votes) but has
// not yet received, retransmitting requests until the block appears in the store.
type Synchronizer struct {
	name       NodeID
	committee  Committee
	store      *store.Store
	transmitor *Transmitor
	sigService *crypto.SigService
	retryDelay int
	reqCh      chan slotKey
}

func NewSynchronizer(
	name NodeID,
	committee Committee,
	store *store.Store,
	transmitor *Transmitor,
	sigService *crypto.SigService,
	retryDelay int,
) *Synchronizer {
	s := &Synchronizer{
		name:       name,
		committee:  committee,
		store:      store,
		transmitor: transmitor,
		sigService: sigService,
		retryDelay: retryDelay,
		reqCh:      make(chan slotKey, 1_000),
	}
	go s.run()
	return s
}

// BlockRequest returns the block for a slot if it is already stored; otherwise it
// registers a pending sync request and returns nil.
func (s *Synchronizer) BlockRequest(epoch, height int) *Block {
	if block := s.readBlock(epoch, height); block != nil {
		return block
	}
	s.reqCh <- slotKey{epoch, height}
	return nil
}

func (s *Synchronizer) readBlock(epoch, height int) *Block {
	data, err := s.store.Read(rankKey(epoch, height, s.committee.Size()))
	if err != nil || len(data) == 0 {
		return nil
	}
	block := &Block{}
	if err := block.Decode(data); err != nil {
		return nil
	}
	// Guard against a ring-buffer collision from a much older slot.
	if block.Epoch != epoch || block.Height != height {
		return nil
	}
	return block
}

func (s *Synchronizer) sendRequest(slot slotKey) {
	msg, err := NewSyncRequestMsg(s.name, slot.epoch, slot.height, s.sigService)
	if err != nil {
		logger.Warn.Println(err)
		return
	}
	s.transmitor.Send(s.name, NONE, msg)
}

func (s *Synchronizer) run() {
	pending := make(map[slotKey]struct{})
	ticker := time.NewTicker(time.Millisecond * time.Duration(s.retryDelay))
	defer ticker.Stop()

	for {
		select {
		case slot := <-s.reqCh:
			if _, ok := pending[slot]; !ok {
				pending[slot] = struct{}{}
				s.sendRequest(slot)
			}
		case <-ticker.C:
			for slot := range pending {
				if s.readBlock(slot.epoch, slot.height) != nil {
					delete(pending, slot)
				} else {
					s.sendRequest(slot)
				}
			}
		}
	}
}
