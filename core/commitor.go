package core

import "falcon/logger"

// MaxBlockBuffer bounds the commitor ring buffer and the storage rank space.
const MaxBlockBuffer = 100_000

// Commitor totally orders blocks via "partial sorting": a single cursor walks a
// ring buffer, advancing past each slot only once it is resolved — either a
// block was delivered (commit it) or the slot was skipped (a PES decision).
type Commitor struct {
	commitChannel chan<- *Block
	cleanupCh     chan [2]int
	blockCh       chan *Block
	filterCh      chan int
	committee     Committee
	buffer        []*Block
	filter        []bool
	curInd        int
}

func NewCommitor(commitChannel chan<- *Block, committee Committee) *Commitor {
	c := &Commitor{
		commitChannel: commitChannel,
		cleanupCh:     make(chan [2]int, 1_000),
		blockCh:       make(chan *Block, 1_000),
		filterCh:      make(chan int, 1_000),
		committee:     committee,
		buffer:        make([]*Block, MaxBlockBuffer),
		filter:        make([]bool, MaxBlockBuffer),
		curInd:        0,
	}
	go c.run()
	return c
}

// BufferBlock delivers a block into its ring-buffer slot.
func (c *Commitor) BufferBlock(b *Block) { c.blockCh <- b }

// FilterBlock marks a ring-buffer slot as skipped (empty).
func (c *Commitor) FilterBlock(ind int) { c.filterCh <- ind }

// CleanupChannel emits (epoch, height) of the last block committed in each run,
// which the core loop uses to prune stale state.
func (c *Commitor) CleanupChannel() <-chan [2]int { return c.cleanupCh }

func (c *Commitor) run() {
	for {
		select {
		case block := <-c.blockCh:
			c.buffer[block.Rank(c.committee)] = block
		case ind := <-c.filterCh:
			c.filter[ind] = true
		}
		c.tryToCommit()
	}
}

func (c *Commitor) tryToCommit() {
	committedEpoch, committedHeight, any := 0, 0, false
	for {
		if block := c.buffer[c.curInd]; block != nil {
			c.buffer[c.curInd] = nil
			if block.Batch.Txs != nil {
				logger.Info.Printf("commit Block epoch %d height %d batch_id %d \n", block.Epoch, block.Height, block.Batch.ID)
			}
			c.commitChannel <- block
			committedEpoch, committedHeight, any = block.Epoch, block.Height, true
			c.curInd = (c.curInd + 1) % MaxBlockBuffer
		} else if c.filter[c.curInd] {
			c.filter[c.curInd] = false
			c.curInd = (c.curInd + 1) % MaxBlockBuffer
		} else {
			break
		}
	}
	if any {
		c.cleanupCh <- [2]int{committedEpoch, committedHeight}
	}
}
