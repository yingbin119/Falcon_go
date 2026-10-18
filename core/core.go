package core

import (
	"time"

	"falcon/crypto"
	"falcon/logger"
	"falcon/pool"
	"falcon/store"
)

type proofKey struct {
	epoch  int
	height int
	tag    int
}

// Core is the Falcon asynchronous-BFT state machine. All protocol state is
// owned by the single Run goroutine; sub-components (synchronizer, commitor)
// communicate back over channels.
type Core struct {
	name          NodeID
	committee     Committee
	parameters    Parameters
	store         *store.Store
	sigService    *crypto.SigService
	txpool        *pool.Pool
	transmitor    *Transmitor
	synchronizer  *Synchronizer
	aggregator    *Aggregator
	commitor      *Commitor
	commitChannel chan<- *Block
	loopBackCh    chan ConsensusMessage

	epoch       int // current epoch (this node's proposal height advances here)
	height      int // this node's fixed RBC lane (== its committee id)
	fallbackLag int

	// RBC state
	buffers         map[slotKey]bool
	rbcProofs       map[proofKey]*RBCProof
	rbcReady        map[slotKey]bool
	rbcEpochOutputs map[int]map[int]bool

	// Prepare state
	prepareFlags map[slotKey]bool

	// ABA state
	abaValues     map[roundKey][2]map[NodeID]bool
	abaValuesFlag map[roundKey][2]bool
	abaValSent    map[roundKey][2]bool
	abaMuxValues  map[roundKey][2]map[NodeID]bool
	abaMuxFlags   map[roundKey][2]bool
	abaMuxSent    map[roundKey]bool
	abaCoinSent   map[roundKey]bool
	abaOutputs    map[roundKey]map[NodeID]bool
	abaOutputSent map[roundKey]bool
	abaEnds       map[slotKey]bool
}

func NewCore(
	name NodeID,
	committee Committee,
	parameters Parameters,
	txpool *pool.Pool,
	transmitor *Transmitor,
	store *store.Store,
	sigService *crypto.SigService,
	commitChannel chan<- *Block,
) *Core {
	c := &Core{
		name:          name,
		committee:     committee,
		parameters:    parameters,
		store:         store,
		sigService:    sigService,
		txpool:        txpool,
		transmitor:    transmitor,
		commitChannel: commitChannel,
		loopBackCh:    make(chan ConsensusMessage, 10_000),
		epoch:         0,
		height:        int(name), //每个节点固定的 RBC 通道（= 自己的节点 ID）
		fallbackLag:   parameters.Fallback,

		buffers:         make(map[slotKey]bool),
		rbcProofs:       make(map[proofKey]*RBCProof),
		rbcReady:        make(map[slotKey]bool),
		rbcEpochOutputs: make(map[int]map[int]bool),
		prepareFlags:    make(map[slotKey]bool),
		abaValues:       make(map[roundKey][2]map[NodeID]bool),
		abaValuesFlag:   make(map[roundKey][2]bool),
		abaValSent:      make(map[roundKey][2]bool),
		abaMuxValues:    make(map[roundKey][2]map[NodeID]bool),
		abaMuxFlags:     make(map[roundKey][2]bool),
		abaMuxSent:      make(map[roundKey]bool),
		abaCoinSent:     make(map[roundKey]bool),
		abaOutputs:      make(map[roundKey]map[NodeID]bool),
		abaOutputSent:   make(map[roundKey]bool),
		abaEnds:         make(map[slotKey]bool),
	}
	c.aggregator = NewAggregator(committee)
	c.commitor = NewCommitor(commitChannel, committee)
	c.synchronizer = NewSynchronizer(name, committee, store, transmitor, sigService, parameters.RetryDelay)
	return c
}

/**************************** helpers ****************************/

func (c *Core) rank(epoch, height int) int {
	return (epoch*c.committee.Size() + height) % MaxBlockBuffer
}

// loopback self-delivers one of our own messages back into the event loop
// without ever blocking it.
func (c *Core) loopback(msg ConsensusMessage) {
	select {
	case c.loopBackCh <- msg:
	default:
		go func() { c.loopBackCh <- msg }()
	}
}

func (c *Core) broadcastAndSelf(msg ConsensusMessage) {
	c.transmitor.Send(c.name, NONE, msg)
	c.loopback(msg)
}

func (c *Core) storeBlock(block *Block) {
	c.buffers[slotKey{block.Epoch, block.Height}] = true
	data, err := block.Encode()
	if err != nil {
		logger.Error.Println(err)
		return
	}
	c.store.Write(rankKey(block.Epoch, block.Height, c.committee.Size()), data)
}

func (c *Core) getBlock(epoch, height int) *Block {
	data, err := c.store.Read(rankKey(epoch, height, c.committee.Size()))
	if err != nil || len(data) == 0 {
		return nil
	}
	block := &Block{}
	if err := block.Decode(data); err != nil {
		return nil
	}
	if block.Epoch != epoch || block.Height != height {
		return nil
	}
	return block
}

func (c *Core) getABAValues(key roundKey) [2]map[NodeID]bool {
	arr, ok := c.abaValues[key]
	if !ok {
		arr = [2]map[NodeID]bool{make(map[NodeID]bool), make(map[NodeID]bool)}
		c.abaValues[key] = arr
	}
	return arr
}

func (c *Core) getABAMuxValues(key roundKey) [2]map[NodeID]bool {
	arr, ok := c.abaMuxValues[key]
	if !ok {
		arr = [2]map[NodeID]bool{make(map[NodeID]bool), make(map[NodeID]bool)}
		c.abaMuxValues[key] = arr
	}
	return arr
}

/**************************** RBC ****************************/

func (c *Core) generateRbcProposal() error {
	if c.height < c.parameters.Faults {
		return nil
	}
	batch := c.txpool.GetBatch()
	block, err := NewBlock(c.name, c.epoch, c.height, batch, c.sigService)
	if err != nil {
		return err
	}
	if batch.Txs != nil {
		logger.Info.Printf("create Block epoch %d height %d batch_id %d \n", c.epoch, c.height, batch.ID)
	}
	c.broadcastAndSelf(NewRBCValMsg(block))
	if c.parameters.MinBlockDelay > 0 {
		time.Sleep(time.Millisecond * time.Duration(c.parameters.MinBlockDelay))
	}
	return nil
}

func (c *Core) handleRbcVal(block *Block) error {
	if !block.Verify(c.committee) {
		return ErrSignature(RBCValType, block.Epoch, block.Height, int(block.Author))
	}
	c.storeBlock(block)
	echo, err := NewEchoMsg(c.name, block.Epoch, block.Height, block.Hash(), c.sigService)
	if err != nil {
		return err
	}
	c.broadcastAndSelf(echo)
	return nil
}

func (c *Core) handleRbcEcho(echo *EchoMsg) error {
	if !echo.Verify(c.committee) {
		return ErrSignature(EchoType, echo.Epoch, echo.Height, int(echo.Author))
	}
	proof := c.aggregator.AddEchoVote(echo)
	if proof == nil {
		return nil
	}
	// 2f+1 echoes -> ready + optimistic prepare.
	c.rbcProofs[proofKey{echo.Epoch, echo.Height, RBC_ECHO}] = proof
	c.rbcReady[slotKey{echo.Epoch, echo.Height}] = true
	ready, err := NewReadyMsg(c.name, echo.Epoch, echo.Height, echo.BlockHash, c.sigService)
	if err != nil {
		return err
	}
	c.broadcastAndSelf(ready)
	// g1, 往AABA输入1
	return c.invokePrepare(echo.Epoch, echo.Height, OPT)
}

func (c *Core) handleRbcReady(ready *ReadyMsg) error {
	if !ready.Verify(c.committee) {
		return ErrSignature(ReadyType, ready.Epoch, ready.Height, int(ready.Author))
	}
	proof := c.aggregator.AddReadyVote(ready)
	if proof == nil {
		return nil
	}
	c.rbcProofs[proofKey{ready.Epoch, ready.Height, RBC_READY}] = proof
	key := slotKey{ready.Epoch, ready.Height}

	if !c.rbcReady[key] && len(proof.Votes) == c.committee.LowThreshold() {
		// f+1 readies -> amplify + optimistic prepare.
		c.rbcReady[key] = true
		myReady, err := NewReadyMsg(c.name, ready.Epoch, ready.Height, ready.BlockHash, c.sigService)
		if err != nil {
			return err
		}
		c.broadcastAndSelf(myReady)
		// g1, 往AABA输入1
		return c.invokePrepare(ready.Epoch, ready.Height, OPT)
	}
	if len(proof.Votes) == c.committee.HightThreshold() {
		//2f + 1 ready, commit
		return c.processRbcOutput(ready.Epoch, ready.Height)
	}
	return nil
}

func (c *Core) processRbcOutput(epoch, height int) error {
	outs, ok := c.rbcEpochOutputs[epoch]
	if !ok {
		outs = make(map[int]bool)
		c.rbcEpochOutputs[epoch] = outs
	}
	if outs[height] {
		return nil
	}
	block := c.synchronizer.BlockRequest(epoch, height)
	if block == nil {
		return nil // sync pending; retried on SyncReply
	}
	outs[height] = true
	c.commitor.BufferBlock(block)

	//2f + 1 g2, 推进至下一轮
	if len(outs) == c.committee.HightThreshold() {
		if err := c.rbcAdvance(epoch + 1); err != nil {
			return err
		}
		//每推进一个 epoch, 看看epoch 里剩余节点的RBC
		return c.fallback(epoch)
	}
	return nil
}

func (c *Core) rbcAdvance(epoch int) error {
	if epoch > c.epoch {
		c.epoch = epoch
		return c.generateRbcProposal()
	}
	return nil
}

func (c *Core) fallback(curEpoch int) error {
	if curEpoch < c.fallbackLag {
		return nil
	}
	//lag=1, epoch 3 凑齐 2f+1 个输出，推进到epoch 4
	//检查 epoch 2。
	fallEpoch := curEpoch - c.fallbackLag
	for h := 0; h < c.committee.Size(); h++ {
		if !c.prepareFlags[slotKey{fallEpoch, h}] {
			//已有2f+1个节点g2, 此时尚未AABA的节点, 说明连g1都没有
			if err := c.invokePrepare(fallEpoch, h, PES); err != nil {
				return err
			}
		}
	}
	return nil
}

/**************************** Prepare ****************************/

func (c *Core) invokePrepare(epoch, height, val int) error {
	key := slotKey{epoch, height}
	if c.prepareFlags[key] {
		return nil
	}
	c.prepareFlags[key] = true
	prep, err := NewPrepareMsg(c.name, epoch, height, PRE_ONE, val, c.sigService)
	if err != nil {
		return err
	}
	c.broadcastAndSelf(prep)
	return nil
}

func (c *Core) handlePrepare(prep *PrepareMsg) error {
	if !prep.Verify(c.committee) {
		return ErrSignature(PrepareType, prep.Epoch, prep.Height, int(prep.Author))
	}
	//ok: 是否凑够 2f+1 票；flag: 是否全票一致；val: 倾向值，带进下一阶段。
	val, flag, ok := c.aggregator.AddPrepareVote(prep)
	if !ok {
		return nil
	}
	// 1 的 快速路径也可以删掉
	if flag {
		if val == OPT { //2f + 1 全 1
			return c.processRbcOutput(prep.Epoch, prep.Height) // optimistic commit
		}
		// else { // 全0直接skip, 改动点
		// 	c.commitor.FilterBlock(c.rank(prep.Epoch, prep.Height))
		// 	return nil
		// }
	}
	// mixed prepares -> start ABA
	// val 规则：有 OPT 则输入 1，全 PES 则输入 0
	return c.sendABAVal(prep.Epoch, prep.Height, 0, val)
}

/**************************** ABA ****************************/

func (c *Core) sendABAVal(epoch, height, round, val int) error {
	key := roundKey{epoch, height, round}
	sent := c.abaValSent[key]
	if sent[val] {
		return nil
	}
	sent[val] = true
	c.abaValSent[key] = sent
	msg, err := NewABAValMsg(c.name, epoch, height, round, val, VAL_PHASE, c.sigService)
	if err != nil {
		return err
	}
	c.broadcastAndSelf(msg)
	return nil
}

func (c *Core) sendABAMux(epoch, height, round, val int) error {
	key := roundKey{epoch, height, round}
	if c.abaMuxSent[key] {
		return nil
	}
	c.abaMuxSent[key] = true
	msg, err := NewABAValMsg(c.name, epoch, height, round, val, MUX_PHASE, c.sigService)
	if err != nil {
		return err
	}
	c.broadcastAndSelf(msg)
	return nil
}

func (c *Core) sendCoinShare(epoch, height, round int) error {
	key := roundKey{epoch, height, round}
	if c.abaCoinSent[key] {
		return nil
	}
	c.abaCoinSent[key] = true
	msg, err := NewABACoinShareMsg(c.name, epoch, height, round, c.sigService)
	if err != nil {
		return err
	}
	c.broadcastAndSelf(msg)
	return nil
}

func (c *Core) handleABAVal(msg *ABAValMsg) error {
	if !msg.Verify(c.committee) {
		return ErrSignature(ABAValType, msg.Epoch, msg.Height, int(msg.Author))
	}
	if msg.Phase == VAL_PHASE {
		return c.handleABAValPhase(msg)
	}
	return c.handleABAMuxPhase(msg)
}

func (c *Core) handleABAValPhase(msg *ABAValMsg) error {
	key := roundKey{msg.Epoch, msg.Height, msg.Round}
	vals := c.getABAValues(key)
	vals[msg.Val][msg.Author] = true
	nums := len(vals[msg.Val])

	if nums >= c.committee.LowThreshold() {
		if err := c.sendABAVal(msg.Epoch, msg.Height, msg.Round, msg.Val); err != nil {
			return err
		}
	}
	if nums == c.committee.HightThreshold() {
		f := c.abaValuesFlag[key]
		if !f[0] && !f[1] {
			f[msg.Val] = true
			c.abaValuesFlag[key] = f
			return c.sendABAMux(msg.Epoch, msg.Height, msg.Round, msg.Val)
		}
		f[msg.Val] = true
		c.abaValuesFlag[key] = f
	}
	return nil
}

func (c *Core) handleABAMuxPhase(msg *ABAValMsg) error {
	key := roundKey{msg.Epoch, msg.Height, msg.Round}
	mux := c.getABAMuxValues(key)
	mux[msg.Val][msg.Author] = true

	mf := c.abaMuxFlags[key]
	if mf[0] || mf[1] {
		return nil // already decided the mux for this round
	}
	if len(mux[0])+len(mux[1]) < c.committee.HightThreshold() {
		return nil
	}
	f := c.abaValuesFlag[key]
	if f[0] && f[1] {
		mf[OPT] = len(mux[OPT]) > 0
		mf[PES] = len(mux[PES]) > 0
	} else if f[OPT] {
		mf[OPT] = len(mux[OPT]) >= c.committee.HightThreshold()
	} else {
		mf[PES] = len(mux[PES]) >= c.committee.HightThreshold()
	}
	c.abaMuxFlags[key] = mf
	if mf[0] || mf[1] {
		return c.sendCoinShare(msg.Epoch, msg.Height, msg.Round)
	}
	return nil
}

func (c *Core) handleABAShare(msg *ABACoinShareMsg) error {
	if !msg.Verify() {
		return ErrThreshold(ABACoinShareType, msg.Epoch, msg.Height, int(msg.Author))
	}
	coin, ok, err := c.aggregator.AddCoinShare(msg, c.sigService.ShareKey)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	mf := c.abaMuxFlags[roundKey{msg.Epoch, msg.Height, msg.Round}]
	var val int
	if mf[coin] && !mf[1-coin] {
		return c.processABAOutput(msg.Epoch, msg.Height, msg.Round, coin)
	} else if !mf[coin] && mf[1-coin] {
		val = 1 - coin
	} else {
		val = coin
	}
	return c.abaAdvanceRound(msg.Epoch, msg.Height, msg.Round+1, val)
}

func (c *Core) abaAdvanceRound(epoch, height, round, val int) error {
	if c.abaEnds[slotKey{epoch, height}] {
		return nil
	}
	return c.sendABAVal(epoch, height, round, val)
}

func (c *Core) handleABAOutput(msg *ABAOutputMsg) error {
	if !msg.Verify(c.committee) {
		return ErrSignature(ABAOutputType, msg.Epoch, msg.Height, int(msg.Author))
	}
	key := roundKey{msg.Epoch, msg.Height, msg.Round}
	set, ok := c.abaOutputs[key]
	if !ok {
		set = make(map[NodeID]bool)
		c.abaOutputs[key] = set
	}
	set[msg.Author] = true
	if len(set) >= c.committee.LowThreshold() {
		return c.processABAOutput(msg.Epoch, msg.Height, msg.Round, msg.Val)
	}
	return nil
}

func (c *Core) processABAOutput(epoch, height, round, val int) error {
	sk := slotKey{epoch, height}
	if c.abaEnds[sk] {
		return nil
	}
	c.abaEnds[sk] = true

	key := roundKey{epoch, height, round}
	if !c.abaOutputSent[key] {
		c.abaOutputSent[key] = true
		out, err := NewABAOutputMsg(c.name, epoch, height, round, val, c.sigService)
		if err != nil {
			return err
		}
		c.transmitor.Send(c.name, NONE, out) // help others terminate
	}

	if val == OPT {
		return c.processRbcOutput(epoch, height)
	}
	c.commitor.FilterBlock(c.rank(epoch, height))
	return nil
}

/**************************** Sync ****************************/

func (c *Core) handleSyncRequest(msg *SyncRequestMsg) error {
	if !msg.Verify(c.committee) {
		return ErrSignature(SyncRequestType, msg.Epoch, msg.Height, int(msg.Author))
	}
	if block := c.getBlock(msg.Epoch, msg.Height); block != nil {
		c.transmitor.Send(c.name, msg.Author, NewSyncReplyMsg(block))
	}
	return nil
}

func (c *Core) handleSyncReply(msg *SyncReplyMsg) error {
	block := msg.B
	if !block.Verify(c.committee) {
		return ErrSignature(SyncReplyType, block.Epoch, block.Height, int(block.Author))
	}
	c.storeBlock(block)
	return c.processRbcOutput(block.Epoch, block.Height)
}

/**************************** cleanup ****************************/

func (c *Core) cleanup(epoch, height int) error {
	size := c.committee.Size()
	threshold := epoch*size + height
	c.aggregator.Cleanup(epoch, height)

	le := func(e, h int) bool { return e*size+h <= threshold }

	for k := range c.buffers {
		if le(k.epoch, k.height) {
			delete(c.buffers, k)
		}
	}
	for k := range c.rbcProofs {
		if le(k.epoch, k.height) {
			delete(c.rbcProofs, k)
		}
	}
	for k := range c.rbcReady {
		if le(k.epoch, k.height) {
			delete(c.rbcReady, k)
		}
	}
	for e := range c.rbcEpochOutputs {
		if e < epoch {
			delete(c.rbcEpochOutputs, e)
		}
	}
	for k := range c.abaValues {
		if le(k.epoch, k.height) {
			delete(c.abaValues, k)
		}
	}
	for k := range c.abaValuesFlag {
		if le(k.epoch, k.height) {
			delete(c.abaValuesFlag, k)
		}
	}
	for k := range c.abaValSent {
		if le(k.epoch, k.height) {
			delete(c.abaValSent, k)
		}
	}
	for k := range c.abaMuxValues {
		if le(k.epoch, k.height) {
			delete(c.abaMuxValues, k)
		}
	}
	for k := range c.abaMuxFlags {
		if le(k.epoch, k.height) {
			delete(c.abaMuxFlags, k)
		}
	}
	for k := range c.abaMuxSent {
		if le(k.epoch, k.height) {
			delete(c.abaMuxSent, k)
		}
	}
	for k := range c.abaCoinSent {
		if le(k.epoch, k.height) {
			delete(c.abaCoinSent, k)
		}
	}
	for k := range c.abaOutputs {
		if le(k.epoch, k.height) {
			delete(c.abaOutputs, k)
		}
	}
	for k := range c.abaOutputSent {
		if le(k.epoch, k.height) {
			delete(c.abaOutputSent, k)
		}
	}
	// prepareFlags and abaEnds are intentionally retained (as in the Rust
	// version) to avoid re-triggering decided slots.
	return nil
}

/**************************** event loop ****************************/

func (c *Core) dispatch(msg ConsensusMessage) error {
	switch msg.MsgType() {
	case RBCValType:
		return c.handleRbcVal(msg.(*RBCValMsg).B)
	case EchoType:
		return c.handleRbcEcho(msg.(*EchoMsg))
	case ReadyType:
		return c.handleRbcReady(msg.(*ReadyMsg))
	case PrepareType:
		return c.handlePrepare(msg.(*PrepareMsg))
	case ABAValType:
		return c.handleABAVal(msg.(*ABAValMsg))
	case ABACoinShareType:
		return c.handleABAShare(msg.(*ABACoinShareMsg))
	case ABAOutputType:
		return c.handleABAOutput(msg.(*ABAOutputMsg))
	case SyncRequestType:
		return c.handleSyncRequest(msg.(*SyncRequestMsg))
	case SyncReplyType:
		return c.handleSyncReply(msg.(*SyncReplyMsg))
	}
	return nil
}

func (c *Core) Run() {
	// Designated crash-fault nodes stay silent but drain the network so peers
	// do not block.
	if c.height < c.parameters.Faults {
		for range c.transmitor.RecvChannel() {
		}
		return
	}

	if err := c.generateRbcProposal(); err != nil {
		logger.Error.Println(err)
		panic(err)
	}

	cleanupCh := c.commitor.CleanupChannel()
	for {
		var err error
		select {
		case msg := <-c.transmitor.RecvChannel():
			err = c.dispatch(msg)
		case msg := <-c.loopBackCh:
			err = c.dispatch(msg)
		case ids := <-cleanupCh:
			err = c.cleanup(ids[0], ids[1])
		}
		if err != nil {
			logger.Warn.Println(err)
		}
	}
}
