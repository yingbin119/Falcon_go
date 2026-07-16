package core

import (
	"net"
	"strings"
	"sync"
	"time"

	"falcon/crypto"
	"falcon/logger"
	"falcon/network"
	"falcon/pool"
	"falcon/store"
)

// Consensus wires the network stack, waits for every peer to come online, then
// launches the txpool and the core state machine.
func Consensus(
	id NodeID,
	committee Committee,
	parameters Parameters,
	txpool *pool.Pool,
	store *store.Store,
	sigService *crypto.SigService,
	commitChannel chan<- *Block,
) error {
	cc := network.NewCodec(DefaultMsgTypes)

	logger.Info.Printf("Consensus Node ID: %d\n", id)
	logger.Info.Printf("Consensus DDos: %v, Faults: %d \n", parameters.DDos, parameters.Faults)

	addr := committee.Address(id)
	port := addr
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		port = addr[i:]
	}
	localAddr := port // e.g. ":9000" — bind on all interfaces

	sender := network.NewSender(cc)
	receiver := network.NewReceiver(localAddr, cc)
	go sender.Run()
	go receiver.Run()

	transmitor := NewTransmitor(sender, receiver, parameters, committee)

	// Barrier: dial every peer until the whole committee is online.
	logger.Info.Println("Waiting for all nodes to be online...")
	var wg sync.WaitGroup
	for nid, authority := range committee.Authorities {
		if nid == id {
			continue
		}
		wg.Add(1)
		go func(a string) {
			defer wg.Done()
			for {
				conn, err := net.Dial("tcp", a)
				if err == nil {
					conn.Close()
					return
				}
				time.Sleep(time.Millisecond * 10)
			}
		}(authority.Addr)
	}
	wg.Wait()
	time.Sleep(time.Millisecond * time.Duration(parameters.SyncTimeout))

	txpool.Run()

	corer := NewCore(id, committee, parameters, txpool, transmitor, store, sigService, commitChannel)
	go corer.Run()

	return nil
}
