package core

import (
	"time"

	"falcon/network"
)

// Transmitor bridges the network layer and the core event loop: it pumps
// outbound messages to the Sender and inbound messages onto recvCh.
type Transmitor struct {
	sender     *network.Sender
	receiver   *network.Receiver
	recvCh     chan ConsensusMessage
	msgCh      chan *network.NetMessage
	parameters Parameters
	committee  Committee
}

func NewTransmitor(
	sender *network.Sender,
	receiver *network.Receiver,
	parameters Parameters,
	committee Committee,
) *Transmitor {
	tr := &Transmitor{
		sender:     sender,
		receiver:   receiver,
		recvCh:     make(chan ConsensusMessage, 1_000),
		msgCh:      make(chan *network.NetMessage, 1_000),
		parameters: parameters,
		committee:  committee,
	}

	go func() {
		for msg := range tr.msgCh {
			tr.sender.Send(msg)
		}
	}()

	go func() {
		for msg := range tr.receiver.RecvChannel() {
			tr.recvCh <- msg.(ConsensusMessage)
		}
	}()

	return tr
}

// Send delivers msg to peer `to`, or broadcasts (to all but `from`) when
// to == NONE.
func (tr *Transmitor) Send(from, to NodeID, msg ConsensusMessage) error {
	var addr []string
	if to == NONE {
		addr = tr.committee.BroadCast(from)
	} else {
		addr = append(addr, tr.committee.Address(to))
	}

	if tr.parameters.DDos && msg.MsgType() == RBCValType {
		time.AfterFunc(time.Millisecond*time.Duration(tr.parameters.NetworkDelay), func() {
			tr.msgCh <- &network.NetMessage{Msg: msg, Address: addr}
		})
	} else {
		tr.msgCh <- &network.NetMessage{Msg: msg, Address: addr}
	}
	return nil
}

func (tr *Transmitor) Recv() ConsensusMessage {
	return <-tr.recvCh
}

func (tr *Transmitor) RecvChannel() chan ConsensusMessage {
	return tr.recvCh
}
