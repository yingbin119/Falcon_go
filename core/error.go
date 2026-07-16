package core

import "fmt"

var (
	ErrSignature = func(msgTyp, epoch, height, node int) error {
		return fmt.Errorf("[type-%d-epoch-%d-height-%d-node-%d] message signature verify error", msgTyp, epoch, height, node)
	}

	ErrThreshold = func(msgTyp, epoch, height, node int) error {
		return fmt.Errorf("[type-%d-epoch-%d-height-%d-node-%d] threshold signature share verify error", msgTyp, epoch, height, node)
	}

	ErrReference = func(msgTyp, epoch, height, node int) error {
		return fmt.Errorf("[type-%d-epoch-%d-height-%d-node-%d] block not yet available", msgTyp, epoch, height, node)
	}
)
