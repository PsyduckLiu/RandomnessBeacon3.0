package timedCommitment

import (
	"fmt"
	"math/big"
	"node/crypto/binaryquadraticform"
	"node/util"
)

func ForcedOpen(t int, maskedMsg *big.Int, h *binaryquadraticform.BQuadraticForm) {
	bigOne := big.NewInt(1)
	bigTwo := big.NewInt(2)

	tPower := new(big.Int)
	tSubPower := new(big.Int)
	rkexp := new(big.Int)
	tPower.Exp(bigTwo, big.NewInt(int64(t)), nil)
	tSubPower.Sub(tPower, bigOne)
	rkexp.Exp(bigTwo, tSubPower, nil)

	rkComptued, err := h.Exp(rkexp)
	if err != nil {
		panic(fmt.Errorf("===>[ERROR from ForcedOpen]Generate new BQuadratic Form failed: %s", err))
	}
	hashedRk := new(big.Int).SetBytes(util.Digest((rkComptued.GetA())))
	msgComputed := new(big.Int)
	msgComputed.Xor(maskedMsg, hashedRk)

	fmt.Println("===>[ForcedOpen]opened msg is", msgComputed)
}
