package timedCommitment

import (
	"RB/crypto/binaryquadraticform"
	"RB/util"
	"fmt"
	"math/big"
)

func VerifyGroup(t int, p, g, m_k, r_k *binaryquadraticform.BQuadraticForm) bool {
	bigTwo := big.NewInt(2)

	// Start := time.Now()
	// generate proof

	// fmt.Println("time-4", float64(time.Since(Start).Milliseconds()))
	gHash := new(big.Int).SetBytes(util.Digest((g.GetA())))
	// fmt.Println("time-3", float64(time.Since(Start).Milliseconds()))
	mkHash := new(big.Int).SetBytes(util.Digest(m_k.GetA()))
	// fmt.Println("time-2", float64(time.Since(Start).Milliseconds()))
	expHash := new(big.Int).SetBytes(util.Digest(t))
	// fmt.Println("time-1", float64(time.Since(Start).Milliseconds()))

	l := big.NewInt(0)
	l.Xor(l, gHash)
	l.Xor(l, mkHash)
	l.Xor(l, expHash)
	// l.Mod(l, mkexp)

	tPower := new(big.Int)
	r := new(big.Int)
	tPower.Exp(bigTwo, big.NewInt(int64(t)), nil)
	r.Exp(bigTwo, tPower, l)
	// q := new(big.Int)
	// r := new(big.Int)
	// q.Div(mkexp, l)
	// r.Mod(mkexp, l)

	// fmt.Println("time1", float64(time.Since(Start).Milliseconds()))
	result1, err := p.Exp(l)
	if err != nil {
		panic(fmt.Errorf("===>[ERROR from VerifyGroup]Generate new BQuadratic Form failed: %s", err))
	}

	result2, err := g.Exp(r)
	if err != nil {
		panic(fmt.Errorf("===>[ERROR from VerifyGroup]Generate new BQuadratic Form failed: %s", err))
	}

	// fmt.Println("time2", float64(time.Since(Start).Milliseconds()))
	computedmk, err := result1.Composition(result2)
	if err != nil {
		panic(fmt.Errorf("===>[ERROR from VerifyGroup]Generate new BQuadratic Form failed: %s", err))
	}

	squaredrk, err := r_k.Exp(bigTwo)
	if err != nil {
		panic(fmt.Errorf("===>[ERROR from VerifyGroup]Generate new BQuadratic Form failed: %s", err))
	}

	// fmt.Println("time3", float64(time.Since(Start).Milliseconds()))
	if !m_k.Equal(computedmk) {
		fmt.Println("===>[VerifyGroup]m_k error")
		return false
	}
	if !m_k.Equal(squaredrk) {
		fmt.Println("===>[VerifyGroup]r_k error")
		return false
	}
	// fmt.Println("time4", float64(time.Since(Start).Milliseconds()))

	return true
}
