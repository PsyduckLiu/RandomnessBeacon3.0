package timedCommitment

import (
	"dkg/config"
	"dkg/crypto/binaryquadraticform"
	"dkg/util"
	"fmt"
	"math/big"
)

func VerifyGroup(g *binaryquadraticform.BQuadraticForm, m_k *binaryquadraticform.BQuadraticForm, r_k *binaryquadraticform.BQuadraticForm) bool {
	// read config file
	p_a, p_b, p_c := config.GetPublicParameterProof()
	t := config.GetTimeParameter()
	bigTwo := big.NewInt(2)

	proof, err := binaryquadraticform.NewBQuadraticForm(big.NewInt(int64(p_a)), big.NewInt(int64(p_b)), big.NewInt(int64(p_c)))
	fmt.Printf("===>[VerifyGroup]The group proof is (a=%v,b=%v,c=%v,d=%v)\n", proof.GetA(), proof.GetB(), proof.GetC(), proof.GetDiscriminant())
	if err != nil {
		panic(fmt.Errorf("===>[ERROR from VerifyGroup]Generate new BQuadratic Form failed: %s", err))
	}

	// generate proof
	tPower := new(big.Int)
	mkexp := new(big.Int)
	tPower.Exp(bigTwo, big.NewInt(int64(t)), nil)
	mkexp.Exp(bigTwo, tPower, nil)

	gHash := new(big.Int).SetBytes(util.Digest((g.GetA())))
	mkHash := new(big.Int).SetBytes(util.Digest(m_k.GetA()))
	expHash := new(big.Int).SetBytes(util.Digest(mkexp))

	l := big.NewInt(0)
	l.Xor(l, gHash)
	l.Xor(l, mkHash)
	l.Xor(l, expHash)
	// l.Mod(l, mkexp)

	q := new(big.Int)
	r := new(big.Int)
	q.Div(mkexp, l)
	r.Mod(mkexp, l)

	result1, err := proof.Exp(l)
	if err != nil {
		panic(fmt.Errorf("===>[ERROR from VerifyGroup]Generate new BQuadratic Form failed: %s", err))
	}
	result2, err := g.Exp(r)
	if err != nil {
		panic(fmt.Errorf("===>[ERROR from VerifyGroup]Generate new BQuadratic Form failed: %s", err))
	}
	computedmk, err := result1.Composition(result2)
	if err != nil {
		panic(fmt.Errorf("===>[ERROR from VerifyGroup]Generate new BQuadratic Form failed: %s", err))
	}
	squaredrk, err := r_k.Exp(bigTwo)
	if err != nil {
		panic(fmt.Errorf("===>[ERROR from VerifyGroup]Generate new BQuadratic Form failed: %s", err))
	}

	if !m_k.Equal(computedmk) {
		fmt.Println("===>[VerifyGroup]m_k error")
		return false
	}
	if !m_k.Equal(squaredrk) {
		fmt.Println("===>[VerifyGroup]r_k error")
		return false
	}

	return true
}
