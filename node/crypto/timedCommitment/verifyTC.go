package timedCommitment

import (
	"fmt"
	"math/big"
	"node/crypto/binaryquadraticform"
	"node/util"
)

func VerifyTC(t int, maskedMsg *big.Int, g, m_k, r_k, p, h, M_k, a1, a2 *binaryquadraticform.BQuadraticForm, z *big.Int) bool {
	d := g.GetDiscriminant()

	check := VerifyGroup(t, p, g, m_k, r_k)
	if !check {
		panic(fmt.Errorf("===>[ERROR from VerifyTC]Verify Group proof failed"))
	}

	// calculate the upper bound of alpha
	// nSqrt := new(big.Int)
	dAbs := new(big.Int)
	dAbs.Abs(d)
	upperBound := new(big.Int)
	upperBound.Sqrt(dAbs)
	// nSqrt.Sqrt(dAbs)

	// upperBound.Div(nSqrt, bigTwo)
	fmt.Printf("===>[VerifyTC]Upper bound of alpha is %v.\n", upperBound)

	gHash := new(big.Int).SetBytes(util.Digest((g.GetA())))
	hHash := new(big.Int).SetBytes(util.Digest((h.GetA())))
	mkHash := new(big.Int).SetBytes(util.Digest(m_k.GetA()))
	a1Hash := new(big.Int).SetBytes(util.Digest(a1.GetA()))
	a2Hash := new(big.Int).SetBytes(util.Digest(a2.GetA()))

	e := big.NewInt(0)
	e.Xor(e, gHash)
	e.Xor(e, hHash)
	e.Xor(e, mkHash)
	e.Xor(e, a1Hash)
	e.Xor(e, a2Hash)
	e.Mod(e, upperBound)

	result1, err := g.Exp(z)
	if err != nil {
		panic(fmt.Errorf("===>[ERROR from VerifyTC]Generate new BQuadratic Form failed: %s", err))
	}
	result2, err := h.Exp(e)
	if err != nil {
		panic(fmt.Errorf("===>[ERROR from VerifyTC]Generate new BQuadratic Form failed: %s", err))
	}
	comp1, _ := result1.Composition(result2)

	result3, err := m_k.Exp(z)
	if err != nil {
		panic(fmt.Errorf("===>[ERROR from VerifyTC]Generate new BQuadratic Form failed: %s", err))
	}
	result4, err := M_k.Exp(e)
	if err != nil {
		panic(fmt.Errorf("===>[ERROR from VerifyTC]Generate new BQuadratic Form failed: %s", err))
	}
	comp2, _ := result3.Composition(result4)

	if !comp1.Equal(a1) {
		if (comp1.GetA().Cmp(a1.GetA()) == 0) && (comp1.GetB().Cmp(a1.GetB()) == 0) && (comp1.GetC().Cmp(a1.GetC()) == 0) {
			fmt.Println("===>[VerifyTC]test1 pass")
		} else {
			fmt.Println("===>[VerifyTC]test1 error")
			return false
		}
	}
	if !comp2.Equal(a2) {
		if (comp2.GetA() == a2.GetA()) && (comp2.GetB() == a2.GetB()) && (comp2.GetC() == a2.GetC()) {
			fmt.Println("===>[VerifyTC]test2 pass")
		} else {
			fmt.Println("===>[VerifyTC]test2 error")
			return false
		}
	}

	return true
}
