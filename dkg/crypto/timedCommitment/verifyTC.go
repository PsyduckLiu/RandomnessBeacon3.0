package timedCommitment

import (
	"dkg/config"
	"dkg/crypto/binaryquadraticform"
	"dkg/util"
	"fmt"
	"math/big"
)

func VerifyTC(maskedMsg *big.Int, h *binaryquadraticform.BQuadraticForm, M_k *binaryquadraticform.BQuadraticForm, a1 *binaryquadraticform.BQuadraticForm, a2 *binaryquadraticform.BQuadraticForm, z *big.Int) bool {
	// read config file
	a, b, c := config.GetGroupParameter()
	m_k_a, m_k_b, m_k_c, r_k_a, r_k_b, r_k_c := config.GetPublicGroupParameter()
	bigTwo := big.NewInt(2)

	// get public class group
	g, err := binaryquadraticform.NewBQuadraticForm(big.NewInt(int64(a)), big.NewInt(int64(b)), big.NewInt(int64(c)))
	fmt.Printf("===>[VerifyTC]The group element g is (a=%v,b=%v,c=%v,d=%v)\n", g.GetA(), g.GetB(), g.GetC(), g.GetDiscriminant())
	if err != nil {
		panic(fmt.Errorf("===>[ERROR from VerifyTC]Generate new BQuadratic Form failed: %s", err))
	}
	d := g.GetDiscriminant()

	m_k, err := binaryquadraticform.NewBQuadraticForm(big.NewInt(int64(m_k_a)), big.NewInt(int64(m_k_b)), big.NewInt(int64(m_k_c)))
	fmt.Printf("===>[VerifyTC]The group element m_k is (a=%v,b=%v,c=%v,d=%v)\n", m_k.GetA(), m_k.GetB(), m_k.GetC(), m_k.GetDiscriminant())
	if err != nil {
		panic(fmt.Errorf("===>[ERROR from VerifyTC]Generate new BQuadratic Form failed: %s", err))
	}
	r_k, err := binaryquadraticform.NewBQuadraticForm(big.NewInt(int64(r_k_a)), big.NewInt(int64(r_k_b)), big.NewInt(int64(r_k_c)))
	fmt.Printf("===>[VerifyTC]The group element r_k is (a=%v,b=%v,c=%v,d=%v)\n", r_k.GetA(), r_k.GetB(), r_k.GetC(), r_k.GetDiscriminant())
	if err != nil {
		panic(fmt.Errorf("===>[ERROR from VerifyTC]Generate new BQuadratic Form failed: %s", err))
	}

	check := VerifyGroup(g, m_k, r_k)
	if !check {
		panic(fmt.Errorf("===>[ERROR from VerifyTC]Verify Group proof failed: %s", err))
	}

	// calculate the upper bound of alpha
	nSqrt := new(big.Int)
	dAbs := new(big.Int)
	dAbs.Abs(d)
	upperBound := new(big.Int)
	nSqrt.Sqrt(dAbs)
	upperBound.Div(nSqrt, bigTwo)
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
		fmt.Println("===>[VerifyTC]test1 error")
		return false
	}
	if !comp2.Equal(a2) {
		fmt.Println("===>[VerifyTC]test2 error")
		return false
	}

	return true
}
