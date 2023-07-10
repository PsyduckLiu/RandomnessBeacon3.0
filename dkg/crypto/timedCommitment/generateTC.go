package timedCommitment

import (
	"crypto/rand"
	"dkg/config"
	"dkg/crypto/binaryquadraticform"
	"dkg/util"
	"fmt"
	"math/big"
)

func GenerateTC() (*big.Int, *binaryquadraticform.BQuadraticForm, *binaryquadraticform.BQuadraticForm, *binaryquadraticform.BQuadraticForm, *binaryquadraticform.BQuadraticForm, *big.Int) {
	// read config file
	a, b, c := config.GetGroupParameter()
	m_k_a, m_k_b, m_k_c, r_k_a, r_k_b, r_k_c := config.GetPublicGroupParameter()
	bigTwo := big.NewInt(2)

	// get public class group
	g, err := binaryquadraticform.NewBQuadraticForm(big.NewInt(int64(a)), big.NewInt(int64(b)), big.NewInt(int64(c)))
	fmt.Printf("===>[GenerateTC]The group element g is (a=%v,b=%v,c=%v,d=%v)\n", g.GetA(), g.GetB(), g.GetC(), g.GetDiscriminant())
	if err != nil {
		panic(fmt.Errorf("===>[ERROR from GenerateTC]Generate new BQuadratic Form failed: %s", err))
	}
	d := g.GetDiscriminant()

	m_k, err := binaryquadraticform.NewBQuadraticForm(big.NewInt(int64(m_k_a)), big.NewInt(int64(m_k_b)), big.NewInt(int64(m_k_c)))
	fmt.Printf("===>[GenerateTC]The group element m_k is (a=%v,b=%v,c=%v,d=%v)\n", m_k.GetA(), m_k.GetB(), m_k.GetC(), m_k.GetDiscriminant())
	if err != nil {
		panic(fmt.Errorf("===>[ERROR from GenerateTC]Generate new BQuadratic Form failed: %s", err))
	}
	r_k, err := binaryquadraticform.NewBQuadraticForm(big.NewInt(int64(r_k_a)), big.NewInt(int64(r_k_b)), big.NewInt(int64(r_k_c)))
	fmt.Printf("===>[GenerateTC]The group element r_k is (a=%v,b=%v,c=%v,d=%v)\n", r_k.GetA(), r_k.GetB(), r_k.GetC(), r_k.GetDiscriminant())
	if err != nil {
		panic(fmt.Errorf("===>[ERROR from GenerateTC]Generate new BQuadratic Form failed: %s", err))
	}

	check := VerifyGroup(g, m_k, r_k)
	if !check {
		panic(fmt.Errorf("===>[ERROR from GenerateTC]Verify Group proof failed: %s", err))
	}

	// calculate the upper bound of alpha
	nSqrt := new(big.Int)
	dAbs := new(big.Int)
	dAbs.Abs(d)
	upperBound := new(big.Int)
	nSqrt.Sqrt(dAbs)
	upperBound.Div(nSqrt, bigTwo)
	fmt.Printf("===>[GenerateTC]Upper bound of alpha is %v.\n", upperBound)

	// get random alpha
	alpha, err := rand.Int(rand.Reader, upperBound)
	if err != nil {
		panic(fmt.Errorf("===>[ERROR from GenerateTC]Generate alpha failed:%s", err))
	}
	fmt.Println("===>[GenerateTC]alpha is", alpha)

	// generate random message
	upper := new(big.Int)
	upper.Exp(bigTwo, big.NewInt(50), nil)
	msg, err := rand.Int(rand.Reader, upper)
	if err != nil {
		panic(fmt.Errorf("===>[ERROR from GenerateTC]Generate random message failed:%s", err))
	}
	fmt.Println("===>[GenerateTC]msg is", msg)

	// xor msg and R_k, gets c
	h, err := g.Exp(alpha)
	if err != nil {
		panic(fmt.Errorf("===>[ERROR from GenerateTC]Generate new BQuadratic Form failed: %s", err))
	}
	M_k, err := m_k.Exp(alpha)
	if err != nil {
		panic(fmt.Errorf("===>[ERROR from GenerateTC]Generate new BQuadratic Form failed: %s", err))
	}
	R_k, err := r_k.Exp(alpha)
	if err != nil {
		panic(fmt.Errorf("===>[ERROR from GenerateTC]Generate new BQuadratic Form failed: %s", err))
	}

	// TODO
	// F function to de modeified
	hashedRk := new(big.Int).SetBytes(util.Digest((R_k.GetA())))
	maskedMsg := new(big.Int)
	maskedMsg.Xor(msg, hashedRk)

	// evalute a series of parameters(a1, a2, a3, z) for verification
	wupperBound := new(big.Int)
	wupperBound.Mul(upperBound, dAbs)
	w, _ := rand.Int(rand.Reader, wupperBound)
	a1, err := g.Exp(w)
	if err != nil {
		panic(fmt.Errorf("===>[ERROR from GenerateTC]Generate new BQuadratic Form failed: %s", err))
	}
	a2, err := m_k.Exp(w)
	if err != nil {
		panic(fmt.Errorf("===>[ERROR from GenerateTC]Generate new BQuadratic Form failed: %s", err))
	}

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

	z := new(big.Int).Set(w)
	alphaE := new(big.Int).Set(e)
	alphaE.Mul(alphaE, alpha)
	z.Sub(z, alphaE)

	return maskedMsg, h, M_k, a1, a2, z
}
