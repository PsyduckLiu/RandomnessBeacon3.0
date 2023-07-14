package timedCommitment

import (
	"RB/crypto/binaryquadraticform"
	"RB/util"
	"crypto/rand"
	"fmt"
	"math/big"
	"time"
)

func GenerateTC(g, m_k, r_k, p *binaryquadraticform.BQuadraticForm, t int) (
	*big.Int, *binaryquadraticform.BQuadraticForm, *binaryquadraticform.BQuadraticForm,
	*binaryquadraticform.BQuadraticForm, *binaryquadraticform.BQuadraticForm, *big.Int) {
	// bigOne := big.NewInt(1)
	bigTwo := big.NewInt(2)
	d := g.GetDiscriminant()

	Start := time.Now()
	check := VerifyGroup(t, p, g, m_k, r_k)
	if !check {
		panic(fmt.Errorf("===>[ERROR from GenerateTC]Verify Group proof failed"))
	}
	fmt.Println("verify group time", float64(time.Since(Start).Milliseconds()))

	// calculate the upper bound of alpha
	// nSqrt := new(big.Int)
	dAbs := new(big.Int)
	dAbs.Abs(d)
	upperBound := new(big.Int)
	upperBound.Sqrt(dAbs)
	// nSqrt.Sqrt(dAbs)
	// upperBound.Div(nSqrt, bigTwo)
	fmt.Printf("===>[GenerateTC]Upper bound of alpha is %v.\n", upperBound)
	fmt.Println("upperBound time", float64(time.Since(Start).Milliseconds()))

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
	fmt.Println("message time", float64(time.Since(Start).Milliseconds()))

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
	fmt.Println("R_k time", float64(time.Since(Start).Milliseconds()))

	// TODO
	// F function to de modeified
	hashedRk := new(big.Int).SetBytes(util.Digest((R_k.GetA())))
	maskedMsg := new(big.Int)
	maskedMsg.Xor(msg, hashedRk)

	// evalute a series of parameters(a1, a2, a3, z) for verification
	wupperBound := new(big.Int)
	wupperBound.Mul(upperBound, dAbs)
	// wupperBound.Set(dAbs)
	w, _ := rand.Int(rand.Reader, wupperBound)
	// w, _ := rand.Int(rand.Reader, upperBound)
	a1, err := g.Exp(w)
	if err != nil {
		panic(fmt.Errorf("===>[ERROR from GenerateTC]Generate new BQuadratic Form failed: %s", err))
	}
	a2, err := m_k.Exp(w)
	if err != nil {
		panic(fmt.Errorf("===>[ERROR from GenerateTC]Generate new BQuadratic Form failed: %s", err))
	}
	fmt.Println("a2 time", float64(time.Since(Start).Milliseconds()))

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

	fmt.Println("[Generate TC]", z, alpha, e, h.GetA(), h.GetB(), h.GetC(), w)
	return maskedMsg, h, M_k, a1, a2, z
}
