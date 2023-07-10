package config

import (
	"crypto/sha256"
	"dkg/crypto/binaryquadraticform"
	"fmt"
	"math/big"
)

// Hash any type message v, using SHA256
func Digest(v interface{}) []byte {
	h := sha256.New()
	h.Write([]byte(fmt.Sprintf("%v", v)))
	digest := h.Sum(nil)

	return digest
}

// init group
func InitGroup() {
	a, b, c := GetGroupParameter()
	t := GetTimeParameter()

	bigOne := big.NewInt(1)
	bigTwo := big.NewInt(2)

	g, err := binaryquadraticform.NewBQuadraticForm(big.NewInt(int64(a)), big.NewInt(int64(b)), big.NewInt(int64(c)))
	fmt.Printf("===>[InitConfig]The group element g is (a=%v,b=%v,c=%v,d=%v)\n", g.GetA(), g.GetB(), g.GetC(), g.GetDiscriminant())
	if err != nil {
		panic(fmt.Errorf("===>[ERROR from InitConfig]Generate new BQuadratic Form failed: %s", err))
	}

	tPower := new(big.Int)
	tSubPower := new(big.Int)
	mkexp := new(big.Int)
	rkexp := new(big.Int)
	tPower.Exp(bigTwo, big.NewInt(int64(t)), nil)
	tSubPower.Sub(tPower, bigOne)
	mkexp.Exp(bigTwo, tPower, nil)
	rkexp.Exp(bigTwo, tSubPower, nil)
	fmt.Printf("===>[InitConfig] 2^t is:%v\n", tPower)

	m_k, err := g.Exp(mkexp)
	if err != nil {
		panic(fmt.Errorf("===>[ERROR from InitConfig]Generate new BQuadratic Form failed: %s", err))
	}
	r_k, err := g.Exp(rkexp)
	if err != nil {
		panic(fmt.Errorf("===>[ERROR from InitConfig]Generate new BQuadratic Form failed: %s", err))
	}
	fmt.Printf("===>[InitConfig] Mk is (a=%v,b=%v,c=%v,d=%v)\n", m_k.GetA(), m_k.GetB(), m_k.GetC(), m_k.GetDiscriminant())
	fmt.Printf("===>[InitConfig] Rk is (a=%v,b=%v,c=%v,d=%v)\n", r_k.GetA(), r_k.GetB(), r_k.GetC(), r_k.GetDiscriminant())

	// generate proof
	gHash := new(big.Int).SetBytes(Digest((g.GetA())))
	mkHash := new(big.Int).SetBytes(Digest(m_k.GetA()))
	expHash := new(big.Int).SetBytes(Digest(mkexp))

	l := big.NewInt(0)
	l.Xor(l, gHash)
	l.Xor(l, mkHash)
	l.Xor(l, expHash)
	// l.Mod(l, mkexp)

	q := new(big.Int)
	q.Div(mkexp, l)

	proof, err := g.Exp(q)
	if err != nil {
		panic(fmt.Errorf("===>[ERROR from InitConfig]Generate new BQuadratic Form failed: %s", err))
	}
	fmt.Println("proof right", proof.GetA(), proof.GetB())

	WriteSetup(m_k, r_k, proof)
}
