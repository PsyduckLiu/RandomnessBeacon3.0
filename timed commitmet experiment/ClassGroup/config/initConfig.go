package config

import (
	"RB/crypto/binaryquadraticform"
	"crypto/sha256"
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

	bigZero := big.NewInt(0)
	bigOne := big.NewInt(1)
	bigTwo := big.NewInt(2)

	g, err := binaryquadraticform.NewBQuadraticForm(a, b, c)
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

	// Start := time.Now()
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
	// fmt.Println("init two exp time", float64(time.Since(Start).Milliseconds()))

	// generate proof
	gHash := new(big.Int).SetBytes(Digest((g.GetA())))
	mkHash := new(big.Int).SetBytes(Digest(m_k.GetA()))
	expHash := new(big.Int).SetBytes(Digest(t))

	l := big.NewInt(0)
	l.Xor(l, gHash)
	l.Xor(l, mkHash)
	l.Xor(l, expHash)
	// l.Mod(l, mkexp)

	identityA := big.NewInt(1)
	identityB := big.NewInt(1)
	identityC := big.NewInt(1)
	identityC.Mul(identityB, identityB)
	identityC.Sub(identityC, g.GetDiscriminant())
	identityC.Div(identityC, big.NewInt(4))
	identityC.Div(identityC, identityA)

	// Start = time.Now()
	x, _ := binaryquadraticform.NewBQuadraticForm(identityA, identityB, identityC)

	b2 := new(big.Int)
	r := big.NewInt(1)
	r2 := new(big.Int)
	for i := big.NewInt(0); i.Cmp(tPower) < 0; i.Add(i, bigOne) {
		r2.Mul(bigTwo, r)
		// fmt.Print(r2.Int64() / l.Int64())
		if r2.Cmp(l) == 1 {
			b2 = bigOne
		} else {
			b2 = bigZero
		}
		// b2.Div(r2, l)
		// if (b2.Cmp(bigZero) != 0) && (b2.Cmp(bigOne) != 0) {
		// 	fmt.Println(b2)
		// }

		r.Mod(r2, l)
		x, err = x.Exp(bigTwo)
		if err != nil {
			fmt.Println("1", err)
		}

		gb, err := g.Exp(b2)
		if err != nil {
			fmt.Println("2", err)
		}
		// g.Exp(b2)

		x, err = x.Composition(gb)
		if err != nil {
			fmt.Println(x.GetDiscriminant())
			fmt.Println("3", err)
		}
	}
	// fmt.Println(b2)
	// fmt.Println("proof time", float64(time.Since(Start).Milliseconds()))
	proof := x
	fmt.Println("proof right", proof.GetA(), proof.GetB(), proof.GetC())

	// q := new(big.Int)
	// q.Div(mkexp, l)

	// proof, err = g.Exp(q)
	// fmt.Printf("===>[InitConfig]The group proof is (a=%v,b=%v,c=%v,d=%v)\n", proof.GetA(), proof.GetB(), proof.GetC(), proof.GetDiscriminant())
	// if err != nil {
	// 	panic(fmt.Errorf("===>[ERROR from InitConfig]Generate new BQuadratic Form failed: %s", err))
	// }

	// fmt.Println("proof right", proof.GetA(), proof.GetB(), proof.GetC())

	WriteSetup(m_k, r_k, proof)
}
