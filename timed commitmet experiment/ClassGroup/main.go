package main

import (
	"RB/config"
	"RB/crypto/binaryquadraticform"
	"RB/crypto/timedCommitment"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"math/big"
	"time"
)

func main() {
	initElapsed := 0.0
	// generateElapsed := 0.0
	// verifyElapsed := 0.0
	// openElapsed := 0.0

	a := big.NewInt(782860151238873921)
	b := big.NewInt(123)
	c, _ := big.NewInt(0).SetString("681582962329953011041792857049", 10)
	t := 10

	// search for group
	var delta *big.Int
	dMod := big.NewInt(2)
	cMod := big.NewInt(1)

	for dMod.Cmp(big.NewInt(1)) != 0 {
		privateKey, _ := rsa.GenerateKey(rand.Reader, 6656)
		delta = privateKey.PublicKey.N
		delta.Neg(delta)

		dMod.Mod(delta, big.NewInt(4))
	}
	fmt.Println("[Delta] Value ", delta)
	fmt.Println("[Delta] Length ", delta.BitLen())

	c.Mul(b, b)
	c.Sub(c, delta)
	c.Div(c, big.NewInt(4))
	fmt.Println("[C] Value ", c)
	for cMod.Mod(c, a).Cmp(big.NewInt(0)) != 0 {
		a.Add(a, big.NewInt(1))
	}
	c.Div(c, a)

	discriminant := new(big.Int).Mul(b, b)
	ac := new(big.Int).Mul(a, c)
	discriminant = discriminant.Sub(discriminant, ac.Lsh(ac, 2))
	fmt.Println("[discriminant] Value ", discriminant)
	fmt.Println("[discriminant] Length ", discriminant.BitLen())
	fmt.Println("[A] Value ", a)
	fmt.Println("[B] Value ", b)
	fmt.Println("[C] Value ", c)

	config.WriteGroup(a.String(), b.String(), c.String())
	config.WriteTime(t)

	// experiment
	initStart := time.Now()
	config.InitGroup()
	initElapsed += float64(time.Since(initStart).Milliseconds())
	fmt.Println("===>[Init]finish")

	// recover the g, m_k, r_k, p
	groupA, groupB, groupC := config.GetGroupParameter()
	timeT := config.GetTimeParameter()
	mkA, mkB, mkC, rkA, rkB, rkC := config.GetPublicGroupParameter()
	pA, pB, pC := config.GetPublicParameterProof()

	g, err := binaryquadraticform.NewBQuadraticForm(groupA, groupB, groupC)
	fmt.Printf("[Setup] The group element g is (a=%v,b=%v,c=%v,d=%v)\n", g.GetA(), g.GetB(), g.GetC(), g.GetDiscriminant())
	if err != nil {
		panic(fmt.Errorf("[!!!Error GroupMsgReceive] Generate new BQuadratic Form g failed: %s", err))
	}
	m_k, err := binaryquadraticform.NewBQuadraticForm(mkA, mkB, mkC)
	fmt.Printf("[Setup] Mk is (a=%v,b=%v,c=%v,d=%v)\n", m_k.GetA(), m_k.GetB(), m_k.GetC(), m_k.GetDiscriminant())
	if err != nil {
		panic(fmt.Errorf("[!!!Error GroupMsgReceive] Generate new BQuadratic Form Mk failed: %s", err))
	}
	r_k, err := binaryquadraticform.NewBQuadraticForm(rkA, rkB, rkC)
	fmt.Printf("[Setup] Rk is (a=%v,b=%v,c=%v,d=%v)\n", r_k.GetA(), r_k.GetB(), r_k.GetC(), r_k.GetDiscriminant())
	if err != nil {
		panic(fmt.Errorf("[!!!Error GroupMsgReceive] Generate new BQuadratic Form Rk failed: %s", err))
	}
	p, err := binaryquadraticform.NewBQuadraticForm(pA, pB, pC)
	fmt.Printf("[Setup] Proof is (a=%v,b=%v,c=%v,d=%v)\n", p.GetA(), p.GetB(), p.GetC(), p.GetDiscriminant())
	if err != nil {
		panic(fmt.Errorf("[!!!Error GroupMsgReceive] Generate new BQuadratic Form Proof failed: %s", err))
	}

	maskedMsg, h, M_k, a1, a2, z := timedCommitment.GenerateTC(g, m_k, r_k, p, int(timeT))
	fmt.Println(timedCommitment.VerifyTC(int(timeT), maskedMsg, g, m_k, r_k, p, h, M_k, a1, a2, z))
	timedCommitment.ForcedOpen(int(timeT), maskedMsg, h)

	/* TIME experiment*/
	// for round := 0; round < 10; round++ {
	// 	fmt.Println("")
	// 	generateStart := time.Now()
	// 	maskedMsg, h, M_k, a1, a2, z := timedCommitment.GenerateTC(g, m_k, r_k, p, timeT)
	// 	generateElapsed += float64(time.Since(generateStart).Milliseconds())
	// 	fmt.Println("===>[Generate]finish")

	// 	verifyStart := time.Now()
	// 	result := timedCommitment.VerifyTC(timeT, maskedMsg, g, m_k, r_k, p, h, M_k, a1, a2, z)
	// 	verifyElapsed += float64(time.Since(verifyStart).Milliseconds())
	// 	fmt.Println("===>[Verify]", result)

	// 	openStart := time.Now()
	// 	openMsg := timedCommitment.ForcedOpen(timeT, maskedMsg, h)

	// 	randomNumber := big.NewInt(0)
	// 	randomNumber.Xor(randomNumber, openMsg)
	// 	openElapsed += float64(time.Since(openStart).Milliseconds())
	// 	fmt.Println("===>[ForcedOpen]", randomNumber)
	// }

	// fmt.Println("===>[initElapsed]", initElapsed)
	// fmt.Println("===>[generateElapsed]", generateElapsed/10)
	// fmt.Println("===>[verifyElapsed]", verifyElapsed/10)
	// fmt.Println("===>[openElapsed]", openElapsed/10)
}
