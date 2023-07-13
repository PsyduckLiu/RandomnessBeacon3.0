package main

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"tc/config"
	tc "tc/src"
	"time"
)

func main() {
	fmt.Println("Start running timed commitment")

	timeParameters := [...]int{15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25}
	for _, timeParameter := range timeParameters {
		processTC(timeParameter)
	}

}

func processTC(timeParameter int) {
	// group parameter contains prime numbers p,q and a large number n=p*q of groupLength bits
	groupLength := 128
	groupParameter, err := Setup(groupLength)
	if err != nil {
		fmt.Println("generate group parameter wrong", groupParameter)
	}

	initElapsed := 0.0
	generateElapsed := 0.0
	verifyElapsed := 0.0
	openElapsed := 0.0

	initStart := time.Now()
	g, mArray, proofSet := tc.GeneratePublicParameter(groupParameter, groupLength, timeParameter)
	var mArrayString []string
	for _, m := range mArray {
		mArrayString = append(mArrayString, m.String())
	}
	config.SetupConfig(g.String(), groupParameter.N.String(), mArrayString, proofSet)
	initElapsed += float64(time.Since(initStart).Milliseconds())

	for i := 0; i < 10; i++ {
		// generate commit
		generateStart := time.Now()
		c, h, rKSubOne, rK, a1, a2, a3, z := tc.GenerateCommit(groupLength, groupParameter)
		generateElapsed += float64(time.Since(generateStart).Milliseconds())
		// fmt.Println("[Main]c is", c)

		// verify tc
		verifyStart := time.Now()
		result := VerifyTC(a1.String(), a2.String(), a3.String(), z.String(), h.String(), rKSubOne.String(), rK.String())
		verifyElapsed += float64(time.Since(verifyStart).Milliseconds())
		if !result {
			fmt.Println("Not pass")
		}
		// fmt.Println("Time is", verifyElapsed)

		openStart := time.Now()
		tc.ForcedOpen(c, h, rKSubOne, rK, timeParameter)
		openElapsed += float64(time.Since(openStart).Milliseconds())
	}

	fmt.Printf("time parameter is %v\n", timeParameter)
	fmt.Println("===>[initElapsed]", initElapsed)
	fmt.Println("===>[generateElapsed]", generateElapsed/10)
	fmt.Println("===>[verifyElapsed]", verifyElapsed/10)
	fmt.Println("===>[openElapsed]", openElapsed/10)
}

// Setup Generate Group parameter
func Setup(nLength int) (*tc.GroupParameter, error) {
	groupParameter, err := tc.GenerateGroupParameter(rand.Reader, nLength)

	return groupParameter, err
}

// verify TC
func VerifyTC(A1 string, A2 string, A3 string, Z string, H string, RKSubOne string, RK string) bool {
	// fmt.Println("the number of goroutines: ", runtime.NumGoroutine())
	// start := time.Now()
	mArray := config.GetMArray()
	g := config.GetG()
	N := config.GetN()

	a1, _ := new(big.Int).SetString(A1, 10)
	a2, _ := new(big.Int).SetString(A2, 10)
	a3, _ := new(big.Int).SetString(A3, 10)
	z, _ := new(big.Int).SetString(Z, 10)
	h, _ := new(big.Int).SetString(H, 10)
	rKSubOne, _ := new(big.Int).SetString(RKSubOne, 10)
	rK, _ := new(big.Int).SetString(RK, 10)

	nHash := new(big.Int).SetBytes(Digest(N))
	gHash := new(big.Int).SetBytes(Digest((g)))
	mSubOneHash := new(big.Int).SetBytes(Digest(mArray[len(mArray)-3]))
	mHash := new(big.Int).SetBytes(Digest(mArray[len(mArray)-2]))
	a1Hash := new(big.Int).SetBytes(Digest(a1))
	a2Hash := new(big.Int).SetBytes(Digest(a2))
	a3Hash := new(big.Int).SetBytes(Digest(a3))

	e := big.NewInt(0)
	e.Xor(e, gHash)
	e.Xor(e, nHash)
	e.Xor(e, mSubOneHash)
	e.Xor(e, mHash)
	e.Xor(e, a1Hash)
	e.Xor(e, a2Hash)
	e.Xor(e, a3Hash)
	fmt.Println("after xor", e)

	// start1 := time.Now()
	result1 := new(big.Int).Set(g)
	result1.Exp(result1, z, N)
	result2 := new(big.Int).Set(h)
	result2.Exp(result2, e, N)
	result1.Mul(result1, result2)
	result1.Mod(result1, N)
	// end1 := time.Now()
	// fmt.Println("passed time1", end1.Sub(start1).Seconds())

	// start2 := time.Now()
	result3 := new(big.Int).Set(mArray[len(mArray)-3])
	result3.Exp(result3, z, N)
	result4 := new(big.Int).Set(rKSubOne)
	result4.Exp(result4, e, N)
	result3.Mul(result3, result4)
	result3.Mod(result3, N)
	// end2 := time.Now()
	// fmt.Println("passed time2", end2.Sub(start2).Seconds())

	// start3 := time.Now()
	result5 := new(big.Int).Set(mArray[len(mArray)-2])
	result5.Exp(result5, z, N)
	result6 := new(big.Int).Set(rK)
	result6.Exp(result6, e, N)
	result5.Mul(result5, result6)
	result5.Mod(result5, N)
	// end3 := time.Now()
	// fmt.Println("passed time3", end3.Sub(start3).Seconds())

	if a1.Cmp(result1) != 0 {
		fmt.Println("===>[VerifyTC]test1 error")
		return false
	}
	if a2.Cmp(result3) != 0 {
		fmt.Println("===>[VerifyTC]test2 error")
		return false
	}
	if a3.Cmp(result5) != 0 {
		fmt.Println("===>[VerifyTC]test3 error")
		return false
	}

	// end := time.Now()
	// fmt.Println("passed time", end.Sub(start).Seconds())
	return true
}

// Hash message v, using SHA256
func Digest(v interface{}) []byte {
	h := sha256.New()
	h.Write([]byte(fmt.Sprintf("%v", v)))
	digest := h.Sum(nil)

	return digest
}
