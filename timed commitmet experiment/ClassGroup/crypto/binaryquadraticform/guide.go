package binaryquadraticform

import (
	"fmt"
	"math/big"
)

// Initialization
func TestInit() {
	form1, _ := NewBQuadraticForm(big.NewInt(1), big.NewInt(1), big.NewInt(6))
	fmt.Println("TestInit 1")
	fmt.Println(form1.a, form1.discriminant)

	form2, _ := NewBQuadraticForm(big.NewInt(13), big.NewInt(7), big.NewInt(1113))
	fmt.Println("TestInit 1")
	fmt.Println(form2.a, form2.discriminant)

	comp, _ := form2.Composition(form2)
	fmt.Println("TestInit 3")
	fmt.Println(comp.a, comp.discriminant)

	square, _ := form2.Exp(big.NewInt(2))
	fmt.Println("TestInit 4")
	fmt.Println(square.a, square.discriminant)
}

// Exp
func TestExp() {
	form1, _ := NewBQuadraticForm(big.NewInt(31), big.NewInt(24), big.NewInt(15951))
	fmt.Println("TestExp 1")
	fmt.Println(form1.a, form1.b, form1.c, form1.discriminant)

	for i := 1; i <= 5; i++ {
		got, _ := form1.Exp(big.NewInt(int64(i)))
		fmt.Println("TestExp 2")
		fmt.Println(got.a, got.b, got.c, got.discriminant)
	}

}
