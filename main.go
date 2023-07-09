package main

import (
	dkg "RB/DKG"
	"RB/msgpb/helloMsgpb"
	"context"
	"fmt"
	"time"

	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/kyber/v3/sign/bls"
	"go.dedis.ch/kyber/v3/sign/tbls"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func SendMsg(ips []string) {
	for i, ip := range ips {
		fmt.Printf("Say hi to node %d\n", i)

		conn, err := grpc.Dial(ip, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			fmt.Println("===>[!!!Generator]did not connect:", err)
			continue
		}

		tc := helloMsgpb.NewHelloMsgHandleClient(conn)
		ctx, _ := context.WithTimeout(context.Background(), time.Second)

		_, err = tc.HelloMsgReceive(ctx, &helloMsgpb.HelloMsg{HelloMsg: "hello"})
		if err != nil {
			fmt.Println("Send to", ip)
			fmt.Println("===>[!!!Collector]Failed to response:", err)
			continue
		}
	}
}

func main() {
	var err error
	var shares []*share.PriShare
	n := 4
	t := n/2 + 1

	nodes, publicKey, ips := dkg.DKG(n)

	msg := []byte("Hello threshold Boneh-Lynn-Shacham")
	suite := bn256.NewSuite()

	for _, node := range nodes {
		shares = append(shares, node.SecretShare)
	}

	priPoly, err := share.RecoverPriPoly(suite.G2(), shares, t, n)
	if err != nil {
		panic(fmt.Errorf("===>[ERROR from tbls]RecoverPriPoly() failed:%s", err))
	}
	pubPoly := priPoly.Commit(suite.G2().Point().Base())
	fmt.Println("Secret key is:", priPoly.Secret())
	fmt.Println("Threshold is:", pubPoly.Threshold())
	fmt.Println("Public key is:", publicKey)

	sigShares := make([][]byte, 0)
	for _, node := range nodes {
		sig, err := tbls.Sign(suite, node.SecretShare, msg)
		if err != nil {
			panic(fmt.Errorf("===>[ERROR from tbls]Sign() failed:%s", err))
		}
		sigShares = append(sigShares, sig)

		err = tbls.Verify(suite, pubPoly, msg, sig)
		if err != nil {
			panic(fmt.Errorf("===>[ERROR from tbls]Verify() failed:%s", err))
		} else {
			fmt.Println("Partial Verify pass")
		}
	}

	sig, err := tbls.Recover(suite, pubPoly, msg, sigShares, t, n)
	if err != nil {
		panic(fmt.Errorf("===>[ERROR from tbls]Recover() failed:%s", err))
	}

	err = bls.Verify(suite, pubPoly.Commit(), msg, sig)
	if err != nil {
		panic(fmt.Errorf("===>[ERROR from tbls]Commit() failed:%s", err))
	} else {
		fmt.Println("Recover then Verify pass")
	}

	SendMsg(ips)

}
