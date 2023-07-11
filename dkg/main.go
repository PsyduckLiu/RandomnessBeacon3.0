package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"dkg/DKG"
	"dkg/config"
	"dkg/msg/groupMsgpb"
	"dkg/msg/rMsgpb"
	"dkg/msg/setupMsgpb"
	"encoding/base64"
	"fmt"
	"math/big"
	"time"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/kyber/v3/sign/bls"
	"go.dedis.ch/kyber/v3/sign/tbls"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func SendInitMsg(nodes []*DKG.Node, publickey kyber.Point, ips []string, pubKeys []kyber.Point, pubPoly *share.PubPoly) {
	var pksString []string

	for _, pk := range pubKeys {
		pksStringBuf := new(bytes.Buffer)
		len, err := pk.MarshalTo(pksStringBuf)
		if err != nil {
			fmt.Println("===>[!!!Generator]pksStringWriter MarshalTo:", err)
			continue
		} else {
			fmt.Println("pksStringWriter Length is:", len)
		}

		pksString = append(pksString, base64.StdEncoding.EncodeToString(pksStringBuf.Bytes()))
	}

	for i, ip := range ips {
		fmt.Printf("Iniaialize node %d\n", i)

		conn, err := grpc.Dial(ip, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			fmt.Println("===>[!!!Generator]did not connect:", err)
			continue
		}

		tc := setupMsgpb.NewSetupMsgHandleClient(conn)
		ctx, _ := context.WithTimeout(context.Background(), time.Second)

		LocalPubKeyBuf := new(bytes.Buffer)
		len, err := nodes[i].PubKey.MarshalTo(LocalPubKeyBuf)
		if err != nil {
			fmt.Println("===>[!!!Generator]LocalPubKeyWriter MarshalTo:", err)
			continue
		} else {
			fmt.Println("LocalPubKeyWriter Length is:", len)
		}

		LocalPrivKeyBuf := new(bytes.Buffer)
		len, err = nodes[i].PrivKey.MarshalTo(LocalPrivKeyBuf)
		if err != nil {
			fmt.Println("===>[!!!Generator]LocalPrivKeyWriter MarshalTo:", err)
			continue
		} else {
			fmt.Println("LocalPrivKeyWriter Length is:", len)
		}

		SecretShareVBuf := new(bytes.Buffer)
		len, err = nodes[i].SecretShare.V.MarshalTo(SecretShareVBuf)
		if err != nil {
			fmt.Println("===>[!!!Generator]SecretShareVWriter MarshalTo:", err)
			continue
		} else {
			fmt.Println("SecretShareVWriter Length is:", len)
		}

		GlobalPubKeyBuf := new(bytes.Buffer)
		len, err = publickey.MarshalTo(GlobalPubKeyBuf)
		if err != nil {
			fmt.Println("===>[!!!Generator]GlobalPubKeyWriter MarshalTo:", err)
			continue
		} else {
			fmt.Println("GlobalPubKeyWriter Length is:", len)
		}

		pubPolyBase, pubPolyCommits := pubPoly.Info()

		pubPolyBaseBuf := new(bytes.Buffer)
		len, err = pubPolyBase.MarshalTo(pubPolyBaseBuf)
		if err != nil {
			fmt.Println("===>[!!!Generator]pubPolyBaseBuf MarshalTo:", err)
			continue
		} else {
			fmt.Println("pubPolyBaseBuf Length is:", len)
		}

		var PubPolyCommit []string
		for _, pubPolyCommit := range pubPolyCommits {
			pubPolyCommitBuf := new(bytes.Buffer)
			len, err = pubPolyCommit.MarshalTo(pubPolyCommitBuf)
			if err != nil {
				fmt.Println("===>[!!!Generator]pubPolyCommitBuf MarshalTo:", err)
				continue
			} else {
				fmt.Println("pubPolyCommitBuf Length is:", len)
			}

			PubPolyCommit = append(PubPolyCommit, base64.StdEncoding.EncodeToString(pubPolyCommitBuf.Bytes()))
		}

		_, err = tc.SetupMsgReceive(ctx, &setupMsgpb.SetupMsg{Id: int64(i), Ip: ip,
			LocalPubKey: base64.StdEncoding.EncodeToString(LocalPubKeyBuf.Bytes()), LocalPrivKey: base64.StdEncoding.EncodeToString(LocalPrivKeyBuf.Bytes()),
			SecretShareI: int64(nodes[i].SecretShare.I), SecretShareV: base64.StdEncoding.EncodeToString(SecretShareVBuf.Bytes()),
			GlobalPubKey: base64.StdEncoding.EncodeToString(GlobalPubKeyBuf.Bytes()),
			Ips:          ips, PubKeys: pksString,
			PubPolyBase: base64.StdEncoding.EncodeToString(pubPolyBaseBuf.Bytes()), PubPolyCommit: PubPolyCommit})
		if err != nil {
			fmt.Println("Send to", ip)
			fmt.Println("===>[!!!Collector]Failed to response:", err)
			continue
		}
	}
}

func SendRMsg(ips []string, r0 *big.Int) {
	for i, ip := range ips {
		fmt.Printf("Send r to node %d\n", i)

		conn, err := grpc.Dial(ip, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			fmt.Println("===>[!!!Generator]did not connect:", err)
			continue
		}

		tc := rMsgpb.NewRMsgHandleClient(conn)
		ctx, _ := context.WithTimeout(context.Background(), time.Second)

		_, err = tc.RMsgReceive(ctx, &rMsgpb.RMsg{R0: r0.String()})
		if err != nil {
			fmt.Println("Send to", ip)
			fmt.Println("===>[!!!Collector]Failed to response:", err)
			continue
		}
	}
}

func SendGroupMsg(ips []string, groupA, groupB, groupC, timeT, mkA, mkB, mkC, rkA, rkB, rkC, pA, pB, pC int) {
	for i, ip := range ips {
		fmt.Printf("Send group to node %d\n", i)

		conn, err := grpc.Dial(ip, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			fmt.Println("===>[!!!Generator]did not connect:", err)
			continue
		}

		tc := groupMsgpb.NewGroupMsgHandleClient(conn)
		ctx, _ := context.WithTimeout(context.Background(), time.Second)

		_, err = tc.GroupMsgReceive(ctx, &groupMsgpb.GroupMsg{GroupA: int64(groupA), GroupB: int64(groupB), GroupC: int64(groupC), TimeT: int64(timeT),
			MkA: int64(mkA), MkB: int64(mkB), MkC: int64(mkC),
			RkA: int64(rkA), RkB: int64(rkB), RkC: int64(rkC),
			PA: int64(pA), PB: int64(pB), PC: int64(pC)})
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
	bigTwo := big.NewInt(2)
	n := 4
	t := n/2 + 1

	nodes, publicKey, ips, pubKeys := DKG.DKG(n)

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
	fmt.Println("pubPoly is:", pubPoly.Commit())
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

	config.InitGroup()

	// Test for crypto part
	// binaryquadraticform.TestInit()
	// binaryquadraticform.TestExp()
	// maskedMsg, h, M_k, a1, a2, z := timedCommitment.GenerateTC()
	// fmt.Println(timedCommitment.VerifyTC(maskedMsg, h, M_k, a1, a2, z))
	// timedCommitment.ForcedOpen(maskedMsg, h)

	groupA, groupB, groupC := config.GetGroupParameter()
	timeT := config.GetTimeParameter()
	mkA, mkB, mkC, rkA, rkB, rkC := config.GetPublicGroupParameter()
	pA, pB, pC := config.GetPublicParameterProof()

	upper := new(big.Int)
	upper.Exp(bigTwo, big.NewInt(50), nil)
	r0, err := rand.Int(rand.Reader, upper)
	if err != nil {
		panic(fmt.Errorf("===>[ERROR from GenerateTC]Generate random message failed:%s", err))
	}
	fmt.Println("===>[GenerateTC]R0 is", r0)

	SendInitMsg(nodes, publicKey, ips, pubKeys, pubPoly)
	SendGroupMsg(ips, groupA, groupB, groupC, timeT, mkA, mkB, mkC, rkA, rkB, rkC, pA, pB, pC)

	time.Sleep(2 * time.Second)
	SendRMsg(ips, r0)
}
