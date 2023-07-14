package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"dkg/DKG"
	"dkg/config"
	"dkg/msg/errSetupMsgpb"
	"dkg/msg/groupMsgpb"
	"dkg/msg/rMsgpb"
	"dkg/msg/tcSetupMsgpb"
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

func SendTcInitMsg(nodes []*DKG.Node, publickey kyber.Point, ips []string, pubKeys []kyber.Point, pubPoly *share.PubPoly) {
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

		tc := tcSetupMsgpb.NewTcSetupMsgHandleClient(conn)
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

		_, err = tc.TcSetupMsgReceive(ctx, &tcSetupMsgpb.TcSetupMsg{Id: int64(i), Ip: ip,
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

func SendErrInitMsg(nodes []*DKG.Node, publickey kyber.Point, ips []string, pubPoly *share.PubPoly) {
	for i, ip := range ips {
		fmt.Printf("Iniaialize node %d\n", i)

		conn, err := grpc.Dial(ip, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			fmt.Println("===>[!!!Generator]did not connect:", err)
			continue
		}

		errConn := errSetupMsgpb.NewErrSetupMsgHandleClient(conn)
		ctx, _ := context.WithTimeout(context.Background(), time.Second)

		SecretShareVBuf := new(bytes.Buffer)
		len, err := nodes[i].SecretShare.V.MarshalTo(SecretShareVBuf)
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

		_, err = errConn.ErrSetupMsgReceive(ctx, &errSetupMsgpb.ErrSetupMsg{Id: int64(i),
			SecretShareI: int64(nodes[i].SecretShare.I), SecretShareV: base64.StdEncoding.EncodeToString(SecretShareVBuf.Bytes()),
			GlobalPubKey: base64.StdEncoding.EncodeToString(GlobalPubKeyBuf.Bytes()),
			PubPolyBase:  base64.StdEncoding.EncodeToString(pubPolyBaseBuf.Bytes()), PubPolyCommit: PubPolyCommit})
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

func SendGroupMsg(ips []string, groupA, groupB, groupC, mkA, mkB, mkC, rkA, rkB, rkC, pA, pB, pC *big.Int, timeT int) {
	for i, ip := range ips {
		fmt.Printf("Send group to node %d\n", i)

		conn, err := grpc.Dial(ip, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			fmt.Println("===>[!!!Generator]did not connect:", err)
			continue
		}

		tc := groupMsgpb.NewGroupMsgHandleClient(conn)
		ctx, _ := context.WithTimeout(context.Background(), time.Second)

		_, err = tc.GroupMsgReceive(ctx, &groupMsgpb.GroupMsg{GroupA: groupA.String(), GroupB: groupB.String(), GroupC: groupC.String(), TimeT: int64(timeT),
			MkA: mkA.String(), MkB: mkB.String(), MkC: mkC.String(),
			RkA: rkA.String(), RkB: rkB.String(), RkC: rkC.String(),
			PA: pA.String(), PB: pB.String(), PC: pC.String()})
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
	var errshares []*share.PriShare
	bigTwo := big.NewInt(2)
	n := 4

	nodes, publicKey, errnodes, errpublicKey, ips, pubKeys := DKG.DKG(n)

	msg := []byte("Hello threshold Boneh-Lynn-Shacham")
	suite := bn256.NewSuite()

	/* TC setup */
	for _, node := range nodes {
		shares = append(shares, node.SecretShare)
	}

	priPoly, err := share.RecoverPriPoly(suite.G2(), shares, 2*n/3+1, n)
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

	sig, err := tbls.Recover(suite, pubPoly, msg, sigShares, 2*n/3+1, n)
	if err != nil {
		panic(fmt.Errorf("===>[ERROR from tbls]Recover() failed:%s", err))
	}

	err = bls.Verify(suite, pubPoly.Commit(), msg, sig)
	if err != nil {
		panic(fmt.Errorf("===>[ERROR from tbls]Commit() failed:%s", err))
	} else {
		fmt.Println("Recover then Verify pass")
	}

	/* Error setup */
	for _, node := range errnodes {
		errshares = append(errshares, node.SecretShare)
	}

	errpriPoly, err := share.RecoverPriPoly(suite.G2(), errshares, n/3+1, n)
	if err != nil {
		panic(fmt.Errorf("===>[ERROR from tbls]RecoverPriPoly() failed:%s", err))
	}
	errpubPoly := errpriPoly.Commit(suite.G2().Point().Base())
	fmt.Println("Secret key is:", errpriPoly.Secret())
	fmt.Println("pubPoly is:", errpubPoly.Commit())
	fmt.Println("Threshold is:", errpubPoly.Threshold())
	fmt.Println("Public key is:", errpublicKey)

	errsigShares := make([][]byte, 0)
	for _, node := range errnodes {
		sig, err := tbls.Sign(suite, node.SecretShare, msg)
		if err != nil {
			panic(fmt.Errorf("===>[ERROR from tbls]Sign() failed:%s", err))
		}
		errsigShares = append(errsigShares, sig)

		err = tbls.Verify(suite, errpubPoly, msg, sig)
		if err != nil {
			panic(fmt.Errorf("===>[ERROR from tbls]Verify() failed:%s", err))
		} else {
			fmt.Println("Partial Verify pass")
		}
	}

	sig, err = tbls.Recover(suite, errpubPoly, msg, errsigShares, n/3+1, n)
	if err != nil {
		panic(fmt.Errorf("===>[ERROR from tbls]Recover() failed:%s", err))
	}

	err = bls.Verify(suite, errpubPoly.Commit(), msg, sig)
	if err != nil {
		panic(fmt.Errorf("===>[ERROR from tbls]Commit() failed:%s", err))
	} else {
		fmt.Println("Recover then Verify pass")
	}

	config.InitGroup()

	// Test for crypto part
	// binaryquadraticform.TestInit()
	// binaryquadraticform.TestExp()
	// maskedMsg, h, M_k, a1, a2, z := timedCommitment.GenerateTC(g, m_k, r_k, p, int(*timeT))
	// fmt.Println(timedCommitment.VerifyTC(int(*timeT), maskedMsg, g, m_k, r_k, p, h, M_k, a1, a2, z))
	// timedCommitment.ForcedOpen(int(*timeT), maskedMsg, h)

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

	SendTcInitMsg(nodes, publicKey, ips, pubKeys, pubPoly)
	SendErrInitMsg(errnodes, errpublicKey, ips, errpubPoly)
	SendGroupMsg(ips, groupA, groupB, groupC, mkA, mkB, mkC, rkA, rkB, rkC, pA, pB, pC, timeT)

	time.Sleep(2 * time.Second)
	SendRMsg(ips, r0)
}
