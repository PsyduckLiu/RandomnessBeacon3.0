package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"node/crypto/binaryquadraticform"
	"node/crypto/timedCommitment"
	"node/msg/blankReplyMsgpb"
	"node/msg/blankRequireMsgpb"
	"node/msg/groupMsgpb"
	"node/msg/rMsgpb"
	"node/msg/setupMsgpb"
	"node/msg/tcFullSigMsgpb"
	"node/msg/tcMsgpb"
	"node/msg/tcPartSigMsgpb"
	"node/util"
	"os"
	"strconv"
	"time"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/kyber/v3/sign/bls"
	"go.dedis.ch/kyber/v3/sign/tbls"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type TC struct {
	MaskedMsg string
	HA        string
	HB        string
	HC        string
}

var tcSet = make(map[int][]byte)
var resultSet = make(map[int]*big.Int)
var tcPartSigSet = make([][]byte, 0)
var tcFullSigSet = make(map[int][]byte)
var round = 0
var suite = bn256.NewSuite()

var Id = new(int64)
var Ip = new(string)
var PubKey = suite.G2().Point()
var PrivKey = suite.G1().Scalar()
var SecretShare = new(share.PriShare)
var GlobalPubKey = suite.G2().Point()
var pubKeys = new([]kyber.Point)
var ips = new([]string)
var pubPoly = new(share.PubPoly)
var R0 = new(big.Int)

var g = new(binaryquadraticform.BQuadraticForm)
var m_k = new(binaryquadraticform.BQuadraticForm)
var r_k = new(binaryquadraticform.BQuadraticForm)
var p = new(binaryquadraticform.BQuadraticForm)
var timeT = new(int64)

// setupMsgServer is used to implement setupMsgpb.SetupMsgReceive
type setupMsgServer struct {
	setupMsgpb.UnimplementedSetupMsgHandleServer
}

// rMsgServer is used to implement rMsgpb.RMsgReceive
type rMsgServer struct {
	rMsgpb.UnimplementedRMsgHandleServer
}

// groupMsgServer is used to implement groupMsgpb.GroupMsgReceive
type groupMsgServer struct {
	groupMsgpb.UnimplementedGroupMsgHandleServer
}

// tcMsgServer is used to implement tcMsgpb.TcMsgReceive
type tcMsgServer struct {
	tcMsgpb.UnimplementedTcMsgHandleServer
}

// tcMsgServer is used to implement tcMsgpb.TcMsgReceive
type tcPartSigMsgServer struct {
	tcPartSigMsgpb.UnimplementedTcPartSigMsgHandleServer
}

// tcMsgServer is used to implement tcMsgpb.TcMsgReceive
type tcFullSigMsgServer struct {
	tcFullSigMsgpb.UnimplementedTcFullSigMsgHandleServer
}

// tcMsgServer is used to implement tcMsgpb.TcMsgReceive
type blankRequireMsgServer struct {
	blankRequireMsgpb.UnimplementedBlankRequireMsgHandleServer
}

// tcMsgServer is used to implement tcMsgpb.TcMsgReceive
type blankReplyMsgServer struct {
	blankReplyMsgpb.UnimplementedBlankReplyMsgHandleServer
}

// setupMsgReceive implements setupMsgpb.SetupMsgReceive
func (hs *setupMsgServer) SetupMsgReceive(ctx context.Context, in *setupMsgpb.SetupMsg) (*setupMsgpb.SetupMsgResponse, error) {
	*Id, *Ip = in.GetId(), in.GetIp()
	fmt.Printf("[Setup]Node %d is ready, IP address is %s\n", *Id, *Ip)

	SecretShareV := suite.G1().Scalar()
	localPubKey := in.GetLocalPubKey()
	localPrivKey := in.GetLocalPrivKey()
	secretShareI := in.GetSecretShareI()
	secretShareV := in.GetSecretShareV()
	localPubKeybytes, _ := base64.StdEncoding.DecodeString(localPubKey)
	localPrivKeybytes, _ := base64.StdEncoding.DecodeString(localPrivKey)
	secretShareVbytes, _ := base64.StdEncoding.DecodeString(secretShareV)

	localPubKeyBuf := new(bytes.Buffer)
	localPubKeyBuf.Write(localPubKeybytes)
	len, err := PubKey.UnmarshalFrom(localPubKeyBuf)
	if err != nil {
		fmt.Println("===>[!!!Node]PubKey UnmarshalFrom:", err)
	} else {
		fmt.Println("PubKey Length is:", len)
	}

	localPrivKeyBuf := new(bytes.Buffer)
	localPrivKeyBuf.Write(localPrivKeybytes)
	len, err = PrivKey.UnmarshalFrom(localPrivKeyBuf)
	if err != nil {
		fmt.Println("===>[!!!Node]PrivKey UnmarshalFrom:", err)
	} else {
		fmt.Println("PrivKey Length is:", len)
	}

	secretShareVBuf := new(bytes.Buffer)
	secretShareVBuf.Write(secretShareVbytes)
	len, err = SecretShareV.UnmarshalFrom(secretShareVBuf)
	if err != nil {
		fmt.Println("===>[!!!Node]SecretShareV UnmarshalFrom:", err)
	} else {
		fmt.Println("SecretShareV Length is:", len)
	}

	SecretShare.I = int(secretShareI)
	SecretShare.V = SecretShareV
	fmt.Printf("[Setup]Info of Node %d: local public key is %v\n", *Id, PubKey)
	fmt.Printf("[Setup]Info of Node %d: local private key is %v\n", *Id, PrivKey)
	fmt.Printf("[Setup]Info of Node %d: local secret share is %v\n", *Id, SecretShare)

	globalPubKey := in.GetGlobalPubKey()
	globalPubKeybytes, _ := base64.StdEncoding.DecodeString(globalPubKey)
	globalPubKeyBuf := new(bytes.Buffer)
	globalPubKeyBuf.Write(globalPubKeybytes)
	len, err = GlobalPubKey.UnmarshalFrom(globalPubKeyBuf)
	if err != nil {
		fmt.Println("===>[!!!Node]globalPubKey UnmarshalFrom:", err)
	} else {
		fmt.Println("globalPubKey Length is:", len)
	}
	fmt.Printf("[Setup]Info of Node %d: global public key is %v\n", *Id, GlobalPubKey)

	*ips = in.GetIps()
	peerPubKeys := in.GetPubKeys()
	for _, pk := range peerPubKeys {
		pkPoint := suite.G2().Point()
		pkbytes, _ := base64.StdEncoding.DecodeString(pk)

		pkBuf := new(bytes.Buffer)
		pkBuf.Write(pkbytes)
		len, err = pkPoint.UnmarshalFrom(pkBuf)
		if err != nil {
			fmt.Println("===>[!!!Node]pkPoint UnmarshalFrom:", err)
		} else {
			fmt.Println("pkPoint Length is:", len)
		}

		*pubKeys = append(*pubKeys, pkPoint)
	}
	fmt.Printf("[Setup]Info of Node %d: peer ips are %v\n", *Id, ips)
	fmt.Printf("[Setup]Info of Node %d: peer pks are %v\n", *Id, pubKeys)

	pubPolyBase := suite.G2().Point()
	pubPolyBasebytes, _ := base64.StdEncoding.DecodeString(in.GetPubPolyBase())
	pubPolyBaseBuf := new(bytes.Buffer)
	pubPolyBaseBuf.Write(pubPolyBasebytes)
	len, err = pubPolyBase.UnmarshalFrom(pubPolyBaseBuf)
	if err != nil {
		fmt.Println("===>[!!!Node]pubPolyBase UnmarshalFrom:", err)
	} else {
		fmt.Println("pubPolyBase Length is:", len)
	}

	var PubPolyCommits []kyber.Point
	pubPolyCommits := in.GetPubPolyCommit()
	for _, pubPolyCommit := range pubPolyCommits {
		PubPolyCommit := suite.G2().Point()
		PubPolyCommitbytes, _ := base64.StdEncoding.DecodeString(pubPolyCommit)
		PubPolyCommitBuf := new(bytes.Buffer)
		PubPolyCommitBuf.Write(PubPolyCommitbytes)
		len, err = PubPolyCommit.UnmarshalFrom(PubPolyCommitBuf)
		if err != nil {
			fmt.Println("===>[!!!Node]PubPolyCommit UnmarshalFrom:", err)
		} else {
			PubPolyCommits = append(PubPolyCommits, PubPolyCommit)
			fmt.Println("PubPolyCommit Length is:", len)
		}
	}

	pubPoly = share.NewPubPoly(suite.G2(), pubPolyBase, PubPolyCommits)
	fmt.Printf("[Setup]Info of Node %d: pubPoly is %v\n", *Id, pubPoly.Commit())

	return &setupMsgpb.SetupMsgResponse{}, nil
}

// rMsgReceive implements rMsgpb.RMsgReceive
func (hs *rMsgServer) RMsgReceive(ctx context.Context, in *rMsgpb.RMsg) (*rMsgpb.RMsgResponse, error) {
	r0 := in.GetR0()
	R0.SetString(r0, 10)
	fmt.Printf("[Setup]Info of Node %d: Initial value R0 is %v\n", *Id, R0)

	return &rMsgpb.RMsgResponse{}, nil
}

// groupMsgReceive implements groupMsgpb.GroupMsgReceive
func (hs *groupMsgServer) GroupMsgReceive(ctx context.Context, in *groupMsgpb.GroupMsg) (*groupMsgpb.GroupMsgResponse, error) {
	var err error
	groupA, groupB, groupC := in.GetGroupA(), in.GetGroupB(), in.GetGroupC()
	*timeT = in.GetTimeT()
	mkA, mkB, mkC, rkA, rkB, rkC := in.GetMkA(), in.GetMkB(), in.GetMkC(), in.GetRkA(), in.GetRkB(), in.GetRkC()
	pA, pB, pC := in.GetPA(), in.GetPB(), in.GetPC()

	g, err = binaryquadraticform.NewBQuadraticForm(big.NewInt(int64(groupA)), big.NewInt(int64(groupB)), big.NewInt(int64(groupC)))
	fmt.Printf("===>[InitConfig]The group element g is (a=%v,b=%v,c=%v,d=%v)\n", g.GetA(), g.GetB(), g.GetC(), g.GetDiscriminant())
	if err != nil {
		panic(fmt.Errorf("===>[ERROR from InitConfig]Generate new BQuadratic Form failed: %s", err))
	}
	m_k, err = binaryquadraticform.NewBQuadraticForm(big.NewInt(int64(mkA)), big.NewInt(int64(mkB)), big.NewInt(int64(mkC)))
	fmt.Printf("===>[InitConfig] Mk is (a=%v,b=%v,c=%v,d=%v)\n", m_k.GetA(), m_k.GetB(), m_k.GetC(), m_k.GetDiscriminant())
	if err != nil {
		panic(fmt.Errorf("===>[ERROR from InitConfig]Generate new BQuadratic Form failed: %s", err))
	}
	r_k, err = binaryquadraticform.NewBQuadraticForm(big.NewInt(int64(rkA)), big.NewInt(int64(rkB)), big.NewInt(int64(rkC)))
	fmt.Printf("===>[InitConfig] Rk is (a=%v,b=%v,c=%v,d=%v)\n", r_k.GetA(), r_k.GetB(), r_k.GetC(), r_k.GetDiscriminant())
	if err != nil {
		panic(fmt.Errorf("===>[ERROR from InitConfig]Generate new BQuadratic Form failed: %s", err))
	}
	p, err = binaryquadraticform.NewBQuadraticForm(big.NewInt(int64(pA)), big.NewInt(int64(pB)), big.NewInt(int64(pC)))
	fmt.Printf("===>[InitConfig] Proof is (a=%v,b=%v,c=%v,d=%v)\n", p.GetA(), p.GetB(), p.GetC(), p.GetDiscriminant())
	if err != nil {
		panic(fmt.Errorf("===>[ERROR from InitConfig]Generate new BQuadratic Form failed: %s", err))
	}
	fmt.Printf("===>[InitConfig] Time Parameter is t=%v\n", *timeT)

	// Test for crypto part
	// binaryquadraticform.TestInit()
	// binaryquadraticform.TestExp()
	// maskedMsg, h, M_k, a1, a2, z := timedCommitment.GenerateTC(g, m_k, r_k, p, int(*timeT))
	// fmt.Println(timedCommitment.VerifyTC(int(*timeT), maskedMsg, g, m_k, r_k, p, h, M_k, a1, a2, z))
	// timedCommitment.ForcedOpen(int(*timeT), maskedMsg, h)

	return &groupMsgpb.GroupMsgResponse{}, nil
}

// tcMsgReceive implements tcMsgpb.TcMsgReceive
func (ts *tcMsgServer) TcMsgReceive(ctx context.Context, in *tcMsgpb.TcMsg) (*tcMsgpb.TcMsgResponse, error) {
	rawtcMsg := &tcMsgpb.TcMsg{Round: in.Round, MaskedMsg: in.MaskedMsg,
		HA: in.HA, HB: in.HB, HC: in.HC,
		MkA: in.MkA, MkB: in.MkB, MkC: in.MkC,
		A1A: in.A1A, A1B: in.A1B, A1C: in.A1C,
		A2A: in.A2A, A2B: in.A2B, A2C: in.A2C,
		Z: in.Z, Id: in.Id}
	marshaledrawtcMsg, err := json.Marshal(rawtcMsg)
	if err != nil {
		panic(fmt.Errorf("===>[ERROR from TcMsgReceive]Marshal error : %s", err))
	}

	sig, _ := base64.StdEncoding.DecodeString(in.GetSig())
	err = bls.Verify(suite, (*pubKeys)[in.GetId()], marshaledrawtcMsg, sig)
	if err != nil {
		panic(fmt.Errorf("===>[ERROR from TcMsgReceive]Signature Verify() failed:%s", err))
	} else {
		fmt.Println("Signature Verify pass")
	}

	maskedMsg := new(big.Int)
	z := new(big.Int)
	maskedMsg.SetString(in.GetMaskedMsg(), 10)
	z.SetString(in.GetZ(), 10)

	h, err := binaryquadraticform.NewBQuadraticForm(big.NewInt(in.GetHA()), big.NewInt(in.GetHB()), big.NewInt(in.GetHC()))
	fmt.Printf("===>[TcMsgReceive]The group element h is (a=%v,b=%v,c=%v,d=%v)\n", h.GetA(), h.GetB(), h.GetC(), h.GetDiscriminant())
	if err != nil {
		panic(fmt.Errorf("===>[ERROR from TcMsgReceive]Generate new BQuadratic Form failed: %s", err))
	}
	M_k, err := binaryquadraticform.NewBQuadraticForm(big.NewInt(in.GetMkA()), big.NewInt(in.GetMkB()), big.NewInt(in.GetMkC()))
	fmt.Printf("===>[TcMsgReceive]The group element M_K is (a=%v,b=%v,c=%v,d=%v)\n", M_k.GetA(), M_k.GetB(), M_k.GetC(), M_k.GetDiscriminant())
	if err != nil {
		panic(fmt.Errorf("===>[ERROR from TcMsgReceive]Generate new BQuadratic Form failed: %s", err))
	}
	a1, err := binaryquadraticform.NewBQuadraticForm(big.NewInt(in.GetA1A()), big.NewInt(in.GetA1B()), big.NewInt(in.GetA1C()))
	fmt.Printf("===>[TcMsgReceive]The group element a1 is (a=%v,b=%v,c=%v,d=%v)\n", a1.GetA(), a1.GetB(), a1.GetC(), a1.GetDiscriminant())
	if err != nil {
		panic(fmt.Errorf("===>[ERROR from TcMsgReceive]Generate new BQuadratic Form failed: %s", err))
	}
	a2, err := binaryquadraticform.NewBQuadraticForm(big.NewInt(in.GetA2A()), big.NewInt(in.GetA2B()), big.NewInt(in.GetA2C()))
	fmt.Printf("===>[TcMsgReceive]The group element a2 is (a=%v,b=%v,c=%v,d=%v)\n", a2.GetA(), a2.GetB(), a2.GetC(), a2.GetDiscriminant())
	if err != nil {
		panic(fmt.Errorf("===>[ERROR from TcMsgReceive]Generate new BQuadratic Form failed: %s", err))
	}

	result := timedCommitment.VerifyTC(int(*timeT), maskedMsg, g, m_k, r_k, p, h, M_k, a1, a2, z)
	if result {
		fmt.Printf("===>[TcMsgReceive]new tc from node %v pass!!!\n", in.Id)
		go SolveTC(round, maskedMsg, h)

		newTC := TC{
			MaskedMsg: maskedMsg.String(),
			HA:        h.GetA().String(),
			HB:        h.GetB().String(),
			HC:        h.GetC().String(),
		}

		marshaledTC, err := json.Marshal(newTC)
		if err != nil {
			panic(fmt.Errorf("===>[ERROR from TcMsgReceive]Marshal error : %s", err))
		}

		tcSet[int(in.Id)] = marshaledTC
	}

	return &tcMsgpb.TcMsgResponse{}, nil
}

// tcMsgReceive implements tcMsgpb.TcMsgReceive
func (ts *tcPartSigMsgServer) TcPartSigMsgReceive(ctx context.Context, in *tcPartSigMsgpb.TcPartSigMsg) (*tcPartSigMsgpb.TcPartSigMsgResponse, error) {
	sig, _ := base64.StdEncoding.DecodeString(in.GetSig())

	err := tbls.Verify(suite, pubPoly, util.Digest(tcSet[int(in.Round)%len(*ips)]), sig)
	if err != nil {
		panic(fmt.Errorf("===>[ERROR from tbls]Verify() failed:%s", err))
	} else {
		tcPartSigSet = append(tcPartSigSet, sig)
		fmt.Println("Partial Verify pass")
	}

	return &tcPartSigMsgpb.TcPartSigMsgResponse{}, nil
}

// tcMsgReceive implements tcMsgpb.TcMsgReceive
func (ts *tcFullSigMsgServer) TcFullSigMsgReceive(ctx context.Context, in *tcFullSigMsgpb.TcFullSigMsg) (*tcFullSigMsgpb.TcFullSigMsgResponse, error) {
	sig, _ := base64.StdEncoding.DecodeString(in.GetSig())

	err := bls.Verify(suite, pubPoly.Commit(), util.Digest(tcSet[int(in.Round)%len(*ips)]), sig)
	if err != nil {
		panic(fmt.Errorf("===>[ERROR from bls]Commit() failed:%s", err))
	} else {
		tcFullSigSet[int(in.Round)%len(*ips)] = sig
		fmt.Println("[TcFullSigMsgReceive]Full Verify pass")
	}

	return &tcFullSigMsgpb.TcFullSigMsgResponse{}, nil
}

// tcMsgReceive implements tcMsgpb.TcMsgReceive
func (ts *blankRequireMsgServer) BlankRequireMsgReceive(ctx context.Context, in *blankRequireMsgpb.BlankRequireMsg) (*blankRequireMsgpb.BlankRequireMsgResponse, error) {
	rawblankRequireMsg := &blankRequireMsgpb.BlankRequireMsg{RequireRound: in.RequireRound, CurrentRound: in.CurrentRound, Id: in.Id}
	marshaledrawblankRequireMsg, err := json.Marshal(rawblankRequireMsg)
	if (err != nil) || (int(in.CurrentRound)%len(*ips) != int(in.Id)) {
		panic(fmt.Errorf("===>[ERROR from BlankRequireMsgReceive]Marshal error : %s", err))
	}

	sig, _ := base64.StdEncoding.DecodeString(in.GetSig())
	err = bls.Verify(suite, (*pubKeys)[in.GetId()], marshaledrawblankRequireMsg, sig)
	if err != nil {
		panic(fmt.Errorf("===>[ERROR from BlankRequireMsgReceive]Signature Verify() failed:%s", err))
	} else {
		fmt.Println("[BlankRequireMsgReceive]Signature Verify pass")

		if tcFullSigSet[int(in.RequireRound)%len(*ips)] != nil {
			newTC := &TC{}
			err = json.Unmarshal(tcSet[int(in.RequireRound)%len(*ips)], newTC)
			if err != nil {
				fmt.Println("===>[!!!Collector]Failed to Unmarshal:", err)
			}

			ip := (*ips)[in.Id]
			conn, err := grpc.Dial(ip, grpc.WithTransportCredentials(insecure.NewCredentials()))
			if err != nil {
				fmt.Println("===>[!!!Generator]did not connect:", err)
			}

			tc := blankReplyMsgpb.NewBlankReplyMsgHandleClient(conn)
			ctx, _ := context.WithTimeout(context.Background(), time.Second)

			blankReplyMsg := &blankReplyMsgpb.BlankReplyMsg{RequireRound: in.RequireRound, MaskedMsg: newTC.MaskedMsg,
				HA: newTC.HA, HB: newTC.HB, HC: newTC.HC, FullSig: base64.StdEncoding.EncodeToString(tcFullSigSet[int(in.RequireRound)%len(*ips)])}

			_, err = tc.BlankReplyMsgReceive(ctx, blankReplyMsg)
			if err != nil {
				fmt.Println("===>[!!!Collector]Failed to response:", err)
			} else {
				fmt.Println("BlankReplyMsg Send to", ip)
			}
		} else {
			//error message
		}
	}

	return &blankRequireMsgpb.BlankRequireMsgResponse{}, nil
}

// tcMsgReceive implements tcMsgpb.TcMsgReceive
func (ts *blankReplyMsgServer) BlankReplyMsgReceive(ctx context.Context, in *blankReplyMsgpb.BlankReplyMsg) (*blankReplyMsgpb.BlankReplyMsgResponse, error) {
	newTC := TC{
		MaskedMsg: in.MaskedMsg,
		HA:        in.HA,
		HB:        in.HB,
		HC:        in.HC,
	}

	marshaledTC, err := json.Marshal(newTC)
	if err != nil {
		panic(fmt.Errorf("===>[ERROR from TcMsgReceive]Marshal error : %s", err))
	}

	sig, _ := base64.StdEncoding.DecodeString(in.GetFullSig())

	err = bls.Verify(suite, pubPoly.Commit(), util.Digest(marshaledTC), sig)
	if err != nil {
		panic(fmt.Errorf("===>[ERROR from bls]Commit() failed:%s", err))
	} else {
		tcSet[int(in.RequireRound)%len(*ips)] = marshaledTC
		tcFullSigSet[int(in.RequireRound)%len(*ips)] = sig

		maskedMsg := new(big.Int)
		maskedMsg.SetString(in.GetMaskedMsg(), 10)
		hA := big.NewInt(0)
		hB := big.NewInt(0)
		hC := big.NewInt(0)
		hA.SetString(in.HA, 10)
		hB.SetString(in.HB, 10)
		hC.SetString(in.HC, 10)
		h, err := binaryquadraticform.NewBQuadraticForm(hA, hB, hC)
		fmt.Printf("===>[BlankReplyMsgReceive]The group element h is (a=%v,b=%v,c=%v,d=%v)\n", h.GetA(), h.GetB(), h.GetC(), h.GetDiscriminant())
		if err != nil {
			panic(fmt.Errorf("===>[ERROR from BlankReplyMsgReceive]Generate new BQuadratic Form failed: %s", err))
		}
		go SolveTC(int(in.RequireRound), maskedMsg, h)
		fmt.Println("[BlankReplyMsgReceive]Full Verify pass")
	}

	return &blankReplyMsgpb.BlankReplyMsgResponse{}, nil
}

func SendTCMsg(maskedMsg *big.Int, h, M_k, a1, a2 *binaryquadraticform.BQuadraticForm, z *big.Int) {
	for i, ip := range *ips {
		if i != int(*Id) {
			fmt.Printf("Send new TC to node %d\n", i)

			conn, err := grpc.Dial(ip, grpc.WithTransportCredentials(insecure.NewCredentials()))
			if err != nil {
				fmt.Println("===>[!!!Generator]did not connect:", err)
				continue
			}

			tc := tcMsgpb.NewTcMsgHandleClient(conn)
			ctx, _ := context.WithTimeout(context.Background(), time.Second)

			tcMsg := &tcMsgpb.TcMsg{Round: int64(round), MaskedMsg: maskedMsg.String(),
				HA: h.GetA().Int64(), HB: h.GetB().Int64(), HC: h.GetC().Int64(),
				MkA: M_k.GetA().Int64(), MkB: M_k.GetB().Int64(), MkC: M_k.GetC().Int64(),
				A1A: a1.GetA().Int64(), A1B: a1.GetB().Int64(), A1C: a1.GetC().Int64(),
				A2A: a2.GetA().Int64(), A2B: a2.GetB().Int64(), A2C: a2.GetC().Int64(),
				Z: z.String(), Id: *Id}

			marshaledtcMsg, err := json.Marshal(tcMsg)
			if err != nil {
				panic(fmt.Errorf("===>[ERROR from TcMsgReceive]Marshal error : %s", err))
			}
			sig, _ := bls.Sign(suite, PrivKey, marshaledtcMsg)
			tcMsg.Sig = base64.StdEncoding.EncodeToString(sig)

			_, err = tc.TcMsgReceive(ctx, tcMsg)
			if err != nil {
				fmt.Println("TcMsg Send to", ip)
				fmt.Println("===>[!!!Collector]Failed to response:", err)
				continue
			}
		}
	}
}

func SendPartSig(partSig []byte, round int64) {
	ip := (*ips)[int(round)%len(*ips)]
	conn, err := grpc.Dial(ip, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Println("===>[!!!Generator]did not connect:", err)
	}

	tc := tcPartSigMsgpb.NewTcPartSigMsgHandleClient(conn)
	ctx, _ := context.WithTimeout(context.Background(), time.Second)

	tcPartSigMsg := &tcPartSigMsgpb.TcPartSigMsg{Round: int64(round), Id: *Id, Sig: base64.StdEncoding.EncodeToString(partSig)}

	_, err = tc.TcPartSigMsgReceive(ctx, tcPartSigMsg)
	if err != nil {
		fmt.Println("===>[!!!Collector]Failed to response:", err)
	} else {
		fmt.Println("TcPartSigMsg Send to", ip)
	}
}

func SendFullSig(fullSig []byte, round int64) {
	for i, ip := range *ips {
		// if i != int(*Id) {
		if (i != int(*Id)) && (i != (int(*Id)+1)%len(*ips)) {
			conn, err := grpc.Dial(ip, grpc.WithTransportCredentials(insecure.NewCredentials()))
			if err != nil {
				fmt.Println("===>[!!!Generator]did not connect:", err)
			}

			tc := tcFullSigMsgpb.NewTcFullSigMsgHandleClient(conn)
			ctx, _ := context.WithTimeout(context.Background(), time.Second)

			tcFullSigMsg := &tcFullSigMsgpb.TcFullSigMsg{Round: int64(round), Id: *Id, Sig: base64.StdEncoding.EncodeToString(fullSig)}

			_, err = tc.TcFullSigMsgReceive(ctx, tcFullSigMsg)
			if err != nil {
				fmt.Println("===>[!!!Collector]Failed to response:", err)
			} else {
				fmt.Println("TcFullSigMsg Send to", ip)
			}
		}
	}
}

func FillBlank(currentRound int64) {
	if currentRound < int64(len(*ips)) {
		for i := 0; i < int(currentRound); i++ {
			if (tcFullSigSet[i] == nil) && (i != int(currentRound)%len(*ips)) {
				fmt.Println("[Require]", i)
				for j, ip := range *ips {
					if j != int(*Id) {
						conn, err := grpc.Dial(ip, grpc.WithTransportCredentials(insecure.NewCredentials()))
						if err != nil {
							fmt.Println("===>[!!!Generator]did not connect:", err)
						}

						tc := blankRequireMsgpb.NewBlankRequireMsgHandleClient(conn)
						ctx, _ := context.WithTimeout(context.Background(), time.Second)

						blankRequireMsg := &blankRequireMsgpb.BlankRequireMsg{RequireRound: int64(i), CurrentRound: currentRound, Id: *Id}
						marshaledblankRequireMsg, err := json.Marshal(blankRequireMsg)
						if err != nil {
							panic(fmt.Errorf("===>[ERROR from TcMsgReceive]Marshal error : %s", err))
						}
						sig, _ := bls.Sign(suite, PrivKey, marshaledblankRequireMsg)
						blankRequireMsg.Sig = base64.StdEncoding.EncodeToString(sig)

						_, err = tc.BlankRequireMsgReceive(ctx, blankRequireMsg)
						if err != nil {
							fmt.Println("===>[!!!Collector]Failed to response:", err)
						} else {
							fmt.Println("BlankRequireMsg Send to", ip)
						}
					}
				}
			}
		}
	} else {
		for i := 0; i < len(*ips); i++ {
			if (tcFullSigSet[i] == nil) && (i != int(currentRound)%len(*ips)) {
				fmt.Println("[Require]", currentRound-(currentRound%int64(len(*ips))-int64(i)))
				for j, ip := range *ips {
					if j != int(*Id) {
						conn, err := grpc.Dial(ip, grpc.WithTransportCredentials(insecure.NewCredentials()))
						if err != nil {
							fmt.Println("===>[!!!Generator]did not connect:", err)
						}

						tc := blankRequireMsgpb.NewBlankRequireMsgHandleClient(conn)
						ctx, _ := context.WithTimeout(context.Background(), time.Second)

						blankRequireMsg := &blankRequireMsgpb.BlankRequireMsg{RequireRound: currentRound - (currentRound%int64(len(*ips)) - int64(i)), CurrentRound: currentRound, Id: *Id}
						marshaledblankRequireMsg, err := json.Marshal(blankRequireMsg)
						if err != nil {
							panic(fmt.Errorf("===>[ERROR from TcMsgReceive]Marshal error : %s", err))
						}
						sig, _ := bls.Sign(suite, PrivKey, marshaledblankRequireMsg)
						blankRequireMsg.Sig = base64.StdEncoding.EncodeToString(sig)

						_, err = tc.BlankRequireMsgReceive(ctx, blankRequireMsg)
						if err != nil {
							fmt.Println("===>[!!!Collector]Failed to response:", err)
						} else {
							fmt.Println("BlankRequireMsg Send to", ip)
						}
					}
				}
			}
		}
	}
}

func SolveTC(round int, maskedMsg *big.Int, h *binaryquadraticform.BQuadraticForm) {
	resultSet[round%len(*ips)] = timedCommitment.ForcedOpen(int(*timeT), maskedMsg, h)
}

func main() {
	id := os.Args[1]
	idInt, _ := strconv.Atoi(id)
	address := "127.0.0.1:" + strconv.Itoa(30000+idInt)

	lis, err := net.Listen("tcp", address)
	if err != nil {
		panic(fmt.Errorf("===>[ERROR from Collector]Failed to listen: %s", err))
	}

	var n int
	var t int

	ps := grpc.NewServer()
	setupMsgpb.RegisterSetupMsgHandleServer(ps, &setupMsgServer{})
	groupMsgpb.RegisterGroupMsgHandleServer(ps, &groupMsgServer{})
	rMsgpb.RegisterRMsgHandleServer(ps, &rMsgServer{})
	tcMsgpb.RegisterTcMsgHandleServer(ps, &tcMsgServer{})
	tcPartSigMsgpb.RegisterTcPartSigMsgHandleServer(ps, &tcPartSigMsgServer{})
	tcFullSigMsgpb.RegisterTcFullSigMsgHandleServer(ps, &tcFullSigMsgServer{})
	blankRequireMsgpb.RegisterBlankRequireMsgHandleServer(ps, &blankRequireMsgServer{})
	blankReplyMsgpb.RegisterBlankReplyMsgHandleServer(ps, &blankReplyMsgServer{})
	go ps.Serve(lis)
	fmt.Printf("===>[Collector]Collector is listening at %v\n", lis.Addr())

	initTimer := time.NewTicker(1 * time.Second)
	startTimer := time.NewTicker(1 * time.Second)
	tcProposalTimer := time.NewTicker(1 * time.Second)
	sigProposalTimer := time.NewTicker(1 * time.Second)
	initTimer.Stop()
	startTimer.Stop()
	tcProposalTimer.Stop()
	sigProposalTimer.Stop()

	lastOutput := big.NewInt(0)
	init := true
	for {
		if p.GetA() == nil {
			continue
		} else {
			if init {
				fmt.Println("Last output is:", lastOutput)
				fmt.Println("len of nodes is ", len(*ips), len(*pubKeys))
				n = len(*ips)
				t = n/2 + 1
				init = false

				if round%n == idInt {
					maskedMsg, h, M_k, a1, a2, z := timedCommitment.GenerateTC(g, m_k, r_k, p, int(*timeT))
					go SolveTC(round, maskedMsg, h)
					fmt.Println(timedCommitment.VerifyTC(int(*timeT), maskedMsg, g, m_k, r_k, p, h, M_k, a1, a2, z))

					newTC := TC{
						MaskedMsg: maskedMsg.String(),
						HA:        h.GetA().String(),
						HB:        h.GetB().String(),
						HC:        h.GetC().String(),
					}

					marshaledTC, err := json.Marshal(newTC)
					if err != nil {
						panic(fmt.Errorf("===>[ERROR from TcMsgReceive]Marshal error : %s", err))
					}
					tcSet[idInt] = marshaledTC

					SendTCMsg(maskedMsg, h, M_k, a1, a2, z)
				}
				initTimer.Reset(1 * time.Second)
			}

			select {
			case <-startTimer.C:
				startTimer.Stop()
				if round%n == idInt {
					go FillBlank(int64(round))
					maskedMsg, h, M_k, a1, a2, z := timedCommitment.GenerateTC(g, m_k, r_k, p, int(*timeT))
					go SolveTC(round, maskedMsg, h)
					fmt.Println(timedCommitment.VerifyTC(int(*timeT), maskedMsg, g, m_k, r_k, p, h, M_k, a1, a2, z))

					newTC := TC{
						MaskedMsg: maskedMsg.String(),
						HA:        h.GetA().String(),
						HB:        h.GetB().String(),
						HC:        h.GetC().String(),
					}

					marshaledTC, err := json.Marshal(newTC)
					if err != nil {
						panic(fmt.Errorf("===>[ERROR from TcMsgReceive]Marshal error : %s", err))
					}
					tcSet[idInt] = marshaledTC

					SendTCMsg(maskedMsg, h, M_k, a1, a2, z)
				}
				initTimer.Reset(1 * time.Second)

			case <-initTimer.C:
				initTimer.Stop()
				if round%n != idInt {
					partSig, err := tbls.Sign(suite, SecretShare, util.Digest(tcSet[round%len(*ips)]))
					if err != nil {
						panic(fmt.Errorf("===>[ERROR from tbls]Sign() failed:%s", err))
					}

					SendPartSig(partSig, int64(round))
					sigProposalTimer.Reset(2 * time.Second)
					// solve tc
				} else {
					partSig, err := tbls.Sign(suite, SecretShare, util.Digest(tcSet[idInt]))
					if err != nil {
						panic(fmt.Errorf("===>[ERROR from tbls]Sign() failed:%s", err))
					}

					tcPartSigSet = append(tcPartSigSet, partSig)
					tcProposalTimer.Reset(1 * time.Second)
				}

			case <-tcProposalTimer.C:
				tcProposalTimer.Stop()
				if round%n == idInt {
					sig, err := tbls.Recover(suite, pubPoly, util.Digest(tcSet[round%len(*ips)]), tcPartSigSet, t, n)
					if err != nil {
						panic(fmt.Errorf("===>[ERROR from tbls]Recover() failed:%s", err))
					}

					err = bls.Verify(suite, pubPoly.Commit(), util.Digest(tcSet[round%len(*ips)]), sig)
					if err != nil {
						panic(fmt.Errorf("===>[ERROR from tbls]Commit() failed:%s", err))
					} else {
						fmt.Println("Recover then Verify pass")
						tcFullSigSet[idInt] = sig
						SendFullSig(sig, int64(round))
						sigProposalTimer.Reset(1 * time.Second)
					}
				}

			case <-sigProposalTimer.C:
				sigProposalTimer.Stop()
				fmt.Println("R0 is", R0)
				fmt.Println(resultSet[round%n])
				fmt.Printf("#####################Round %v Over#####################\n", round)

				tcPartSigSet = make([][]byte, 0)

				round++
				if round >= n {
					tcSet[round%n] = nil
					resultSet[round%n] = nil
					tcFullSigSet[round%n] = nil
				}
				startTimer.Reset(1 * time.Second)
			}
		}
	}
}
