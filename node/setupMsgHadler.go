package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"math/big"
	"node/crypto/binaryquadraticform"
	"node/msg/errSetupMsgpb"
	"node/msg/groupMsgpb"
	"node/msg/rMsgpb"
	"node/msg/tcSetupMsgpb"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/share"
)

// tcSetupMsgServer is used to implement tcSetupMsgpb.TcSetupMsgReceive.
type tcSetupMsgServer struct {
	tcSetupMsgpb.UnimplementedTcSetupMsgHandleServer
}

// errSetupMsgServer is used to implement errSetupMsgpb.ErrSetupMsgReceive.
type errSetupMsgServer struct {
	errSetupMsgpb.UnimplementedErrSetupMsgHandleServer
}

// rMsgServer is used to implement rMsgpb.RMsgReceive.
type rMsgServer struct {
	rMsgpb.UnimplementedRMsgHandleServer
}

// groupMsgServer is used to implement groupMsgpb.GroupMsgReceive.
type groupMsgServer struct {
	groupMsgpb.UnimplementedGroupMsgHandleServer
}

// tcSetupMsgReceive implements tcSetupMsgpb.TcSetupMsgReceive.
// initialize the BLS signature scheme, the tBLS signature scheme, local configurations and peer public configurations.
func (sms *tcSetupMsgServer) TcSetupMsgReceive(ctx context.Context, in *tcSetupMsgpb.TcSetupMsg) (*tcSetupMsgpb.TcSetupMsgResponse, error) {
	// initialize local configurations
	*Id, *Ip = in.GetId(), in.GetIp()
	fmt.Printf("[Setup] Node %d is ready, IP address is %s\n", *Id, *Ip)

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
	_, err := PubKey.UnmarshalFrom(localPubKeyBuf)
	if err != nil {
		panic(fmt.Errorf("[!!!Error TcSetupMsgReceive] Local PubKey Unmarshal:%v", err))
	}

	localPrivKeyBuf := new(bytes.Buffer)
	localPrivKeyBuf.Write(localPrivKeybytes)
	_, err = PrivKey.UnmarshalFrom(localPrivKeyBuf)
	if err != nil {
		panic(fmt.Errorf("[!!!Error TcSetupMsgReceive] Local PrivKey Unmarshal:%v", err))
	}

	secretShareVBuf := new(bytes.Buffer)
	secretShareVBuf.Write(secretShareVbytes)
	_, err = SecretShareV.UnmarshalFrom(secretShareVBuf)
	if err != nil {
		panic(fmt.Errorf("[!!!Error TcSetupMsgReceive] Local SecretShareV Unmarshal:%v", err))
	}

	SecretShare.I = int(secretShareI)
	SecretShare.V = SecretShareV
	fmt.Printf("[Setup] Info of Node %d: local public key is %v\n", *Id, PubKey)
	fmt.Printf("[Setup] Info of Node %d: local private key is %v\n", *Id, PrivKey)
	fmt.Printf("[Setup] Info of Node %d: local secret share is %v\n", *Id, SecretShare)

	// initialize global public configurations
	globalPubKey := in.GetGlobalPubKey()
	globalPubKeybytes, _ := base64.StdEncoding.DecodeString(globalPubKey)
	globalPubKeyBuf := new(bytes.Buffer)
	globalPubKeyBuf.Write(globalPubKeybytes)
	_, err = GlobalPubKey.UnmarshalFrom(globalPubKeyBuf)
	if err != nil {
		panic(fmt.Errorf("[!!!Error TcSetupMsgReceive] Global PubKey Unmarshal:%v", err))
	}
	fmt.Printf("[Setup] Info of Node %d: global public key is %v\n", *Id, GlobalPubKey)

	pubPolyBase := suite.G2().Point()
	pubPolyBasebytes, _ := base64.StdEncoding.DecodeString(in.GetPubPolyBase())
	pubPolyBaseBuf := new(bytes.Buffer)
	pubPolyBaseBuf.Write(pubPolyBasebytes)
	_, err = pubPolyBase.UnmarshalFrom(pubPolyBaseBuf)
	if err != nil {
		panic(fmt.Errorf("[!!!Error TcSetupMsgReceive] pubPolyBase Unmarshal:%v", err))
	}

	var PubPolyCommits []kyber.Point
	pubPolyCommits := in.GetPubPolyCommit()
	for _, pubPolyCommit := range pubPolyCommits {
		PubPolyCommit := suite.G2().Point()
		PubPolyCommitbytes, _ := base64.StdEncoding.DecodeString(pubPolyCommit)
		PubPolyCommitBuf := new(bytes.Buffer)
		PubPolyCommitBuf.Write(PubPolyCommitbytes)
		_, err = PubPolyCommit.UnmarshalFrom(PubPolyCommitBuf)
		if err != nil {
			panic(fmt.Errorf("[!!!Error TcSetupMsgReceive] PubPolyCommit Unmarshal:%v", err))
		} else {
			PubPolyCommits = append(PubPolyCommits, PubPolyCommit)
		}
	}

	pubPoly = share.NewPubPoly(suite.G2(), pubPolyBase, PubPolyCommits)
	fmt.Printf("[Setup] Info of Node %d: pubPoly is %v\n", *Id, pubPoly.Commit())

	// initialize peer public configurations
	*ips = in.GetIps()
	peerPubKeys := in.GetPubKeys()
	for _, pk := range peerPubKeys {
		pkPoint := suite.G2().Point()
		pkbytes, _ := base64.StdEncoding.DecodeString(pk)

		pkBuf := new(bytes.Buffer)
		pkBuf.Write(pkbytes)
		_, err = pkPoint.UnmarshalFrom(pkBuf)
		if err != nil {
			panic(fmt.Errorf("[!!!Error TcSetupMsgReceive] peer PubKeys Unmarshal:%v", err))
		}

		*pubKeys = append(*pubKeys, pkPoint)
	}
	fmt.Printf("[Setup] Info of Node %d: peer ips are %v\n", *Id, ips)
	fmt.Printf("[Setup] Info of Node %d: peer pks are %v\n", *Id, pubKeys)

	return &tcSetupMsgpb.TcSetupMsgResponse{}, nil
}

// errSetupMsgReceive implements errSetupMsgpb.ErrSetupMsgReceive.
// initialize the BLS signature scheme, the tBLS signature scheme, local configurations and peer public configurations.
func (sms *errSetupMsgServer) ErrSetupMsgReceive(ctx context.Context, in *errSetupMsgpb.ErrSetupMsg) (*errSetupMsgpb.ErrSetupMsgResponse, error) {
	// initialize local configurations
	fmt.Printf("[Setup] Node %d error thresdold is ready\n", in.GetId())

	SecretShareV := suite.G1().Scalar()
	secretShareI := in.GetSecretShareI()
	secretShareV := in.GetSecretShareV()
	secretShareVbytes, _ := base64.StdEncoding.DecodeString(secretShareV)

	secretShareVBuf := new(bytes.Buffer)
	secretShareVBuf.Write(secretShareVbytes)
	_, err := SecretShareV.UnmarshalFrom(secretShareVBuf)
	if err != nil {
		panic(fmt.Errorf("[!!!Error ErrSetupMsgReceive] Local SecretShareV Unmarshal:%v", err))
	}

	ErrSecretShare.I = int(secretShareI)
	ErrSecretShare.V = SecretShareV
	fmt.Printf("[Setup] Info of Node %d: local error secret share is %v\n", *Id, ErrSecretShare)

	// initialize global public configurations
	globalPubKey := in.GetGlobalPubKey()
	globalPubKeybytes, _ := base64.StdEncoding.DecodeString(globalPubKey)
	globalPubKeyBuf := new(bytes.Buffer)
	globalPubKeyBuf.Write(globalPubKeybytes)
	_, err = ErrGlobalPubKey.UnmarshalFrom(globalPubKeyBuf)
	if err != nil {
		panic(fmt.Errorf("[!!!Error ErrSetupMsgReceive] Global PubKey Unmarshal:%v", err))
	}
	fmt.Printf("[Setup] Info of Node %d: error global public key is %v\n", *Id, ErrGlobalPubKey)

	pubPolyBase := suite.G2().Point()
	pubPolyBasebytes, _ := base64.StdEncoding.DecodeString(in.GetPubPolyBase())
	pubPolyBaseBuf := new(bytes.Buffer)
	pubPolyBaseBuf.Write(pubPolyBasebytes)
	_, err = pubPolyBase.UnmarshalFrom(pubPolyBaseBuf)
	if err != nil {
		panic(fmt.Errorf("[!!!Error ErrSetupMsgReceive] pubPolyBase Unmarshal:%v", err))
	}

	var PubPolyCommits []kyber.Point
	pubPolyCommits := in.GetPubPolyCommit()
	for _, pubPolyCommit := range pubPolyCommits {
		PubPolyCommit := suite.G2().Point()
		PubPolyCommitbytes, _ := base64.StdEncoding.DecodeString(pubPolyCommit)
		PubPolyCommitBuf := new(bytes.Buffer)
		PubPolyCommitBuf.Write(PubPolyCommitbytes)
		_, err = PubPolyCommit.UnmarshalFrom(PubPolyCommitBuf)
		if err != nil {
			panic(fmt.Errorf("[!!!Error ErrSetupMsgReceive] PubPolyCommit Unmarshal:%v", err))
		} else {
			PubPolyCommits = append(PubPolyCommits, PubPolyCommit)
		}
	}

	ErrpubPoly = share.NewPubPoly(suite.G2(), pubPolyBase, PubPolyCommits)
	fmt.Printf("[Setup] Info of Node %d: error pubPoly is %v\n", *Id, ErrpubPoly.Commit())

	return &errSetupMsgpb.ErrSetupMsgResponse{}, nil
}

// rMsgReceive implements rMsgpb.RMsgReceive
// initialize the initial value of the randomness beacon.
func (rms *rMsgServer) RMsgReceive(ctx context.Context, in *rMsgpb.RMsg) (*rMsgpb.RMsgResponse, error) {
	r0 := in.GetR0()
	R0.SetString(r0, 10)
	fmt.Printf("[Setup] Info of Node %d: Initial value R0 is %v\n", *Id, R0)

	return &rMsgpb.RMsgResponse{}, nil
}

// groupMsgReceive implements groupMsgpb.GroupMsgReceive
// initialize the class group configurations
func (gms *groupMsgServer) GroupMsgReceive(ctx context.Context, in *groupMsgpb.GroupMsg) (*groupMsgpb.GroupMsgResponse, error) {
	var err error

	// get the time parameter T
	*timeT = in.GetTimeT()
	fmt.Printf("[Setup] Time Parameter is t=%v\n", *timeT)

	// get the components of g, m_k, r_k, p
	groupA, groupB, groupC := in.GetGroupA(), in.GetGroupB(), in.GetGroupC()
	mkA, mkB, mkC, rkA, rkB, rkC := in.GetMkA(), in.GetMkB(), in.GetMkC(), in.GetRkA(), in.GetRkB(), in.GetRkC()
	pA, pB, pC := in.GetPA(), in.GetPB(), in.GetPC()

	groupAInt, _ := big.NewInt(0).SetString(groupA, 10)
	groupBInt, _ := big.NewInt(0).SetString(groupB, 10)
	groupCInt, _ := big.NewInt(0).SetString(groupC, 10)
	mkAInt, _ := big.NewInt(0).SetString(mkA, 10)
	mkBInt, _ := big.NewInt(0).SetString(mkB, 10)
	mkCInt, _ := big.NewInt(0).SetString(mkC, 10)
	rkAInt, _ := big.NewInt(0).SetString(rkA, 10)
	rkBInt, _ := big.NewInt(0).SetString(rkB, 10)
	rkCInt, _ := big.NewInt(0).SetString(rkC, 10)
	pAInt, _ := big.NewInt(0).SetString(pA, 10)
	pBInt, _ := big.NewInt(0).SetString(pB, 10)
	pCInt, _ := big.NewInt(0).SetString(pC, 10)

	// recover the g, m_k, r_k, p
	g, err = binaryquadraticform.NewBQuadraticForm(groupAInt, groupBInt, groupCInt)
	fmt.Printf("[Setup] The group element g is (a=%v,b=%v,c=%v,d=%v)\n", g.GetA(), g.GetB(), g.GetC(), g.GetDiscriminant())
	if err != nil {
		panic(fmt.Errorf("[!!!Error GroupMsgReceive] Generate new BQuadratic Form g failed: %s", err))
	}
	m_k, err = binaryquadraticform.NewBQuadraticForm(mkAInt, mkBInt, mkCInt)
	fmt.Printf("[Setup] Mk is (a=%v,b=%v,c=%v,d=%v)\n", m_k.GetA(), m_k.GetB(), m_k.GetC(), m_k.GetDiscriminant())
	if err != nil {
		panic(fmt.Errorf("[!!!Error GroupMsgReceive] Generate new BQuadratic Form Mk failed: %s", err))
	}
	r_k, err = binaryquadraticform.NewBQuadraticForm(rkAInt, rkBInt, rkCInt)
	fmt.Printf("[Setup] Rk is (a=%v,b=%v,c=%v,d=%v)\n", r_k.GetA(), r_k.GetB(), r_k.GetC(), r_k.GetDiscriminant())
	if err != nil {
		panic(fmt.Errorf("[!!!Error GroupMsgReceive] Generate new BQuadratic Form Rk failed: %s", err))
	}
	p, err = binaryquadraticform.NewBQuadraticForm(pAInt, pBInt, pCInt)
	fmt.Printf("[Setup] Proof is (a=%v,b=%v,c=%v,d=%v)\n", p.GetA(), p.GetB(), p.GetC(), p.GetDiscriminant())
	if err != nil {
		panic(fmt.Errorf("[!!!Error GroupMsgReceive] Generate new BQuadratic Form Proof failed: %s", err))
	}

	/* A test for crypto part */
	// binaryquadraticform.TestInit()
	// binaryquadraticform.TestExp()
	// maskedMsg, h, M_k, a1, a2, z := timedCommitment.GenerateTC(g, m_k, r_k, p, int(*timeT))
	// fmt.Println(timedCommitment.VerifyTC(int(*timeT), maskedMsg, g, m_k, r_k, p, h, M_k, a1, a2, z))
	// timedCommitment.ForcedOpen(int(*timeT), maskedMsg, h)

	return &groupMsgpb.GroupMsgResponse{}, nil
}
