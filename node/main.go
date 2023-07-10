package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"math/big"
	"net"
	"node/crypto/binaryquadraticform"
	"node/crypto/timedCommitment"
	"node/msg/groupMsgpb"
	"node/msg/setupMsgpb"
	"os"
	"strconv"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/share"
	"google.golang.org/grpc"
)

// setupMsgServer is used to implement setupMsgpb.SetupMsgReceive
type setupMsgServer struct {
	setupMsgpb.UnimplementedSetupMsgHandleServer
}

// groupMsgServer is used to implement groupMsgpb.GroupMsgReceive
type groupMsgServer struct {
	groupMsgpb.UnimplementedGroupMsgHandleServer
}

var suite = bn256.NewSuite()

// setupMsgReceive implements setupMsgpb.SetupMsgReceive
func (hs *setupMsgServer) SetupMsgReceive(ctx context.Context, in *setupMsgpb.SetupMsg) (*setupMsgpb.SetupMsgResponse, error) {
	id, ip := in.GetId(), in.GetIp()
	fmt.Printf("[Setup]Node %d is ready, IP address is %s\n", id, ip)

	localPubKey := in.GetLocalPubKey()
	localPrivKey := in.GetLocalPrivKey()
	secretShareI := in.GetSecretShareI()
	secretShareV := in.GetSecretShareV()
	localPubKeybytes, _ := base64.StdEncoding.DecodeString(localPubKey)
	localPrivKeybytes, _ := base64.StdEncoding.DecodeString(localPrivKey)
	secretShareVbytes, _ := base64.StdEncoding.DecodeString(secretShareV)

	PubKey := suite.G2().Point()
	PrivKey := suite.G1().Scalar()
	SecretShareV := suite.G1().Scalar()

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

	SecretShare := new(share.PriShare)
	SecretShare.I = int(secretShareI)
	SecretShare.V = SecretShareV
	fmt.Printf("[Setup]Info of Node %d: local public key is %v\n", id, PubKey)
	fmt.Printf("[Setup]Info of Node %d: local private key is %v\n", id, PrivKey)
	fmt.Printf("[Setup]Info of Node %d: local secret share is %v\n", id, SecretShare)

	globalPubKey := in.GetGlobalPubKey()
	GlobalPubKey := suite.G2().Point()

	globalPubKeybytes, _ := base64.StdEncoding.DecodeString(globalPubKey)
	globalPubKeyBuf := new(bytes.Buffer)
	globalPubKeyBuf.Write(globalPubKeybytes)
	len, err = GlobalPubKey.UnmarshalFrom(globalPubKeyBuf)
	if err != nil {
		fmt.Println("===>[!!!Node]globalPubKey UnmarshalFrom:", err)
	} else {
		fmt.Println("globalPubKey Length is:", len)
	}
	fmt.Printf("[Setup]Info of Node %d: global public key is %v\n", id, GlobalPubKey)

	ips := in.GetIps()
	peerPubKeys := in.GetPubKeys()
	var pubKeys []kyber.Point
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

		pubKeys = append(pubKeys, pkPoint)
	}
	fmt.Printf("[Setup]Info of Node %d: peer ips are %v\n", id, ips)
	fmt.Printf("[Setup]Info of Node %d: peer pks are %v\n", id, pubKeys)

	return &setupMsgpb.SetupMsgResponse{}, nil
}

// groupMsgReceive implements groupMsgpb.GroupMsgReceive
func (hs *groupMsgServer) GroupMsgReceive(ctx context.Context, in *groupMsgpb.GroupMsg) (*groupMsgpb.GroupMsgResponse, error) {
	groupA, groupB, groupC := in.GetGroupA(), in.GetGroupB(), in.GetGroupC()
	timeT := in.GetTimeT()
	mkA, mkB, mkC, rkA, rkB, rkC := in.GetMkA(), in.GetMkB(), in.GetMkC(), in.GetRkA(), in.GetRkB(), in.GetRkC()
	pA, pB, pC := in.GetPA(), in.GetPB(), in.GetPC()

	g, err := binaryquadraticform.NewBQuadraticForm(big.NewInt(int64(groupA)), big.NewInt(int64(groupB)), big.NewInt(int64(groupC)))
	fmt.Printf("===>[InitConfig]The group element g is (a=%v,b=%v,c=%v,d=%v)\n", g.GetA(), g.GetB(), g.GetC(), g.GetDiscriminant())
	if err != nil {
		panic(fmt.Errorf("===>[ERROR from InitConfig]Generate new BQuadratic Form failed: %s", err))
	}
	m_k, err := binaryquadraticform.NewBQuadraticForm(big.NewInt(int64(mkA)), big.NewInt(int64(mkB)), big.NewInt(int64(mkC)))
	fmt.Printf("===>[InitConfig] Mk is (a=%v,b=%v,c=%v,d=%v)\n", m_k.GetA(), m_k.GetB(), m_k.GetC(), m_k.GetDiscriminant())
	if err != nil {
		panic(fmt.Errorf("===>[ERROR from InitConfig]Generate new BQuadratic Form failed: %s", err))
	}
	r_k, err := binaryquadraticform.NewBQuadraticForm(big.NewInt(int64(rkA)), big.NewInt(int64(rkB)), big.NewInt(int64(rkC)))
	fmt.Printf("===>[InitConfig] Rk is (a=%v,b=%v,c=%v,d=%v)\n", r_k.GetA(), r_k.GetB(), r_k.GetC(), r_k.GetDiscriminant())
	if err != nil {
		panic(fmt.Errorf("===>[ERROR from InitConfig]Generate new BQuadratic Form failed: %s", err))
	}
	p, err := binaryquadraticform.NewBQuadraticForm(big.NewInt(int64(pA)), big.NewInt(int64(pB)), big.NewInt(int64(pC)))
	fmt.Printf("===>[InitConfig] Proof is (a=%v,b=%v,c=%v,d=%v)\n", p.GetA(), p.GetB(), p.GetC(), p.GetDiscriminant())
	if err != nil {
		panic(fmt.Errorf("===>[ERROR from InitConfig]Generate new BQuadratic Form failed: %s", err))
	}
	fmt.Printf("===>[InitConfig] Time Parameter is t=%v\n", timeT)

	// Test for crypto part
	binaryquadraticform.TestInit()
	binaryquadraticform.TestExp()
	maskedMsg, h, M_k, a1, a2, z := timedCommitment.GenerateTC(g, m_k, r_k, p, int(timeT))
	fmt.Println(timedCommitment.VerifyTC(int(timeT), maskedMsg, g, m_k, r_k, p, h, M_k, a1, a2, z))
	timedCommitment.ForcedOpen(int(timeT), maskedMsg, h)

	return &groupMsgpb.GroupMsgResponse{}, nil
}

func main() {
	id := os.Args[1]
	idInt, _ := strconv.Atoi(id)
	address := "127.0.0.1:" + strconv.Itoa(30000+idInt)

	lis, err := net.Listen("tcp", address)
	if err != nil {
		panic(fmt.Errorf("===>[ERROR from Collector]Failed to listen: %s", err))
	}

	ps := grpc.NewServer()
	setupMsgpb.RegisterSetupMsgHandleServer(ps, &setupMsgServer{})
	groupMsgpb.RegisterGroupMsgHandleServer(ps, &groupMsgServer{})
	go ps.Serve(lis)
	fmt.Printf("===>[Collector]Collector is listening at %v\n", lis.Addr())

	for {

	}
}
