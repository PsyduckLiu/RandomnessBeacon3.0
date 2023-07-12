package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"node/crypto/binaryquadraticform"
	"node/crypto/timedCommitment"
	"node/msg/tcCompleteSigMsgpb"
	"node/msg/tcMsgpb"
	"node/msg/tcPartSigMsgpb"
	"node/util"
	"time"

	"go.dedis.ch/kyber/v3/sign/bls"
	"go.dedis.ch/kyber/v3/sign/tbls"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// tcMsgServer is used to implement tcMsgpb.TcMsgReceive
type tcMsgServer struct {
	tcMsgpb.UnimplementedTcMsgHandleServer
}

// tcPartSigMsgServer is used to implement tcPartSigMsgpb.TcPartSigMsgReceive
type tcPartSigMsgServer struct {
	tcPartSigMsgpb.UnimplementedTcPartSigMsgHandleServer
}

// tcCompleteSigMsgServer is used to implement tcCompleteSigMsgpb.TcCompleteSigMsgReceive
type tcCompleteSigMsgServer struct {
	tcCompleteSigMsgpb.UnimplementedTcCompleteSigMsgHandleServer
}

// tcMsgReceive implements tcMsgpb.TcMsgReceive
// Nodes handle the timed commitment received from the leader
func (tms *tcMsgServer) TcMsgReceive(ctx context.Context, in *tcMsgpb.TcMsg) (*tcMsgpb.TcMsgResponse, error) {
	// verify the signature of the message
	rawtcMsg := &tcMsgpb.TcMsg{Round: in.Round, MaskedMsg: in.MaskedMsg,
		HA: in.HA, HB: in.HB, HC: in.HC,
		MkA: in.MkA, MkB: in.MkB, MkC: in.MkC,
		A1A: in.A1A, A1B: in.A1B, A1C: in.A1C,
		A2A: in.A2A, A2B: in.A2B, A2C: in.A2C,
		Z: in.Z, Id: in.Id}
	marshaledrawtcMsg, err := json.Marshal(rawtcMsg)
	if err != nil {
		fmt.Printf("[!!!Error TcMsgReceive] Marshal error: %s", err)
		return &tcMsgpb.TcMsgResponse{}, nil
	}

	sig, err := base64.StdEncoding.DecodeString(in.GetSig())
	if err != nil {
		fmt.Printf("[!!!Error TcMsgReceive] DecodeString error: %s", err)
		return &tcMsgpb.TcMsgResponse{}, nil
	}

	err = bls.Verify(suite, (*pubKeys)[in.GetId()], marshaledrawtcMsg, sig)
	if err != nil {
		fmt.Printf("[!!!Error TcMsgReceive] Signature Verify() failed:%s", err)
		return &tcMsgpb.TcMsgResponse{}, nil
	} else {
		fmt.Println("[TcMsgReceive] Signature Verify pass")
	}

	// verify the validity of the timed commitment
	maskedMsg := new(big.Int)
	maskedMsg.SetString(in.GetMaskedMsg(), 10)

	z := new(big.Int)
	z.SetString(in.GetZ(), 10)

	h, err := binaryquadraticform.NewBQuadraticForm(big.NewInt(in.GetHA()), big.NewInt(in.GetHB()), big.NewInt(in.GetHC()))
	fmt.Printf("[TcMsgReceive] The group element h is (a=%v,b=%v,c=%v,d=%v)\n", h.GetA(), h.GetB(), h.GetC(), h.GetDiscriminant())
	if err != nil {
		fmt.Printf("===>[!!!Error TcMsgReceive] Generate new BQuadratic Form h failed: %s", err)
		return &tcMsgpb.TcMsgResponse{}, nil
	}
	M_k, err := binaryquadraticform.NewBQuadraticForm(big.NewInt(in.GetMkA()), big.NewInt(in.GetMkB()), big.NewInt(in.GetMkC()))
	fmt.Printf("[TcMsgReceive] The group element M_K is (a=%v,b=%v,c=%v,d=%v)\n", M_k.GetA(), M_k.GetB(), M_k.GetC(), M_k.GetDiscriminant())
	if err != nil {
		fmt.Printf("===>[!!!Error TcMsgReceive] Generate new BQuadratic Form M_K failed: %s", err)
		return &tcMsgpb.TcMsgResponse{}, nil
	}
	a1, err := binaryquadraticform.NewBQuadraticForm(big.NewInt(in.GetA1A()), big.NewInt(in.GetA1B()), big.NewInt(in.GetA1C()))
	fmt.Printf("[TcMsgReceive] The group element a1 is (a=%v,b=%v,c=%v,d=%v)\n", a1.GetA(), a1.GetB(), a1.GetC(), a1.GetDiscriminant())
	if err != nil {
		fmt.Printf("===>[!!!Error TcMsgReceive] Generate new BQuadratic Form a1 failed: %s", err)
		return &tcMsgpb.TcMsgResponse{}, nil
	}
	a2, err := binaryquadraticform.NewBQuadraticForm(big.NewInt(in.GetA2A()), big.NewInt(in.GetA2B()), big.NewInt(in.GetA2C()))
	fmt.Printf("[TcMsgReceive] The group element a2 is (a=%v,b=%v,c=%v,d=%v)\n", a2.GetA(), a2.GetB(), a2.GetC(), a2.GetDiscriminant())
	if err != nil {
		fmt.Printf("===>[!!!Error TcMsgReceive] Generate new BQuadratic Form a2 failed: %s", err)
		return &tcMsgpb.TcMsgResponse{}, nil
	}

	result := timedCommitment.VerifyTC(int(*timeT), maskedMsg, g, m_k, r_k, p, h, M_k, a1, a2, z)
	if result {
		fmt.Printf("[TcMsgReceive] new TC from node %v pass!!!\n", in.Id)
		go SolveTC(int(in.Round), maskedMsg, h)

		newTC := TC{
			MaskedMsg: maskedMsg.String(),
			HA:        h.GetA().String(),
			HB:        h.GetB().String(),
			HC:        h.GetC().String(),
		}

		marshaledTC, err := json.Marshal(newTC)
		if err != nil {
			fmt.Printf("===>[!!!Error TcMsgReceive] Marshal error : %s", err)
			return &tcMsgpb.TcMsgResponse{}, nil
		} else {
			tcSet[int(in.Id)] = marshaledTC
			fmt.Printf("[TcMsgReceive] Add new TC from node %v for Round %v to [tcSet]\n", in.Id, in.Round)
		}
	}

	return &tcMsgpb.TcMsgResponse{}, nil
}

// tcPartSigMsgReceive implements tcPartSigMsgpb.TcPartSigMsgReceive
// Leader handles the partial signatures for the timed commitment from all other nodes
func (tpsms *tcPartSigMsgServer) TcPartSigMsgReceive(ctx context.Context, in *tcPartSigMsgpb.TcPartSigMsg) (*tcPartSigMsgpb.TcPartSigMsgResponse, error) {
	sig, err := base64.StdEncoding.DecodeString(in.GetSig())
	if err != nil {
		fmt.Printf("[!!!Error TcPartSigMsgReceive] DecodeString error: %s", err)
		return &tcPartSigMsgpb.TcPartSigMsgResponse{}, nil
	}

	err = tbls.Verify(suite, pubPoly, util.Digest(tcSet[int(in.Round)%n]), sig)
	if err != nil {
		fmt.Printf("[!!!Error TcPartSigMsgReceive] Signature Verify failed: %s", err)
		return &tcPartSigMsgpb.TcPartSigMsgResponse{}, nil
	} else {
		tcPartSigSet = append(tcPartSigSet, sig)
		fmt.Println("[TcPartSigMsgReceive] Partial Verify pass")
		fmt.Printf("[TcPartSigMsgReceive] Add new tcPartSig from node %v for Round %v to [tcPartSigSet]\n", in.Id, in.Round)
	}

	return &tcPartSigMsgpb.TcPartSigMsgResponse{}, nil
}

// tcCompleteSigMsgReceive implements tcCompleteSigMsgpb.TcCompleteSigMsgReceive
// Nodes handle the complete signatures for the timed commitment from the leader
func (tfsms *tcCompleteSigMsgServer) TcCompleteSigMsgReceive(ctx context.Context, in *tcCompleteSigMsgpb.TcCompleteSigMsg) (*tcCompleteSigMsgpb.TcCompleteSigMsgResponse, error) {
	sig, err := base64.StdEncoding.DecodeString(in.GetSig())
	if err != nil {
		fmt.Printf("[!!!Error TcCompleteSigMsgReceive] DecodeString error: %s", err)
		return &tcCompleteSigMsgpb.TcCompleteSigMsgResponse{}, nil
	}

	err = bls.Verify(suite, pubPoly.Commit(), util.Digest(tcSet[int(in.Round)%n]), sig)
	if err != nil {
		fmt.Printf("[!!!Error TcCompleteSigMsgReceive] Commit() failed:%s", err)
		return &tcCompleteSigMsgpb.TcCompleteSigMsgResponse{}, nil
	} else {
		if tcCompleteSigSet[int(in.Round)%n] == nil {
			tcCompleteSigSet[int(in.Round)%n] = sig
			fmt.Println("[TcCompleteSigMsgReceive] Complete Verify pass")
			fmt.Printf("[TcCompleteSigMsgReceive] Add new tcCompleteSig from node %v for Round %v to [tcCompleteSigSet]\n", in.Id, in.Round)
		}
	}

	return &tcCompleteSigMsgpb.TcCompleteSigMsgResponse{}, nil
}

// Leader sends a new timed commitment to all other nodes
// Only used in the normalMsgHandler
func SendTCMsg(maskedMsg *big.Int, h, M_k, a1, a2 *binaryquadraticform.BQuadraticForm, z *big.Int) {
	if (maskedMsg != nil) && (h != nil) && (M_k != nil) && (a1 != nil) && (a2 != nil) && (z != nil) {
		for i, ip := range *ips {
			if i != int(*Id) {
				fmt.Printf("[SendTCMsg] Start to send a new TC to node %d\n", i)

				conn, err := grpc.Dial(ip, grpc.WithTransportCredentials(insecure.NewCredentials()))
				if err != nil {
					fmt.Println("[!!!Error SendTCMsg] Did not connect:", err)
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
					fmt.Printf("[!!!Error SendTCMsg] Marshal error: %s\n", err)
					continue
				}

				sig, err := bls.Sign(suite, PrivKey, marshaledtcMsg)
				if err != nil {
					fmt.Printf("[!!!Error SendTCMsg] Sign error: %s\n", err)
					continue
				}

				tcMsg.Sig = base64.StdEncoding.EncodeToString(sig)

				_, err = tc.TcMsgReceive(ctx, tcMsg)
				if err != nil {
					fmt.Println("[!!!Error SendTCMsg] Failed to send:", err)
					continue
				}

				fmt.Printf("[SendTCMsg] Successfully send a new TC to node %d\n", i)
			}
		}
	}
}

// Nodes send the partial signature for the timed commitment to the leader after receiving a valid timed commitment
// Only used in the normalMsgHandler
func SendPartSig(partSig []byte) {
	if partSig != nil {
		fmt.Printf("[SendPartSig] Start to send a new partSig to node %d\n", int(round)%n)

		ip := (*ips)[int(round)%n]
		conn, err := grpc.Dial(ip, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			fmt.Println("[!!!Error SendPartSig] Did not connect:", err)
			return
		}

		tc := tcPartSigMsgpb.NewTcPartSigMsgHandleClient(conn)
		ctx, _ := context.WithTimeout(context.Background(), time.Second)

		tcPartSigMsg := &tcPartSigMsgpb.TcPartSigMsg{Round: int64(round), Id: *Id, Sig: base64.StdEncoding.EncodeToString(partSig)}

		_, err = tc.TcPartSigMsgReceive(ctx, tcPartSigMsg)
		if err != nil {
			fmt.Println("[!!!Error SendPartSig] Failed to send:", err)
			return
		} else {
			fmt.Printf("[SendPartSig] Successfully send a new partSig to node %d\n", int(round)%n)
		}
	}
}

// Leader sends the complete signature for the timed commitment to all other nodes after recovering a valid complete signature
// Also used in the blankMsgHandler
func SendCompleteSig(completeSig []byte, requireRound int64) {
	if completeSig != nil {
		for i, ip := range *ips {
			/* norml case */
			if i != int(*Id) {
				/* simulate lacking complete signature */
				// if (i != int(*Id)) && (i != (int(*Id)+1)%n) {
				fmt.Printf("[SendCompleteSig] Start to send a new completeSig to node %d\n", i)

				conn, err := grpc.Dial(ip, grpc.WithTransportCredentials(insecure.NewCredentials()))
				if err != nil {
					fmt.Println("[!!!Error SendCompleteSig] Did not connect:", err)
					continue
				}

				tc := tcCompleteSigMsgpb.NewTcCompleteSigMsgHandleClient(conn)
				ctx, _ := context.WithTimeout(context.Background(), time.Second)

				tcCompleteSigMsg := &tcCompleteSigMsgpb.TcCompleteSigMsg{Round: requireRound, Id: *Id, Sig: base64.StdEncoding.EncodeToString(completeSig)}

				_, err = tc.TcCompleteSigMsgReceive(ctx, tcCompleteSigMsg)
				if err != nil {
					fmt.Println("[!!!Error SendCompleteSig] Failed to send:", err)
					continue
				} else {
					fmt.Printf("[SendCompleteSig] Successfully send a new completeSig to node %d\n", i)
				}
			}
		}
	}
}
