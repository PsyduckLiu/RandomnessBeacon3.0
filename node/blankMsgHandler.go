package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"node/crypto/binaryquadraticform"
	"node/msg/blankReplyMsgpb"
	"node/msg/blankRequireMsgpb"
	"node/msg/errMsgpb"
	"node/util"
	"time"

	"go.dedis.ch/kyber/v3/sign/bls"
	"go.dedis.ch/kyber/v3/sign/tbls"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// blankRequireMsgServer is used to implement blankRequireMsgpb.BlankRequireMsgReceive
type blankRequireMsgServer struct {
	blankRequireMsgpb.UnimplementedBlankRequireMsgHandleServer
}

// blankReplyMsgServer is used to implement blankReplyMsgpb.BlankReplyMsgReceive
type blankReplyMsgServer struct {
	blankReplyMsgpb.UnimplementedBlankReplyMsgHandleServer
}

// blankRequireMsgReceive implements blankRequireMsgpb.BlankRequireMsgReceive
// Nodes reponse to the require message based on its situation
func (brms *blankRequireMsgServer) BlankRequireMsgReceive(ctx context.Context, in *blankRequireMsgpb.BlankRequireMsg) (*blankRequireMsgpb.BlankRequireMsgResponse, error) {
	if int(in.CurrentRound)%n != int(in.Id) {
		fmt.Println("[!!!Error BlankRequireMsgReceive] Wrong id")
		return &blankRequireMsgpb.BlankRequireMsgResponse{}, nil
	}

	// verify the signature of the message
	rawblankRequireMsg := &blankRequireMsgpb.BlankRequireMsg{RequireRound: in.RequireRound, CurrentRound: in.CurrentRound, Id: in.Id}
	marshaledrawblankRequireMsg, err := json.Marshal(rawblankRequireMsg)
	if err != nil {
		fmt.Printf("[!!!Error BlankRequireMsgReceive] Marshal error : %s", err)
		return &blankRequireMsgpb.BlankRequireMsgResponse{}, nil
	}

	sig, err := base64.StdEncoding.DecodeString(in.GetSig())
	if err != nil {
		fmt.Printf("[!!!Error BlankRequireMsgReceive] DecodeString error: %s", err)
		return &blankRequireMsgpb.BlankRequireMsgResponse{}, nil
	}

	err = bls.Verify(suite, (*pubKeys)[in.GetId()], marshaledrawblankRequireMsg, sig)
	if err != nil {
		fmt.Printf("[!!!Error BlankRequireMsgReceive] Signature Verify() failed:%s", err)
		return &blankRequireMsgpb.BlankRequireMsgResponse{}, nil
	} else {
		fmt.Println("[BlankRequireMsgReceive] Signature Verify pass")

		// the node has a complete error certificate
		if errCompleteSet[int(in.RequireRound)%n] != nil {
			fmt.Println("[BlankRequireMsgReceive] Send a complete error certificate")
			SendErrCompleteSig(errCompleteSet[int(in.RequireRound)%n], in.RequireRound)
		} else {
			if tcCompleteSigSet[int(in.RequireRound)%n] != nil {
				// the node has a complete TC certificate
				fmt.Println("[BlankRequireMsgReceive] Send a complete TC certificate")

				newTC := &TC{}
				err = json.Unmarshal(tcSet[int(in.RequireRound)%n], newTC)
				if err != nil {
					fmt.Println("[!!!Error BlankRequireMsgReceive] Failed to Unmarshal:", err)
					return &blankRequireMsgpb.BlankRequireMsgResponse{}, nil
				}

				ip := (*ips)[in.Id]
				conn, err := grpc.Dial(ip, grpc.WithTransportCredentials(insecure.NewCredentials()))
				if err != nil {
					fmt.Println("[!!!Error BlankRequireMsgReceive] Did not connect:", err)
					return &blankRequireMsgpb.BlankRequireMsgResponse{}, nil
				}

				tc := blankReplyMsgpb.NewBlankReplyMsgHandleClient(conn)
				ctx, _ := context.WithTimeout(context.Background(), time.Second)

				blankReplyMsg := &blankReplyMsgpb.BlankReplyMsg{RequireRound: in.RequireRound, MaskedMsg: newTC.MaskedMsg,
					HA: newTC.HA, HB: newTC.HB, HC: newTC.HC, CompleteSig: base64.StdEncoding.EncodeToString(tcCompleteSigSet[int(in.RequireRound)%n])}

				_, err = tc.BlankReplyMsgReceive(ctx, blankReplyMsg)
				if err != nil {
					fmt.Println("[!!!Error BlankRequireMsgReceive] Failed to send:", err)
					return &blankRequireMsgpb.BlankRequireMsgResponse{}, nil
				} else {
					fmt.Printf("[BlankRequireMsgReceive] Successfully send a BlankReplyMsg to node %d\n", in.Id)
				}
			} else {
				// the node sends an partial error signature
				fmt.Println("[BlankRequireMsgReceive] Send an partial error signature")

				ip := (*ips)[in.Id]
				conn, err := grpc.Dial(ip, grpc.WithTransportCredentials(insecure.NewCredentials()))
				if err != nil {
					fmt.Println("[!!!Error BlankRequireMsgReceive] Did not connect:", err)
					return &blankRequireMsgpb.BlankRequireMsgResponse{}, nil
				}

				tc := errMsgpb.NewErrMsgHandleClient(conn)
				ctx, _ := context.WithTimeout(context.Background(), time.Second)

				errMsg := &errMsgpb.ErrMsg{Round: in.RequireRound, Err: true}
				marshalederrMsg, err := json.Marshal(errMsg.String())
				if err != nil {
					fmt.Printf("[!!!Error BlankRequireMsgReceive] Marshal error: %s\n", err)
					return &blankRequireMsgpb.BlankRequireMsgResponse{}, nil
				}

				partErrSig, err := tbls.Sign(suite, ErrSecretShare, util.Digest(marshalederrMsg))
				if err != nil {
					fmt.Printf("[!!!Error BlankRequireMsgReceive] Sign error: %s\n", err)
					return &blankRequireMsgpb.BlankRequireMsgResponse{}, nil
				}
				errMsg.Id = *Id
				errMsg.Sig = base64.StdEncoding.EncodeToString(partErrSig)

				_, err = tc.ErrMsgReceive(ctx, errMsg)
				if err != nil {
					fmt.Println("[!!!Error BlankRequireMsgReceive] Failed to send:", err)
					return &blankRequireMsgpb.BlankRequireMsgResponse{}, nil
				} else {
					fmt.Printf("[BlankRequireMsgReceive] Successfully send a ErrMsg to node %d\n", in.Id)
				}
			}
		}
	}

	return &blankRequireMsgpb.BlankRequireMsgResponse{}, nil
}

// blankReplyMsgReceive implements blankReplyMsgpb.BlankReplyMsgReceive
// Leader handles the complete TC certificate received from other nodes
func (brms *blankReplyMsgServer) BlankReplyMsgReceive(ctx context.Context, in *blankReplyMsgpb.BlankReplyMsg) (*blankReplyMsgpb.BlankReplyMsgResponse, error) {
	newTC := TC{
		MaskedMsg: in.MaskedMsg,
		HA:        in.HA,
		HB:        in.HB,
		HC:        in.HC,
	}

	marshaledTC, err := json.Marshal(newTC)
	if err != nil {
		fmt.Printf("[!!!Error BlankReplyMsgReceive] Marshal error : %s", err)
		return &blankReplyMsgpb.BlankReplyMsgResponse{}, nil
	}

	sig, err := base64.StdEncoding.DecodeString(in.GetCompleteSig())
	if err != nil {
		fmt.Printf("[!!!Error BlankReplyMsgReceive] DecodeString error: %s", err)
		return &blankReplyMsgpb.BlankReplyMsgResponse{}, nil
	}

	err = bls.Verify(suite, pubPoly.Commit(), util.Digest(marshaledTC), sig)
	if err != nil {
		fmt.Printf("[!!!Error BlankReplyMsgReceive] Commit() failed:%s", err)
		return &blankReplyMsgpb.BlankReplyMsgResponse{}, nil
	} else {
		if (tcCompleteSigSet[int(in.RequireRound)%n] == nil) && (errCompleteSet[int(in.RequireRound)%n] == nil) {
			tcSet[int(in.RequireRound)%n] = marshaledTC
			tcCompleteSigSet[int(in.RequireRound)%n] = sig

			maskedMsg := new(big.Int)
			maskedMsg.SetString(in.GetMaskedMsg(), 10)
			hA := big.NewInt(0)
			hB := big.NewInt(0)
			hC := big.NewInt(0)
			hA.SetString(in.HA, 10)
			hB.SetString(in.HB, 10)
			hC.SetString(in.HC, 10)
			h, err := binaryquadraticform.NewBQuadraticForm(hA, hB, hC)
			if err != nil {
				fmt.Printf("===>[!!!Error BlankReplyMsgReceive] Generate new BQuadratic Form h failed: %s", err)
				return &blankReplyMsgpb.BlankReplyMsgResponse{}, nil
			} else {
				fmt.Printf("[BlankReplyMsgReceive] The group element h is (a=%v,b=%v,c=%v,d=%v)\n", h.GetA(), h.GetB(), h.GetC(), h.GetDiscriminant())
			}

			// broadcast complete signature
			SendCompleteSig(sig, in.RequireRound)
			go SolveTC(int(in.RequireRound), maskedMsg, h)

			fmt.Println("[BlankReplyMsgReceive] Complete Verify pass")
			fmt.Printf("[BlankReplyMsgReceive] Add new TC for Round %v to [tcSet]\n", in.RequireRound)
			fmt.Printf("[BlankReplyMsgReceive] Add new tcCompleteSig for Round %v to [tcCompleteSigSet]\n", in.RequireRound)
		}
	}

	return &blankReplyMsgpb.BlankReplyMsgResponse{}, nil
}

// Leader tries to fill its blank
func FillBlank(currentRound int64, errTimer *time.Ticker) {
	fmt.Println("[FillBlank] Current round is", currentRound)

	if currentRound <= int64(n) {
		for i := 0; i < int(currentRound); i++ {
			if (tcCompleteSigSet[i] == nil) && (errCompleteSet[i] == nil) && (i != int(currentRound)%n) {
				if IsBad(i) {
					fmt.Printf("[FillBlank] Node %d is a bad guy", i)
					continue
				}

				fmt.Printf("[FillBlank] Require round %d\n", i)
				SendBlankRequireMsg(currentRound, i)

			}
		}
	} else {
		for i := 0; i < n; i++ {
			if (tcCompleteSigSet[i] == nil) && (i != int(currentRound)%n) && (errCompleteSet[i] == nil) {
				var requireRound int64
				if i < int(currentRound)%n {
					requireRound = currentRound - (currentRound%int64(n) - int64(i))
				} else {
					requireRound = currentRound - (currentRound%int64(n) - int64(i)) - int64(n)
				}

				if IsBad(i % n) {
					fmt.Printf("[!!!FillBlank] Node %d is a bad guy", i)
					continue
				}

				fmt.Printf("[FillBlank] Require round %d\n", requireRound)
				SendBlankRequireMsg(currentRound, int(requireRound))
			}
		}
	}

	errTimer.Reset(10 * time.Second)
}

// Leader sends the blank require message to all other nodes
func SendBlankRequireMsg(currentRound int64, requireRound int) {
	errMsg := &errMsgpb.ErrMsg{Round: int64(requireRound), Err: true}
	marshalederrMsg, err := json.Marshal(errMsg.String())
	if err != nil {
		fmt.Printf("[!!!Error SendBlankRequireMsg] Marshal error: %s\n", err)
		return
	}

	partErrSig, err := tbls.Sign(suite, ErrSecretShare, util.Digest(marshalederrMsg))
	if err != nil {
		fmt.Printf("[!!!Error SendBlankRequireMsg] Sign error: %s\n", err)
		return
	}
	errPartSet[requireRound%n] = append(errPartSet[requireRound%n], partErrSig)

	for j, ip := range *ips {
		if j != int(*Id) {
			fmt.Printf("[SendBlankRequireMsg] Start to send a new BlankRequireMsg to node %d\n", j)

			conn, err := grpc.Dial(ip, grpc.WithTransportCredentials(insecure.NewCredentials()))
			if err != nil {
				fmt.Println("[!!!Error SendBlankRequireMsg] Did not connect:", err)
				continue
			}

			tc := blankRequireMsgpb.NewBlankRequireMsgHandleClient(conn)
			ctx, _ := context.WithTimeout(context.Background(), time.Second)

			blankRequireMsg := &blankRequireMsgpb.BlankRequireMsg{RequireRound: int64(requireRound), CurrentRound: currentRound, Id: *Id}
			marshaledblankRequireMsg, err := json.Marshal(blankRequireMsg)
			if err != nil {
				fmt.Printf("[!!!Error SendBlankRequireMsg] Marshal error: %s\n", err)
				continue
			}

			sig, err := bls.Sign(suite, PrivKey, marshaledblankRequireMsg)
			if err != nil {
				fmt.Printf("[!!!Error SendBlankRequireMsg] Sign error: %s\n", err)
				continue
			}
			blankRequireMsg.Sig = base64.StdEncoding.EncodeToString(sig)

			_, err = tc.BlankRequireMsgReceive(ctx, blankRequireMsg)
			if err != nil {
				fmt.Println("[!!!Error SendBlankRequireMsg] Failed to send:", err)
				continue
			} else {
				fmt.Printf("[SendBlankRequireMsg] Successfully send a new BlankRequireMsg to node %d\n", j)
			}
		}
	}
}
