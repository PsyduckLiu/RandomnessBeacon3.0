package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"node/msg/errCompleteSigMsgpb"
	"node/msg/errMsgpb"
	"node/util"
	"time"

	"go.dedis.ch/kyber/v3/sign/bls"
	"go.dedis.ch/kyber/v3/sign/tbls"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// errMsgServer is used to implement errMsgpb.ErrMsgReceive
type errMsgServer struct {
	errMsgpb.UnimplementedErrMsgHandleServer
}

// errCompleteMsgServer is used to implement errCompleteMsgpb.ErrCompleteMsgReceive
type errCompleteSigMsgServer struct {
	errCompleteSigMsgpb.UnimplementedErrCompleteSigMsgHandleServer
}

// errMsgReceive implements errMsgpb.ErrMsgReceive
// Leader handles the partial signatures for the error message from all other nodes
func (ems *errMsgServer) ErrMsgReceive(ctx context.Context, in *errMsgpb.ErrMsg) (*errMsgpb.ErrMsgResponse, error) {
	if in.Err {
		rawerrMsg := &errMsgpb.ErrMsg{Round: in.Round, Err: in.Err}
		marshaledrawerrMsg, err := json.Marshal(rawerrMsg.String())
		if err != nil {
			fmt.Printf("[!!!Error ErrMsgReceive] Marshal error : %s", err)
			return &errMsgpb.ErrMsgResponse{}, nil
		}

		sig, err := base64.StdEncoding.DecodeString(in.GetSig())
		if err != nil {
			fmt.Printf("[!!!Error ErrMsgReceive] DecodeString error: %s", err)
			return &errMsgpb.ErrMsgResponse{}, nil
		}

		err = tbls.Verify(suite, ErrpubPoly, util.Digest(marshaledrawerrMsg), sig)
		if err != nil {
			fmt.Printf("[!!!Error ErrMsgReceive] Signature Verify failed: %s", err)
			return &errMsgpb.ErrMsgResponse{}, nil
		} else {
			errPartSet[int(in.Round)%n] = append(errPartSet[int(in.Round)%n], sig)
			fmt.Println("[ErrMsgReceive] Partial Verify pass")
			fmt.Printf("[ErrMsgReceive] Add new errPartSig from node %v for Round %v to [errPartSet]\n", in.Id, in.Round)
		}
	}

	return &errMsgpb.ErrMsgResponse{}, nil
}

// errCompleteSigMsgReceive implements errCompleteSigMsgpb.ErrCompleteSigMsgReceive
// Nodes handle the complete signatures for the error message
func (efsms *errCompleteSigMsgServer) ErrCompleteSigMsgReceive(ctx context.Context, in *errCompleteSigMsgpb.ErrCompleteSigMsg) (*errCompleteSigMsgpb.ErrCompleteSigMsgResponse, error) {
	errMsg := &errMsgpb.ErrMsg{Round: in.Round, Err: true}

	marshalederrMsg, err := json.Marshal(errMsg.String())
	if err != nil {
		fmt.Printf("[!!!Error ErrCompleteSigMsgReceive] Marshal error : %s", err)
		return &errCompleteSigMsgpb.ErrCompleteSigMsgResponse{}, nil
	}

	sig, err := base64.StdEncoding.DecodeString(in.GetSig())
	if err != nil {
		fmt.Printf("[!!!Error ErrCompleteSigMsgReceive] DecodeString error: %s", err)
		return &errCompleteSigMsgpb.ErrCompleteSigMsgResponse{}, nil
	}

	err = bls.Verify(suite, ErrpubPoly.Commit(), util.Digest(marshalederrMsg), sig)
	if err != nil {
		fmt.Printf("[!!!Error ErrCompleteSigMsgReceive] Commit() failed:%s", err)
		return &errCompleteSigMsgpb.ErrCompleteSigMsgResponse{}, nil
	} else {
		if errCompleteSet[int(in.Round)%n] == nil {
			errCompleteSet[int(in.Round)%n] = sig
			badNode = append(badNode, int(in.Round)%n)
			tcSet[int(in.Round)%n] = nil
			resultSet[int(in.Round)%n] = nil
			tcCompleteSigSet[int(in.Round)%n] = nil
			errPartSet[int(in.Round)%n] = nil
			SendErrCompleteSig(sig, in.Round)

			fmt.Println("[ErrCompleteSigMsgReceive] Complete Verify pass")
			fmt.Printf("[ErrCompleteSigMsgReceive] Add new errCompleteSig for Round %v to [errCompleteSet]\n", in.Round)
		}

	}

	return &errCompleteSigMsgpb.ErrCompleteSigMsgResponse{}, nil
}

// Nodes send the complete signature for the error message to all other nodes
func SendErrCompleteSig(errCompleteSig []byte, requireRound int64) {
	if errCompleteSig != nil {
		for i, ip := range *ips {
			if i != int(*Id) {
				fmt.Printf("[SendErrCompleteSig] Start to send a new errCompleteSig to node %d\n", i)

				conn, err := grpc.Dial(ip, grpc.WithTransportCredentials(insecure.NewCredentials()))
				if err != nil {
					fmt.Println("[!!!Error SendErrCompleteSig] Did not connect:", err)
					continue
				}

				errComplete := errCompleteSigMsgpb.NewErrCompleteSigMsgHandleClient(conn)
				ctx, _ := context.WithTimeout(context.Background(), time.Second)

				errCompleteSigMsg := &errCompleteSigMsgpb.ErrCompleteSigMsg{Round: requireRound, Sig: base64.StdEncoding.EncodeToString(errCompleteSig)}

				_, err = errComplete.ErrCompleteSigMsgReceive(ctx, errCompleteSigMsg)
				if err != nil {
					fmt.Println("[!!!Error SendErrCompleteSig] Failed to send:", err)
					continue
				} else {
					fmt.Printf("[SendErrCompleteSig] Successfully send a new errCompleteSig to node %d\n", i)
				}
			}
		}
	}

}
