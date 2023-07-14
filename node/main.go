package main

import (
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"node/crypto/binaryquadraticform"
	"node/crypto/timedCommitment"
	"node/msg/blankReplyMsgpb"
	"node/msg/blankRequireMsgpb"
	"node/msg/errCompleteSigMsgpb"
	"node/msg/errMsgpb"
	"node/msg/errSetupMsgpb"
	"node/msg/groupMsgpb"
	"node/msg/rMsgpb"
	"node/msg/tcCompleteSigMsgpb"
	"node/msg/tcMsgpb"
	"node/msg/tcPartSigMsgpb"
	"node/msg/tcSetupMsgpb"
	"node/util"
	"os"
	"strconv"
	"time"

	"go.dedis.ch/kyber/v3/sign/bls"
	"go.dedis.ch/kyber/v3/sign/tbls"
	"google.golang.org/grpc"
)

// Once a valid Timed Commitment is received, start the process of force-opening it
// Todo: Include the VRF mechanism
func SolveTC(round int, maskedMsg *big.Int, h *binaryquadraticform.BQuadraticForm) {
	// VRF
	// bigZero := big.NewInt(0)
	// bigThree := big.NewInt(3)
	// vrf := big.NewInt(0)
	// vrf.Mod(lastOutput, bigThree)

	// if vrf.Cmp(bigZero) == 0 {
	// 	fmt.Printf("[SolveTC] Start to force-open the TC from [Node %d].\n", round%n)
	// 	resultSet[round%n] = timedCommitment.ForcedOpen(int(*timeT), maskedMsg, h)
	// }

	fmt.Printf("[SolveTC] Start to force-open the TC from [Node %d].\n", round%n)
	resultSet[round%n] = timedCommitment.ForcedOpen(int(*timeT), maskedMsg, h)
}

// Determine whether a node is a verified malicious one
func IsBad(id int) bool {
	for _, bad := range badNode {
		if bad == id {
			return true
		}
	}

	return false
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
	tcSetupMsgpb.RegisterTcSetupMsgHandleServer(ps, &tcSetupMsgServer{})
	errSetupMsgpb.RegisterErrSetupMsgHandleServer(ps, &errSetupMsgServer{})
	groupMsgpb.RegisterGroupMsgHandleServer(ps, &groupMsgServer{})
	rMsgpb.RegisterRMsgHandleServer(ps, &rMsgServer{})
	tcMsgpb.RegisterTcMsgHandleServer(ps, &tcMsgServer{})
	tcPartSigMsgpb.RegisterTcPartSigMsgHandleServer(ps, &tcPartSigMsgServer{})
	tcCompleteSigMsgpb.RegisterTcCompleteSigMsgHandleServer(ps, &tcCompleteSigMsgServer{})
	blankRequireMsgpb.RegisterBlankRequireMsgHandleServer(ps, &blankRequireMsgServer{})
	blankReplyMsgpb.RegisterBlankReplyMsgHandleServer(ps, &blankReplyMsgServer{})
	errMsgpb.RegisterErrMsgHandleServer(ps, &errMsgServer{})
	errCompleteSigMsgpb.RegisterErrCompleteSigMsgHandleServer(ps, &errCompleteSigMsgServer{})
	go ps.Serve(lis)
	fmt.Printf("===>[Collector]Collector is listening at %v\n", lis.Addr())

	initTimer := time.NewTicker(1 * time.Second)
	startTimer := time.NewTicker(1 * time.Second)
	tcProposalTimer := time.NewTicker(1 * time.Second)
	sigProposalTimer := time.NewTicker(1 * time.Second)
	errTimer := time.NewTicker(1 * time.Second)
	initTimer.Stop()
	startTimer.Stop()
	tcProposalTimer.Stop()
	sigProposalTimer.Stop()
	errTimer.Stop()

	lastOutput := big.NewInt(0)
	init := true
	for {
		if p.GetA() == nil {
			continue
		} else {
			// time.Sleep(10 * time.Second)
			if init {
				n = len(*ips)
				tcT = 2*n/3 + 1
				errT = n/3 + 1
				init = false
				fmt.Println("[Init] Last output is:", lastOutput)
				fmt.Println("[Init] Number of nodes is ", n)
				fmt.Println("[Init] Number of TC threshold is ", tcT)
				fmt.Println("[Init] Number of ERR threshold is ", errT)

				if round%n == idInt {
					maskedMsg, h, M_k, a1, a2, z := timedCommitment.GenerateTC(g, m_k, r_k, p, int(*timeT))
					go SolveTC(round, maskedMsg, h)
					// fmt.Println(timedCommitment.VerifyTC(int(*timeT), maskedMsg, g, m_k, r_k, p, h, M_k, a1, a2, z))

					newTC := TC{
						MaskedMsg: maskedMsg.String(),
						HA:        h.GetA().String(),
						HB:        h.GetB().String(),
						HC:        h.GetC().String(),
					}

					marshaledTC, err := json.Marshal(newTC)
					if err != nil {
						fmt.Printf("[!!!Error Init] Marshal error: %s\n", err)
						continue
					}

					tcSet[idInt] = marshaledTC
					SendTCMsg(maskedMsg, h, M_k, a1, a2, z)
				}
				initTimer.Reset(5 * time.Second)
			}

			select {
			case <-startTimer.C:
				startTimer.Stop()
				if round%n == idInt {
					go FillBlank(int64(round), errTimer)
					maskedMsg, h, M_k, a1, a2, z := timedCommitment.GenerateTC(g, m_k, r_k, p, int(*timeT))
					go SolveTC(round, maskedMsg, h)
					// fmt.Println(timedCommitment.VerifyTC(int(*timeT), maskedMsg, g, m_k, r_k, p, h, M_k, a1, a2, z))

					newTC := TC{
						MaskedMsg: maskedMsg.String(),
						HA:        h.GetA().String(),
						HB:        h.GetB().String(),
						HC:        h.GetC().String(),
					}

					marshaledTC, err := json.Marshal(newTC)
					if err != nil {
						fmt.Printf("[!!!Error Leader] Marshal error: %s\n", err)
						continue
					}

					tcSet[idInt] = marshaledTC
					SendTCMsg(maskedMsg, h, M_k, a1, a2, z)
				}
				initTimer.Reset(5 * time.Second)

			case <-initTimer.C:
				initTimer.Stop()
				var partSig []byte
				var err error
				if tcSet[round%n] != nil {
					partSig, err = tbls.Sign(suite, SecretShare, util.Digest(tcSet[round%n]))
					if err != nil {
						fmt.Printf("[!!!Error Node] tbls Sign() failed: %s\n", err)
						continue
					}
				}

				if round%n != idInt {
					SendPartSig(partSig)
					sigProposalTimer.Reset(10 * time.Second)
				} else {
					tcPartSigSet = append(tcPartSigSet, partSig)
					tcProposalTimer.Reset(5 * time.Second)
				}

			case <-tcProposalTimer.C:
				tcProposalTimer.Stop()
				if round%n == idInt {
					sig, err := tbls.Recover(suite, pubPoly, util.Digest(tcSet[round%n]), tcPartSigSet, tcT, n)
					if err != nil {
						fmt.Printf("[!!!Error Leader] tbls Recover() failed: %s\n", err)
						continue
					}

					err = bls.Verify(suite, pubPoly.Commit(), util.Digest(tcSet[round%n]), sig)
					if err != nil {
						fmt.Printf("[!!!Error Leader] tbls Commit() failed: %s\n", err)
						continue
					} else {
						fmt.Println("[Leader] Recover then Verify pass")
						tcCompleteSigSet[idInt] = sig
						SendCompleteSig(sig, int64(round))
						sigProposalTimer.Reset(5 * time.Second)
					}
				}

			case <-sigProposalTimer.C:
				sigProposalTimer.Stop()
				tcPartSigSet = make([][]byte, 0)

				util.WriteFile("bandwidth/result"+id, []byte(sendBandwidth.String()+"\n"), 0666)
				util.WriteFile("bandwidth/result"+id, []byte(receiveBandwidth.String()+"\n"), 0666)
				fmt.Printf("[Node] Send %v bytes", sendBandwidth)
				fmt.Printf("[Node] Receive %v bytes", receiveBandwidth)
				sendBandwidth.Set(bigZero)
				receiveBandwidth.Set(bigZero)

				if round >= n {
					fmt.Println("[Node] R0 is", R0)
					if errCompleteSet[round%n] == nil {
						output := big.NewInt(0)
						outputBytes := append(lastResultSet[round%n].Bytes(), []byte(strconv.Itoa(round))...)
						fmt.Println("[Node] This is a normal round, the forced-open result is", lastResultSet[round%n])
						fmt.Println("[Node] This is a normal round, the forced-open result is", lastResultSet[round%n].Bytes())
						fmt.Println("[Node] This is a normal round, the round number is", []byte(strconv.Itoa(round)))
						fmt.Println("[Node] This is a normal round, the mid-value is", outputBytes)
						outputBytes = util.Digest(outputBytes)
						fmt.Println("[Node] This is a normal round, the forced-open result is", output.SetBytes(outputBytes))
						lastOutput = output.SetBytes(outputBytes)
					} else {
						fmt.Println("[Node] This is a error round, the result is default value")
					}
				}
				fmt.Printf("#####################Round %v Over#####################\n", round)

				round++
				lastResultSet[round%n] = resultSet[round%n]
				tcSet[round%n] = nil
				resultSet[round%n] = nil
				tcCompleteSigSet[round%n] = nil
				errPartSet[round%n] = nil
				for IsBad(round % n) {
					fmt.Println("[Node] The leader is malicious, pass this round")
					fmt.Printf("#####################Round %v Over#####################\n", round)
					round++
					lastResultSet[round%n] = resultSet[round%n]
					tcSet[round%n] = nil
					resultSet[round%n] = nil
					tcCompleteSigSet[round%n] = nil
					errPartSet[round%n] = nil
				}

				startTimer.Reset(5 * time.Second)

			case <-errTimer.C:
				errTimer.Stop()
				for i := 0; i < n; i++ {
					if (len(errPartSet[i]) >= errT) && (!IsBad(i)) {
						requireRound := 0
						if round <= n {
							requireRound = i
						} else {
							if i < round%n {
								requireRound = round - (round%n - i)
							} else {
								requireRound = round - (round%n - i) - n
							}
						}

						fmt.Println("[Node] requireRound in errMsg", requireRound)
						errMsg := &errMsgpb.ErrMsg{Round: int64(requireRound), Err: true}

						marshalederrMsg, err := json.Marshal(errMsg.String())
						if err != nil {
							fmt.Printf("[!!!Error Node] Marshal error: %s\n", err)
							continue
						}

						completeErrSig, err := tbls.Recover(suite, ErrpubPoly, util.Digest(marshalederrMsg), errPartSet[i], errT, n)
						if err != nil {
							fmt.Printf("[!!!Error Node] tbls Recover() failed: %s\n", err)
							continue
						}

						err = bls.Verify(suite, ErrpubPoly.Commit(), util.Digest(marshalederrMsg), completeErrSig)
						if err != nil {
							fmt.Printf("[!!!Error Node] tbls Commit() failed: %s\n", err)
							continue
						} else {
							fmt.Println("[Node] completeErrSig Recover then Verify pass")
							errCompleteSet[i] = completeErrSig
							badNode = append(badNode, i)
							SendErrCompleteSig(completeErrSig, int64(requireRound))
						}
					}
				}
			}
		}
	}
}
