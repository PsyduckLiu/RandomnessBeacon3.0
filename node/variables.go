package main

import (
	"math/big"
	"node/crypto/binaryquadraticform"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/share"
)

// struct for Timed Commitment.
// MaskedMsg: maskedMsg.String().
// HA, HB, HC: h.GetA().String(), h.GetB().String(), h.GetC().String().
// TC.ForcedOpen() needs [timeT, maskedMsg, h].
type TC struct {
	MaskedMsg string
	HA        string
	HB        string
	HC        string
}

// n: the overall number of nodes.
var n = 0

// tcT: the threshold number required to recover a complete signature.
var tcT = 0

// errT: the threshold number required to recover a complete signature.
var errT = 0

// round: the current round number of the randomness beacon.
var round = 0

// suite: the group suite used for BLS signature.
var suite = bn256.NewSuite()

// Id: the id of the node.
var Id = new(int64)

// Ip: the ip address of the node.
var Ip = new(string)

// PubKey: the normal BLS public key of the node.
var PubKey = suite.G2().Point()

// PrivKey: the normal BLS private key of the node.
var PrivKey = suite.G1().Scalar()

// SecretShare: the secret share of the node for tBLS signature.
var SecretShare = new(share.PriShare)

// GlobalPubKey: the global public key for tBLS signature.
var GlobalPubKey = suite.G2().Point()

// pubPoly: the polynomial of the GlobalPubKey
var pubPoly = new(share.PubPoly)

// ErrSecretShare: the secret share of the node for tBLS signature.
var ErrSecretShare = new(share.PriShare)

// ErrGlobalPubKey: the global public key for tBLS signature.
var ErrGlobalPubKey = suite.G2().Point()

// ErrpubPoly: the polynomial of the GlobalPubKey
var ErrpubPoly = new(share.PubPoly)

// pubKeys: the normal BLS public keys of peer nodes.
var pubKeys = new([]kyber.Point)

// ips: the ip addresses of peer nodes.
var ips = new([]string)

// R0: the initial value of the randomness beacon.
var R0 = new(big.Int)

// g: the class group parameter.
var g = new(binaryquadraticform.BQuadraticForm)

// m_k: the class group parameter for verification.
var m_k = new(binaryquadraticform.BQuadraticForm)

// r_k: the class group parameter for verification.
var r_k = new(binaryquadraticform.BQuadraticForm)

// p: the class group parameter for verification.
var p = new(binaryquadraticform.BQuadraticForm)

// timeT: the time parameter.
var timeT = new(int64)

// tcSet: store the current collection of valid timed commitments.
var tcSet = make(map[int][]byte)

// resultSet: store the forced-open results for the corresponding timed commitments.
var resultSet = make(map[int]*big.Int)

// lastResultSet: store the forced-open results for the last corresponding timed commitments.
var lastResultSet = make(map[int]*big.Int)

// lastOutput: last output of the randomness beacon.
var lastOutput = big.NewInt(0)

// tcPartSigSet: store the current collection of valid partial signatures for timed commitments.
// Since tcPartSigSet is only utilized when the node is chosen as the leader, there is no need for an index.
var tcPartSigSet = make([][]byte, 0)

// tcCompleteSigSet: store the current collection of valid complete signatures for timed commitments.
// Complete signatures serve as certificates for the timed commitments.
var tcCompleteSigSet = make(map[int][]byte)

// errPartSet: store the current collection of valid partial signatures for error messages.
var errPartSet = make(map[int][][]byte)

// errPartSet: store the current collection of valid complete signatures for error messages.
var errCompleteSet = make(map[int][]byte)

// badNode: store the indices of verified malicious nodes.
var badNode = make([]int, 0)

var bigZero = big.NewInt(0)

// sendBandwidth: count the total bandwidth cost
var sendBandwidth = big.NewInt(0)

// receiveBandwidth: count the total bandwidth cost
var receiveBandwidth = big.NewInt(0)
