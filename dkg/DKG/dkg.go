package DKG

import (
	"fmt"
	"strconv"

	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/pairing/bn256"
	"go.dedis.ch/kyber/v3/share"
	dkg "go.dedis.ch/kyber/v3/share/dkg/rabin"
	"go.dedis.ch/kyber/v3/sign/bls"
)

type Node struct {
	Id                 int
	ip                 string
	dkg                *dkg.DistKeyGenerator
	PubKey             kyber.Point
	PrivKey            kyber.Scalar
	Ips                map[int]string
	deals              []*dkg.Deal
	resps              []*dkg.Response
	commits            []*dkg.SecretCommits
	complaintcommits   []*dkg.ComplaintCommits
	reconstructcommits []*dkg.ReconstructCommits
	SecretShare        *share.PriShare
}

var suite = bn256.NewSuite()
var suiteG2 = bn256.NewSuiteG2()

// Use the dkg/pedersen API to generate a public key and its corresponding private key that is shared among nodes.
// It shows the different phases that each node must perform in order to construct the private shares that will form the final private key.
func DKG(n int) ([]*Node, kyber.Point, []*Node, kyber.Point, []string, []kyber.Point) {
	nodes := make([]*Node, n)
	pubKeys := make([]kyber.Point, n)
	ips := make([]string, n)

	// 1. Init the nodes
	for i := 0; i < n; i++ {
		// privKey, pubKey := bls.NewKeyPair(suite, random.New())
		privKey := suite.G1().Scalar().Pick(suite.RandomStream())
		pubKey := suite.G2().Point().Mul(privKey, nil)
		ip := "127.0.0.1:" + strconv.Itoa(30000+i)
		ips[i] = ip
		pubKeys[i] = pubKey
		nodes[i] = &Node{
			Id:      i,
			ip:      ip,
			PubKey:  pubKey,
			PrivKey: privKey,
			Ips:     make(map[int]string, 0),
			deals:   make([]*dkg.Deal, 0),
			resps:   make([]*dkg.Response, 0),
		}

		fmt.Println("new local public key:", pubKey)
		fmt.Println("new local private key:", privKey)
	}

	/* TC setup */
	// 2. Create the DKGs on each node
	for i, node := range nodes {
		dkg, err := dkg.NewDistKeyGenerator(suiteG2, nodes[i].PrivKey, pubKeys, 2*n/3+1)
		if err != nil {
			panic(fmt.Errorf("===>[ERROR from DKG step 2]NewDistKeyGenerator() failed:%s", err))
		}

		for j, otherNode := range nodes {
			if j != i {
				node.Ips[j] = otherNode.ip
			}
		}

		node.dkg = dkg
	}

	// 3. Each node sends its Deals to the other nodes
	for _, node := range nodes {
		deals, err := node.dkg.Deals()
		if err != nil {
			panic(fmt.Errorf("===>[ERROR from DKG step 3]Deals() failed:%s", err))
		}

		for i, deal := range deals {
			nodes[i].deals = append(nodes[i].deals, deal)
		}
	}

	// 4. Process the Deals on each node and send the responses to the other nodes
	for i, node := range nodes {
		for _, deal := range node.deals {
			resp, err := node.dkg.ProcessDeal(deal)
			if err != nil {
				panic(fmt.Errorf("===>[ERROR from DKG step 4]ProcessDeal() failed:%s", err))
			}

			for j, otherNode := range nodes {
				if j == i {
					continue
				}
				otherNode.resps = append(otherNode.resps, resp)
			}
		}
	}

	// 5. Process the responses on each node
	for _, node := range nodes {
		for _, resp := range node.resps {
			justification, err := node.dkg.ProcessResponse(resp)
			if err != nil {
				panic(fmt.Errorf("===>[ERROR from DKG step 5]ProcessResponse() failed:%s", err))
			}

			if justification != nil {
				err = node.dkg.ProcessJustification(justification)
				if err != nil {
					panic(fmt.Errorf("===>[ERROR from DKG step 5]ProcessJustification() failed:%s", err))
				}
			}

		}
	}

	// 6. Check and print the qualified shares
	// Each QUAL participant generates their secret commitments calling `SecretCommits()` and broadcasts them to the QUAL set.
	// Each QUAL participant processes the received secret commitments using `SecretCommits()`.
	// If there is an error, it can return a commitment complaint (ComplaintCommits) that must be broadcasted to the QUAL set.
	// Each QUAL participant receiving a complaint can process it with `ProcessComplaintCommits()`
	// which returns the secret share (ReconstructCommits) given from the malicious participant.
	// This structure must be broadcasted to all the QUAL participant.
	for _, node := range nodes {
		if node.dkg.Certified() {
			commit, err := node.dkg.SecretCommits()
			if err != nil {
				panic(fmt.Errorf("===>[ERROR from DKG step 6]SecretCommits() failed:%s", err))
			}

			for i := range node.dkg.QUAL() {
				nodes[i].commits = append(nodes[i].commits, commit)
			}
		} else {
			panic(fmt.Errorf("===>[ERROR from DKG step 6]Certified() failed"))
		}
	}

	for _, node := range nodes {
		for _, commit := range node.commits {
			complaintcommit, err := node.dkg.ProcessSecretCommits(commit)
			if err != nil {
				panic(fmt.Errorf("===>[ERROR from DKG step 6]ProcessSecretCommits() failed:%s", err))
			}
			if complaintcommit != nil {
				for i := range node.dkg.QUAL() {
					nodes[i].complaintcommits = append(nodes[i].complaintcommits, complaintcommit)
				}
			}
		}
	}

	for _, node := range nodes {
		for _, complaintcommit := range node.complaintcommits {
			reconstructcommit, err := node.dkg.ProcessComplaintCommits(complaintcommit)
			if err != nil {
				panic(fmt.Errorf("===>[ERROR from DKG step 6]ProcessComplaintCommits() failed:%s", err))
			}
			if reconstructcommit != nil {
				for i := range node.dkg.QUAL() {
					nodes[i].reconstructcommits = append(nodes[i].reconstructcommits, reconstructcommit)
				}
			}
		}
	}

	// 7. Get the secret shares and public key
	shares := make([]*share.PriShare, n)
	var publicKey kyber.Point
	for i, node := range nodes {
		distrKey, err := node.dkg.DistKeyShare()
		if err != nil {
			panic(fmt.Errorf("===>[ERROR from DKG step 7]DistKeyShare() failed:%s", err))
		}

		shares[i] = distrKey.PriShare()
		publicKey = distrKey.Public()
		node.SecretShare = distrKey.PriShare()
		fmt.Println("new distributed secret share is:", node.SecretShare)
	}

	// 8. Recover
	message := []byte("Hello world")
	secretKey, err := share.RecoverSecret(suite.G2(), shares, 2*n/3+1, n)
	if err != nil {
		panic(fmt.Errorf("===>[ERROR from DKG step 8. Variant A]RecoverSecret() failed:%s", err))
	}
	fmt.Println(secretKey)

	sig, _ := bls.Sign(suite, secretKey, message)
	err = bls.Verify(suite, publicKey, message, sig)
	if err != nil {
		panic(fmt.Errorf("===>[ERROR from DKG step 8.]Verify() failed:%s", err))
	} else {
		fmt.Println("Total Verify pass")
	}

	// 9. bls signature
	for i := range nodes {
		sig, _ := bls.Sign(suite, nodes[i].PrivKey, message)
		err := bls.Verify(suite, nodes[i].PubKey, message, sig)

		if err != nil {
			panic(fmt.Errorf("===>[ERROR from DKG step 9.]Verify() failed:%s", err))
		} else {
			fmt.Println("Longterm Verify pass")
		}
	}

	/* Error setup */
	errnodes := make([]*Node, n)

	// 1. Init the errnodes
	for i := 0; i < n; i++ {
		ip := "127.0.0.1:" + strconv.Itoa(30000+i)
		errnodes[i] = &Node{
			Id:      i,
			ip:      ip,
			PubKey:  nodes[i].PubKey,
			PrivKey: nodes[i].PrivKey,
			Ips:     make(map[int]string, 0),
			deals:   make([]*dkg.Deal, 0),
			resps:   make([]*dkg.Response, 0),
		}

		fmt.Println("new local public key:", errnodes[i].PubKey)
		fmt.Println("new local private key:", errnodes[i].PrivKey)
	}

	// 2. Create the DKGs on each node
	for i, node := range errnodes {
		dkg, err := dkg.NewDistKeyGenerator(suiteG2, errnodes[i].PrivKey, pubKeys, n/3+1)
		if err != nil {
			panic(fmt.Errorf("===>[ERROR from DKG step 2]NewDistKeyGenerator() failed:%s", err))
		}

		for j, otherNode := range errnodes {
			if j != i {
				node.Ips[j] = otherNode.ip
			}
		}

		node.dkg = dkg
	}

	// 3. Each node sends its Deals to the other errnodes
	for _, node := range errnodes {
		deals, err := node.dkg.Deals()
		if err != nil {
			panic(fmt.Errorf("===>[ERROR from DKG step 3]Deals() failed:%s", err))
		}

		for i, deal := range deals {
			errnodes[i].deals = append(errnodes[i].deals, deal)
		}
	}

	// 4. Process the Deals on each node and send the responses to the other errnodes
	for i, node := range errnodes {
		for _, deal := range node.deals {
			resp, err := node.dkg.ProcessDeal(deal)
			if err != nil {
				panic(fmt.Errorf("===>[ERROR from DKG step 4]ProcessDeal() failed:%s", err))
			}

			for j, otherNode := range errnodes {
				if j == i {
					continue
				}
				otherNode.resps = append(otherNode.resps, resp)
			}
		}
	}

	// 5. Process the responses on each node
	for _, node := range errnodes {
		for _, resp := range node.resps {
			justification, err := node.dkg.ProcessResponse(resp)
			if err != nil {
				panic(fmt.Errorf("===>[ERROR from DKG step 5]ProcessResponse() failed:%s", err))
			}

			if justification != nil {
				err = node.dkg.ProcessJustification(justification)
				if err != nil {
					panic(fmt.Errorf("===>[ERROR from DKG step 5]ProcessJustification() failed:%s", err))
				}
			}

		}
	}

	// 6. Check and print the qualified shares
	// Each QUAL participant generates their secret commitments calling `SecretCommits()` and broadcasts them to the QUAL set.
	// Each QUAL participant processes the received secret commitments using `SecretCommits()`.
	// If there is an error, it can return a commitment complaint (ComplaintCommits) that must be broadcasted to the QUAL set.
	// Each QUAL participant receiving a complaint can process it with `ProcessComplaintCommits()`
	// which returns the secret share (ReconstructCommits) given from the malicious participant.
	// This structure must be broadcasted to all the QUAL participant.
	for _, node := range errnodes {
		if node.dkg.Certified() {
			commit, err := node.dkg.SecretCommits()
			if err != nil {
				panic(fmt.Errorf("===>[ERROR from DKG step 6]SecretCommits() failed:%s", err))
			}

			for i := range node.dkg.QUAL() {
				errnodes[i].commits = append(errnodes[i].commits, commit)
			}
		} else {
			panic(fmt.Errorf("===>[ERROR from DKG step 6]Certified() failed"))
		}
	}

	for _, node := range errnodes {
		for _, commit := range node.commits {
			complaintcommit, err := node.dkg.ProcessSecretCommits(commit)
			if err != nil {
				panic(fmt.Errorf("===>[ERROR from DKG step 6]ProcessSecretCommits() failed:%s", err))
			}
			if complaintcommit != nil {
				for i := range node.dkg.QUAL() {
					errnodes[i].complaintcommits = append(errnodes[i].complaintcommits, complaintcommit)
				}
			}
		}
	}

	for _, node := range errnodes {
		for _, complaintcommit := range node.complaintcommits {
			reconstructcommit, err := node.dkg.ProcessComplaintCommits(complaintcommit)
			if err != nil {
				panic(fmt.Errorf("===>[ERROR from DKG step 6]ProcessComplaintCommits() failed:%s", err))
			}
			if reconstructcommit != nil {
				for i := range node.dkg.QUAL() {
					errnodes[i].reconstructcommits = append(errnodes[i].reconstructcommits, reconstructcommit)
				}
			}
		}
	}

	// 7. Get the secret errshares and errpublickey
	errshares := make([]*share.PriShare, n)
	var errpublicKey kyber.Point
	for i, node := range errnodes {
		distrKey, err := node.dkg.DistKeyShare()
		if err != nil {
			panic(fmt.Errorf("===>[ERROR from DKG step 7]DistKeyShare() failed:%s", err))
		}

		errshares[i] = distrKey.PriShare()
		errpublicKey = distrKey.Public()
		node.SecretShare = distrKey.PriShare()
		fmt.Println("new distributed secret share is:", node.SecretShare)
	}

	// 8. Recover
	errsecretKey, err := share.RecoverSecret(suite.G2(), errshares, n/3+1, n)
	if err != nil {
		panic(fmt.Errorf("===>[ERROR from DKG step 8. Variant A]RecoverSecret() failed:%s", err))
	}
	fmt.Println(errsecretKey)

	sig, _ = bls.Sign(suite, errsecretKey, message)
	err = bls.Verify(suite, errpublicKey, message, sig)
	if err != nil {
		panic(fmt.Errorf("===>[ERROR from DKG step 8.]Verify() failed:%s", err))
	} else {
		fmt.Println("Total Verify pass")
	}

	// 9. bls signature
	for i := range errnodes {
		sig, _ := bls.Sign(suite, errnodes[i].PrivKey, message)
		err := bls.Verify(suite, errnodes[i].PubKey, message, sig)

		if err != nil {
			panic(fmt.Errorf("===>[ERROR from DKG step 9.]Verify() failed:%s", err))
		} else {
			fmt.Println("Longterm Verify pass")
		}
	}

	return nodes, publicKey, errnodes, errpublicKey, ips, pubKeys
}
