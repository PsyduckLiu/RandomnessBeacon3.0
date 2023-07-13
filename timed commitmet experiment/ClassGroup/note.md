## class groups (Cl) of imaginary quadratic orders

Cls are easy to generate. Their most interesting and useful property is that finding the group order is considered hard.

## Group Element Representation

Group Element can be represented as (a,b,c) or (a,b,Δ) triple (correspond to BinaryQF and ABDeltaTriple structures respectively).


## Related Papers
>  This a finite abelian group, with an efficiently computable group law and a compact representation of elements. Another feature of class groups is that given Δ, the order of 𝐶𝑙(Δ) (called the class number) is only known to be computable in sub-exponential time.

[1] (Page 5) Thyagarajan, Sri Aravinda Krishnan, et al. "Efficient cca timed commitments in class groups." Proceedings of the 2021 ACM SIGSAC Conference on Computer and Communications Security. 2021.

> 3 proposals for concrete unknown-order groups: RSA groups, ideal class groups of imaginary quadratic fields, and hyperelliptic Jacobians.

> 1665-bit discriminants (≈ 833-bit orders) provide security equivalent to 3072-bit RSA (i.e., 128-bit security)

![binary quadratic form](note/binary%20quadratic%20form.png)

![class number](note/class%20number.png)

Can be used in [Introduction]

[2] Dobson, Samuel, Steven Galbraith, and Benjamin Smith. "Trustless unknown-order groups." arXiv preprint arXiv:2211.16128 (2022).

> Normalization, Reduction, Composition (Multiply), Squaring

![composition](note/composition.png)

![composition algorithm](note/composition%20algorithm.png)

![squaring](note/squaring.png)

Can be used in [Introduction]

[3] Long, Lipa, and Chia Network. "Binary quadratic forms." Website, https://github.com/Chia-Network/vdf-competition/blob/master/classgroups.pdf (2018).

> IQ-DLP, IQ-OP, and IQ-RP appear to be hard problems.

![class number2](note/class%20number2.png)

[4] Buchmann, Johannes, and Safuat Hamdy. "A survey on IQ cryptography." Public-Key Cryptography and Computational Number Theory. 2001.

## Useful References
[1] <https://www.michaelstraka.com/posts/classgroups>

[2] <https://github.com/Chia-Network/vdf-competition/blob/master/classgroups.pdf>

## Commands
> go get google.golang.org/grpc

> go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.28

> go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.2

> export PATH="$PATH:$(go env GOPATH)/bin"

> protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative proposal.proto

> go get go.dedis.ch/dela/crypto/bls