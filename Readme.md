In /RandomnessBeacon3.0

> go get -u google.golang.org/grpc

> go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.28

> go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.2

> export PATH="$PATH:$(go env GOPATH)/bin"

> protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative setupMsg.proto

> sudo go build main.go setupMsgHadler.go

> ./main 0

# RandomnessBeacon

This project contains an implementation of the distributed randomness beacon proposed in `Practical Distributed Randomness Beacon with Optimal Communication Complexity`.

How to use:

1. To build the beacon distributed key generation (DKG), use the following commands: `cd dkg` and `sudo make build`.

2. To build the beacon nodes, use the following commands: `cd node` and `sudo make build`.

3. To start the beacon, use the following commands: `cd node` and `sudo sh start.sh`.

4. To stop the beacon use the following commands: `cd node` and `sudo sh end.sh`.
