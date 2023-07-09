package main

import (
	"context"
	"fmt"
	"net"
	"node/helloMsgpb"
	"os"
	"strconv"

	"google.golang.org/grpc"
)

// helloMsgServer is used to implement helloMsgpb.HelloMsgReceive
type helloMsgServer struct {
	helloMsgpb.UnimplementedHelloMsgHandleServer
}

// helloMsgReceive implements helloMsgpb.HelloMsgReceive
func (hs *helloMsgServer) HelloMsgReceive(ctx context.Context, in *helloMsgpb.HelloMsg) (*helloMsgpb.HelloMsgResponse, error) {
	fmt.Println(in.GetHelloMsg())

	return &helloMsgpb.HelloMsgResponse{}, nil
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
	helloMsgpb.RegisterHelloMsgHandleServer(ps, &helloMsgServer{})
	go ps.Serve(lis)
	fmt.Printf("===>[Collector]Collector is listening at %v\n", lis.Addr())

	for {

	}
}
