// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.2.0
// - protoc             v3.12.4
// source: blankReplyMsg.proto

package blankReplyMsgpb

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// BlankReplyMsgHandleClient is the client API for BlankReplyMsgHandle service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type BlankReplyMsgHandleClient interface {
	// Handles a received BlankReplyMsg message
	BlankReplyMsgReceive(ctx context.Context, in *BlankReplyMsg, opts ...grpc.CallOption) (*BlankReplyMsgResponse, error)
}

type blankReplyMsgHandleClient struct {
	cc grpc.ClientConnInterface
}

func NewBlankReplyMsgHandleClient(cc grpc.ClientConnInterface) BlankReplyMsgHandleClient {
	return &blankReplyMsgHandleClient{cc}
}

func (c *blankReplyMsgHandleClient) BlankReplyMsgReceive(ctx context.Context, in *BlankReplyMsg, opts ...grpc.CallOption) (*BlankReplyMsgResponse, error) {
	out := new(BlankReplyMsgResponse)
	err := c.cc.Invoke(ctx, "/blankReplyMsgpb.BlankReplyMsgHandle/BlankReplyMsgReceive", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// BlankReplyMsgHandleServer is the server API for BlankReplyMsgHandle service.
// All implementations must embed UnimplementedBlankReplyMsgHandleServer
// for forward compatibility
type BlankReplyMsgHandleServer interface {
	// Handles a received BlankReplyMsg message
	BlankReplyMsgReceive(context.Context, *BlankReplyMsg) (*BlankReplyMsgResponse, error)
	mustEmbedUnimplementedBlankReplyMsgHandleServer()
}

// UnimplementedBlankReplyMsgHandleServer must be embedded to have forward compatible implementations.
type UnimplementedBlankReplyMsgHandleServer struct {
}

func (UnimplementedBlankReplyMsgHandleServer) BlankReplyMsgReceive(context.Context, *BlankReplyMsg) (*BlankReplyMsgResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method BlankReplyMsgReceive not implemented")
}
func (UnimplementedBlankReplyMsgHandleServer) mustEmbedUnimplementedBlankReplyMsgHandleServer() {}

// UnsafeBlankReplyMsgHandleServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to BlankReplyMsgHandleServer will
// result in compilation errors.
type UnsafeBlankReplyMsgHandleServer interface {
	mustEmbedUnimplementedBlankReplyMsgHandleServer()
}

func RegisterBlankReplyMsgHandleServer(s grpc.ServiceRegistrar, srv BlankReplyMsgHandleServer) {
	s.RegisterService(&BlankReplyMsgHandle_ServiceDesc, srv)
}

func _BlankReplyMsgHandle_BlankReplyMsgReceive_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(BlankReplyMsg)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(BlankReplyMsgHandleServer).BlankReplyMsgReceive(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/blankReplyMsgpb.BlankReplyMsgHandle/BlankReplyMsgReceive",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(BlankReplyMsgHandleServer).BlankReplyMsgReceive(ctx, req.(*BlankReplyMsg))
	}
	return interceptor(ctx, in, info, handler)
}

// BlankReplyMsgHandle_ServiceDesc is the grpc.ServiceDesc for BlankReplyMsgHandle service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var BlankReplyMsgHandle_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "blankReplyMsgpb.BlankReplyMsgHandle",
	HandlerType: (*BlankReplyMsgHandleServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "BlankReplyMsgReceive",
			Handler:    _BlankReplyMsgHandle_BlankReplyMsgReceive_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "blankReplyMsg.proto",
}