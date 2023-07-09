// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        v3.12.4
// source: helloMsg.proto

package helloMsgpb

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// The request message containing the user's name.
type HelloMsg struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	HelloMsg string `protobuf:"bytes,1,opt,name=helloMsg,proto3" json:"helloMsg,omitempty"`
}

func (x *HelloMsg) Reset() {
	*x = HelloMsg{}
	if protoimpl.UnsafeEnabled {
		mi := &file_helloMsg_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *HelloMsg) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HelloMsg) ProtoMessage() {}

func (x *HelloMsg) ProtoReflect() protoreflect.Message {
	mi := &file_helloMsg_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use HelloMsg.ProtoReflect.Descriptor instead.
func (*HelloMsg) Descriptor() ([]byte, []int) {
	return file_helloMsg_proto_rawDescGZIP(), []int{0}
}

func (x *HelloMsg) GetHelloMsg() string {
	if x != nil {
		return x.HelloMsg
	}
	return ""
}

type HelloMsgResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *HelloMsgResponse) Reset() {
	*x = HelloMsgResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_helloMsg_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *HelloMsgResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HelloMsgResponse) ProtoMessage() {}

func (x *HelloMsgResponse) ProtoReflect() protoreflect.Message {
	mi := &file_helloMsg_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use HelloMsgResponse.ProtoReflect.Descriptor instead.
func (*HelloMsgResponse) Descriptor() ([]byte, []int) {
	return file_helloMsg_proto_rawDescGZIP(), []int{1}
}

var File_helloMsg_proto protoreflect.FileDescriptor

var file_helloMsg_proto_rawDesc = []byte{
	0x0a, 0x0e, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x4d, 0x73, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x12, 0x0a, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x4d, 0x73, 0x67, 0x70, 0x62, 0x22, 0x26, 0x0a, 0x08,
	0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x4d, 0x73, 0x67, 0x12, 0x1a, 0x0a, 0x08, 0x68, 0x65, 0x6c, 0x6c,
	0x6f, 0x4d, 0x73, 0x67, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x08, 0x68, 0x65, 0x6c, 0x6c,
	0x6f, 0x4d, 0x73, 0x67, 0x22, 0x12, 0x0a, 0x10, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x4d, 0x73, 0x67,
	0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x32, 0x59, 0x0a, 0x0e, 0x48, 0x65, 0x6c, 0x6c,
	0x6f, 0x4d, 0x73, 0x67, 0x48, 0x61, 0x6e, 0x64, 0x6c, 0x65, 0x12, 0x47, 0x0a, 0x0f, 0x48, 0x65,
	0x6c, 0x6c, 0x6f, 0x4d, 0x73, 0x67, 0x52, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x12, 0x14, 0x2e,
	0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x4d, 0x73, 0x67, 0x70, 0x62, 0x2e, 0x48, 0x65, 0x6c, 0x6c, 0x6f,
	0x4d, 0x73, 0x67, 0x1a, 0x1c, 0x2e, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x4d, 0x73, 0x67, 0x70, 0x62,
	0x2e, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x4d, 0x73, 0x67, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
	0x65, 0x22, 0x00, 0x42, 0x0f, 0x5a, 0x0d, 0x2e, 0x2e, 0x2f, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x4d,
	0x73, 0x67, 0x70, 0x62, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_helloMsg_proto_rawDescOnce sync.Once
	file_helloMsg_proto_rawDescData = file_helloMsg_proto_rawDesc
)

func file_helloMsg_proto_rawDescGZIP() []byte {
	file_helloMsg_proto_rawDescOnce.Do(func() {
		file_helloMsg_proto_rawDescData = protoimpl.X.CompressGZIP(file_helloMsg_proto_rawDescData)
	})
	return file_helloMsg_proto_rawDescData
}

var file_helloMsg_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_helloMsg_proto_goTypes = []interface{}{
	(*HelloMsg)(nil),         // 0: helloMsgpb.HelloMsg
	(*HelloMsgResponse)(nil), // 1: helloMsgpb.HelloMsgResponse
}
var file_helloMsg_proto_depIdxs = []int32{
	0, // 0: helloMsgpb.HelloMsgHandle.HelloMsgReceive:input_type -> helloMsgpb.HelloMsg
	1, // 1: helloMsgpb.HelloMsgHandle.HelloMsgReceive:output_type -> helloMsgpb.HelloMsgResponse
	1, // [1:2] is the sub-list for method output_type
	0, // [0:1] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_helloMsg_proto_init() }
func file_helloMsg_proto_init() {
	if File_helloMsg_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_helloMsg_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*HelloMsg); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_helloMsg_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*HelloMsgResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_helloMsg_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_helloMsg_proto_goTypes,
		DependencyIndexes: file_helloMsg_proto_depIdxs,
		MessageInfos:      file_helloMsg_proto_msgTypes,
	}.Build()
	File_helloMsg_proto = out.File
	file_helloMsg_proto_rawDesc = nil
	file_helloMsg_proto_goTypes = nil
	file_helloMsg_proto_depIdxs = nil
}