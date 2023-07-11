// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.1
// 	protoc        v3.12.4
// source: rMsg.proto

package rMsgpb

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

type RMsg struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	R0 string `protobuf:"bytes,1,opt,name=r0,proto3" json:"r0,omitempty"`
}

func (x *RMsg) Reset() {
	*x = RMsg{}
	if protoimpl.UnsafeEnabled {
		mi := &file_rMsg_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RMsg) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RMsg) ProtoMessage() {}

func (x *RMsg) ProtoReflect() protoreflect.Message {
	mi := &file_rMsg_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RMsg.ProtoReflect.Descriptor instead.
func (*RMsg) Descriptor() ([]byte, []int) {
	return file_rMsg_proto_rawDescGZIP(), []int{0}
}

func (x *RMsg) GetR0() string {
	if x != nil {
		return x.R0
	}
	return ""
}

type RMsgResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *RMsgResponse) Reset() {
	*x = RMsgResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_rMsg_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RMsgResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RMsgResponse) ProtoMessage() {}

func (x *RMsgResponse) ProtoReflect() protoreflect.Message {
	mi := &file_rMsg_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RMsgResponse.ProtoReflect.Descriptor instead.
func (*RMsgResponse) Descriptor() ([]byte, []int) {
	return file_rMsg_proto_rawDescGZIP(), []int{1}
}

var File_rMsg_proto protoreflect.FileDescriptor

var file_rMsg_proto_rawDesc = []byte{
	0x0a, 0x0a, 0x72, 0x4d, 0x73, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x06, 0x72, 0x4d,
	0x73, 0x67, 0x70, 0x62, 0x22, 0x16, 0x0a, 0x04, 0x52, 0x4d, 0x73, 0x67, 0x12, 0x0e, 0x0a, 0x02,
	0x72, 0x30, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x72, 0x30, 0x22, 0x0e, 0x0a, 0x0c,
	0x52, 0x4d, 0x73, 0x67, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x32, 0x41, 0x0a, 0x0a,
	0x52, 0x4d, 0x73, 0x67, 0x48, 0x61, 0x6e, 0x64, 0x6c, 0x65, 0x12, 0x33, 0x0a, 0x0b, 0x52, 0x4d,
	0x73, 0x67, 0x52, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65, 0x12, 0x0c, 0x2e, 0x72, 0x4d, 0x73, 0x67,
	0x70, 0x62, 0x2e, 0x52, 0x4d, 0x73, 0x67, 0x1a, 0x14, 0x2e, 0x72, 0x4d, 0x73, 0x67, 0x70, 0x62,
	0x2e, 0x52, 0x4d, 0x73, 0x67, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x00, 0x42,
	0x0b, 0x5a, 0x09, 0x2e, 0x2e, 0x2f, 0x72, 0x4d, 0x73, 0x67, 0x70, 0x62, 0x62, 0x06, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_rMsg_proto_rawDescOnce sync.Once
	file_rMsg_proto_rawDescData = file_rMsg_proto_rawDesc
)

func file_rMsg_proto_rawDescGZIP() []byte {
	file_rMsg_proto_rawDescOnce.Do(func() {
		file_rMsg_proto_rawDescData = protoimpl.X.CompressGZIP(file_rMsg_proto_rawDescData)
	})
	return file_rMsg_proto_rawDescData
}

var file_rMsg_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_rMsg_proto_goTypes = []interface{}{
	(*RMsg)(nil),         // 0: rMsgpb.RMsg
	(*RMsgResponse)(nil), // 1: rMsgpb.RMsgResponse
}
var file_rMsg_proto_depIdxs = []int32{
	0, // 0: rMsgpb.RMsgHandle.RMsgReceive:input_type -> rMsgpb.RMsg
	1, // 1: rMsgpb.RMsgHandle.RMsgReceive:output_type -> rMsgpb.RMsgResponse
	1, // [1:2] is the sub-list for method output_type
	0, // [0:1] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_rMsg_proto_init() }
func file_rMsg_proto_init() {
	if File_rMsg_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_rMsg_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RMsg); i {
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
		file_rMsg_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RMsgResponse); i {
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
			RawDescriptor: file_rMsg_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_rMsg_proto_goTypes,
		DependencyIndexes: file_rMsg_proto_depIdxs,
		MessageInfos:      file_rMsg_proto_msgTypes,
	}.Build()
	File_rMsg_proto = out.File
	file_rMsg_proto_rawDesc = nil
	file_rMsg_proto_goTypes = nil
	file_rMsg_proto_depIdxs = nil
}