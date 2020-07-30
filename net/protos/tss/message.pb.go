// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: net/protos/tss/message.proto

package pb

import (
	bytes "bytes"
	fmt "fmt"
	proto "github.com/gogo/protobuf/proto"
	io "io"
	math "math"
	math_bits "math/bits"
	reflect "reflect"
	strings "strings"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.GoGoProtoPackageIsVersion3 // please upgrade the proto package

type TSSProtocolMessage struct {
	SenderID    []byte `protobuf:"bytes,1,opt,name=senderID,proto3" json:"senderID,omitempty"`
	Payload     []byte `protobuf:"bytes,2,opt,name=payload,proto3" json:"payload,omitempty"`
	IsBroadcast bool   `protobuf:"varint,3,opt,name=isBroadcast,proto3" json:"isBroadcast,omitempty"`
	SessionID   string `protobuf:"bytes,4,opt,name=sessionID,proto3" json:"sessionID,omitempty"`
}

func (m *TSSProtocolMessage) Reset()      { *m = TSSProtocolMessage{} }
func (*TSSProtocolMessage) ProtoMessage() {}
func (*TSSProtocolMessage) Descriptor() ([]byte, []int) {
	return fileDescriptor_2c8720b58bd2f80c, []int{0}
}
func (m *TSSProtocolMessage) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *TSSProtocolMessage) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_TSSProtocolMessage.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *TSSProtocolMessage) XXX_Merge(src proto.Message) {
	xxx_messageInfo_TSSProtocolMessage.Merge(m, src)
}
func (m *TSSProtocolMessage) XXX_Size() int {
	return m.Size()
}
func (m *TSSProtocolMessage) XXX_DiscardUnknown() {
	xxx_messageInfo_TSSProtocolMessage.DiscardUnknown(m)
}

var xxx_messageInfo_TSSProtocolMessage proto.InternalMessageInfo

func (m *TSSProtocolMessage) GetSenderID() []byte {
	if m != nil {
		return m.SenderID
	}
	return nil
}

func (m *TSSProtocolMessage) GetPayload() []byte {
	if m != nil {
		return m.Payload
	}
	return nil
}

func (m *TSSProtocolMessage) GetIsBroadcast() bool {
	if m != nil {
		return m.IsBroadcast
	}
	return false
}

func (m *TSSProtocolMessage) GetSessionID() string {
	if m != nil {
		return m.SessionID
	}
	return ""
}

type ReadyMessage struct {
	SenderID []byte `protobuf:"bytes,1,opt,name=senderID,proto3" json:"senderID,omitempty"`
}

func (m *ReadyMessage) Reset()      { *m = ReadyMessage{} }
func (*ReadyMessage) ProtoMessage() {}
func (*ReadyMessage) Descriptor() ([]byte, []int) {
	return fileDescriptor_2c8720b58bd2f80c, []int{1}
}
func (m *ReadyMessage) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *ReadyMessage) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_ReadyMessage.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *ReadyMessage) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ReadyMessage.Merge(m, src)
}
func (m *ReadyMessage) XXX_Size() int {
	return m.Size()
}
func (m *ReadyMessage) XXX_DiscardUnknown() {
	xxx_messageInfo_ReadyMessage.DiscardUnknown(m)
}

var xxx_messageInfo_ReadyMessage proto.InternalMessageInfo

func (m *ReadyMessage) GetSenderID() []byte {
	if m != nil {
		return m.SenderID
	}
	return nil
}

type AnnounceMessage struct {
	SenderID []byte `protobuf:"bytes,1,opt,name=senderID,proto3" json:"senderID,omitempty"`
}

func (m *AnnounceMessage) Reset()      { *m = AnnounceMessage{} }
func (*AnnounceMessage) ProtoMessage() {}
func (*AnnounceMessage) Descriptor() ([]byte, []int) {
	return fileDescriptor_2c8720b58bd2f80c, []int{2}
}
func (m *AnnounceMessage) XXX_Unmarshal(b []byte) error {
	return m.Unmarshal(b)
}
func (m *AnnounceMessage) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	if deterministic {
		return xxx_messageInfo_AnnounceMessage.Marshal(b, m, deterministic)
	} else {
		b = b[:cap(b)]
		n, err := m.MarshalToSizedBuffer(b)
		if err != nil {
			return nil, err
		}
		return b[:n], nil
	}
}
func (m *AnnounceMessage) XXX_Merge(src proto.Message) {
	xxx_messageInfo_AnnounceMessage.Merge(m, src)
}
func (m *AnnounceMessage) XXX_Size() int {
	return m.Size()
}
func (m *AnnounceMessage) XXX_DiscardUnknown() {
	xxx_messageInfo_AnnounceMessage.DiscardUnknown(m)
}

var xxx_messageInfo_AnnounceMessage proto.InternalMessageInfo

func (m *AnnounceMessage) GetSenderID() []byte {
	if m != nil {
		return m.SenderID
	}
	return nil
}

func init() {
	proto.RegisterType((*TSSProtocolMessage)(nil), "tss.TSSProtocolMessage")
	proto.RegisterType((*ReadyMessage)(nil), "tss.ReadyMessage")
	proto.RegisterType((*AnnounceMessage)(nil), "tss.AnnounceMessage")
}

func init() { proto.RegisterFile("net/protos/tss/message.proto", fileDescriptor_2c8720b58bd2f80c) }

var fileDescriptor_2c8720b58bd2f80c = []byte{
	// 249 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0x92, 0xc9, 0x4b, 0x2d, 0xd1,
	0x2f, 0x28, 0xca, 0x2f, 0xc9, 0x2f, 0xd6, 0x2f, 0x29, 0x2e, 0xd6, 0xcf, 0x4d, 0x2d, 0x2e, 0x4e,
	0x4c, 0x4f, 0xd5, 0x03, 0x0b, 0x09, 0x31, 0x97, 0x14, 0x17, 0x2b, 0x75, 0x31, 0x72, 0x09, 0x85,
	0x04, 0x07, 0x07, 0x80, 0x44, 0x92, 0xf3, 0x73, 0x7c, 0x21, 0x2a, 0x84, 0xa4, 0xb8, 0x38, 0x8a,
	0x53, 0xf3, 0x52, 0x52, 0x8b, 0x3c, 0x5d, 0x24, 0x18, 0x15, 0x18, 0x35, 0x78, 0x82, 0xe0, 0x7c,
	0x21, 0x09, 0x2e, 0xf6, 0x82, 0xc4, 0xca, 0x9c, 0xfc, 0xc4, 0x14, 0x09, 0x26, 0xb0, 0x14, 0x8c,
	0x2b, 0xa4, 0xc0, 0xc5, 0x9d, 0x59, 0xec, 0x54, 0x94, 0x9f, 0x98, 0x92, 0x9c, 0x58, 0x5c, 0x22,
	0xc1, 0xac, 0xc0, 0xa8, 0xc1, 0x11, 0x84, 0x2c, 0x24, 0x24, 0xc3, 0xc5, 0x59, 0x9c, 0x5a, 0x5c,
	0x9c, 0x99, 0x9f, 0xe7, 0xe9, 0x22, 0xc1, 0xa2, 0xc0, 0xa8, 0xc1, 0x19, 0x84, 0x10, 0x50, 0xd2,
	0xe2, 0xe2, 0x09, 0x4a, 0x4d, 0x4c, 0xa9, 0x24, 0xc2, 0x15, 0x4a, 0xba, 0x5c, 0xfc, 0x8e, 0x79,
	0x79, 0xf9, 0xa5, 0x79, 0xc9, 0xa9, 0x44, 0x28, 0x77, 0xb2, 0xb8, 0xf0, 0x50, 0x8e, 0xe1, 0xc6,
	0x43, 0x39, 0x86, 0x0f, 0x0f, 0xe5, 0x18, 0x1b, 0x1e, 0xc9, 0x31, 0xae, 0x78, 0x24, 0xc7, 0x78,
	0xe2, 0x91, 0x1c, 0xe3, 0x85, 0x47, 0x72, 0x8c, 0x0f, 0x1e, 0xc9, 0x31, 0xbe, 0x78, 0x24, 0xc7,
	0xf0, 0xe1, 0x91, 0x1c, 0xe3, 0x84, 0xc7, 0x72, 0x0c, 0x17, 0x1e, 0xcb, 0x31, 0xdc, 0x78, 0x2c,
	0xc7, 0x10, 0xc5, 0x54, 0x90, 0x94, 0xc4, 0x06, 0x0e, 0x2d, 0x63, 0x40, 0x00, 0x00, 0x00, 0xff,
	0xff, 0xf7, 0xb3, 0x8b, 0x35, 0x4d, 0x01, 0x00, 0x00,
}

func (this *TSSProtocolMessage) Equal(that interface{}) bool {
	if that == nil {
		return this == nil
	}

	that1, ok := that.(*TSSProtocolMessage)
	if !ok {
		that2, ok := that.(TSSProtocolMessage)
		if ok {
			that1 = &that2
		} else {
			return false
		}
	}
	if that1 == nil {
		return this == nil
	} else if this == nil {
		return false
	}
	if !bytes.Equal(this.SenderID, that1.SenderID) {
		return false
	}
	if !bytes.Equal(this.Payload, that1.Payload) {
		return false
	}
	if this.IsBroadcast != that1.IsBroadcast {
		return false
	}
	if this.SessionID != that1.SessionID {
		return false
	}
	return true
}
func (this *ReadyMessage) Equal(that interface{}) bool {
	if that == nil {
		return this == nil
	}

	that1, ok := that.(*ReadyMessage)
	if !ok {
		that2, ok := that.(ReadyMessage)
		if ok {
			that1 = &that2
		} else {
			return false
		}
	}
	if that1 == nil {
		return this == nil
	} else if this == nil {
		return false
	}
	if !bytes.Equal(this.SenderID, that1.SenderID) {
		return false
	}
	return true
}
func (this *AnnounceMessage) Equal(that interface{}) bool {
	if that == nil {
		return this == nil
	}

	that1, ok := that.(*AnnounceMessage)
	if !ok {
		that2, ok := that.(AnnounceMessage)
		if ok {
			that1 = &that2
		} else {
			return false
		}
	}
	if that1 == nil {
		return this == nil
	} else if this == nil {
		return false
	}
	if !bytes.Equal(this.SenderID, that1.SenderID) {
		return false
	}
	return true
}
func (this *TSSProtocolMessage) GoString() string {
	if this == nil {
		return "nil"
	}
	s := make([]string, 0, 8)
	s = append(s, "&pb.TSSProtocolMessage{")
	s = append(s, "SenderID: "+fmt.Sprintf("%#v", this.SenderID)+",\n")
	s = append(s, "Payload: "+fmt.Sprintf("%#v", this.Payload)+",\n")
	s = append(s, "IsBroadcast: "+fmt.Sprintf("%#v", this.IsBroadcast)+",\n")
	s = append(s, "SessionID: "+fmt.Sprintf("%#v", this.SessionID)+",\n")
	s = append(s, "}")
	return strings.Join(s, "")
}
func (this *ReadyMessage) GoString() string {
	if this == nil {
		return "nil"
	}
	s := make([]string, 0, 5)
	s = append(s, "&pb.ReadyMessage{")
	s = append(s, "SenderID: "+fmt.Sprintf("%#v", this.SenderID)+",\n")
	s = append(s, "}")
	return strings.Join(s, "")
}
func (this *AnnounceMessage) GoString() string {
	if this == nil {
		return "nil"
	}
	s := make([]string, 0, 5)
	s = append(s, "&pb.AnnounceMessage{")
	s = append(s, "SenderID: "+fmt.Sprintf("%#v", this.SenderID)+",\n")
	s = append(s, "}")
	return strings.Join(s, "")
}
func valueToGoStringMessage(v interface{}, typ string) string {
	rv := reflect.ValueOf(v)
	if rv.IsNil() {
		return "nil"
	}
	pv := reflect.Indirect(rv).Interface()
	return fmt.Sprintf("func(v %v) *%v { return &v } ( %#v )", typ, typ, pv)
}
func (m *TSSProtocolMessage) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *TSSProtocolMessage) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *TSSProtocolMessage) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if len(m.SessionID) > 0 {
		i -= len(m.SessionID)
		copy(dAtA[i:], m.SessionID)
		i = encodeVarintMessage(dAtA, i, uint64(len(m.SessionID)))
		i--
		dAtA[i] = 0x22
	}
	if m.IsBroadcast {
		i--
		if m.IsBroadcast {
			dAtA[i] = 1
		} else {
			dAtA[i] = 0
		}
		i--
		dAtA[i] = 0x18
	}
	if len(m.Payload) > 0 {
		i -= len(m.Payload)
		copy(dAtA[i:], m.Payload)
		i = encodeVarintMessage(dAtA, i, uint64(len(m.Payload)))
		i--
		dAtA[i] = 0x12
	}
	if len(m.SenderID) > 0 {
		i -= len(m.SenderID)
		copy(dAtA[i:], m.SenderID)
		i = encodeVarintMessage(dAtA, i, uint64(len(m.SenderID)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *ReadyMessage) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *ReadyMessage) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *ReadyMessage) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if len(m.SenderID) > 0 {
		i -= len(m.SenderID)
		copy(dAtA[i:], m.SenderID)
		i = encodeVarintMessage(dAtA, i, uint64(len(m.SenderID)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func (m *AnnounceMessage) Marshal() (dAtA []byte, err error) {
	size := m.Size()
	dAtA = make([]byte, size)
	n, err := m.MarshalToSizedBuffer(dAtA[:size])
	if err != nil {
		return nil, err
	}
	return dAtA[:n], nil
}

func (m *AnnounceMessage) MarshalTo(dAtA []byte) (int, error) {
	size := m.Size()
	return m.MarshalToSizedBuffer(dAtA[:size])
}

func (m *AnnounceMessage) MarshalToSizedBuffer(dAtA []byte) (int, error) {
	i := len(dAtA)
	_ = i
	var l int
	_ = l
	if len(m.SenderID) > 0 {
		i -= len(m.SenderID)
		copy(dAtA[i:], m.SenderID)
		i = encodeVarintMessage(dAtA, i, uint64(len(m.SenderID)))
		i--
		dAtA[i] = 0xa
	}
	return len(dAtA) - i, nil
}

func encodeVarintMessage(dAtA []byte, offset int, v uint64) int {
	offset -= sovMessage(v)
	base := offset
	for v >= 1<<7 {
		dAtA[offset] = uint8(v&0x7f | 0x80)
		v >>= 7
		offset++
	}
	dAtA[offset] = uint8(v)
	return base
}
func (m *TSSProtocolMessage) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.SenderID)
	if l > 0 {
		n += 1 + l + sovMessage(uint64(l))
	}
	l = len(m.Payload)
	if l > 0 {
		n += 1 + l + sovMessage(uint64(l))
	}
	if m.IsBroadcast {
		n += 2
	}
	l = len(m.SessionID)
	if l > 0 {
		n += 1 + l + sovMessage(uint64(l))
	}
	return n
}

func (m *ReadyMessage) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.SenderID)
	if l > 0 {
		n += 1 + l + sovMessage(uint64(l))
	}
	return n
}

func (m *AnnounceMessage) Size() (n int) {
	if m == nil {
		return 0
	}
	var l int
	_ = l
	l = len(m.SenderID)
	if l > 0 {
		n += 1 + l + sovMessage(uint64(l))
	}
	return n
}

func sovMessage(x uint64) (n int) {
	return (math_bits.Len64(x|1) + 6) / 7
}
func sozMessage(x uint64) (n int) {
	return sovMessage(uint64((x << 1) ^ uint64((int64(x) >> 63))))
}
func (this *TSSProtocolMessage) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&TSSProtocolMessage{`,
		`SenderID:` + fmt.Sprintf("%v", this.SenderID) + `,`,
		`Payload:` + fmt.Sprintf("%v", this.Payload) + `,`,
		`IsBroadcast:` + fmt.Sprintf("%v", this.IsBroadcast) + `,`,
		`SessionID:` + fmt.Sprintf("%v", this.SessionID) + `,`,
		`}`,
	}, "")
	return s
}
func (this *ReadyMessage) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&ReadyMessage{`,
		`SenderID:` + fmt.Sprintf("%v", this.SenderID) + `,`,
		`}`,
	}, "")
	return s
}
func (this *AnnounceMessage) String() string {
	if this == nil {
		return "nil"
	}
	s := strings.Join([]string{`&AnnounceMessage{`,
		`SenderID:` + fmt.Sprintf("%v", this.SenderID) + `,`,
		`}`,
	}, "")
	return s
}
func valueToStringMessage(v interface{}) string {
	rv := reflect.ValueOf(v)
	if rv.IsNil() {
		return "nil"
	}
	pv := reflect.Indirect(rv).Interface()
	return fmt.Sprintf("*%v", pv)
}
func (m *TSSProtocolMessage) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowMessage
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: TSSProtocolMessage: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: TSSProtocolMessage: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field SenderID", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMessage
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthMessage
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthMessage
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.SenderID = append(m.SenderID[:0], dAtA[iNdEx:postIndex]...)
			if m.SenderID == nil {
				m.SenderID = []byte{}
			}
			iNdEx = postIndex
		case 2:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field Payload", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMessage
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthMessage
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthMessage
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.Payload = append(m.Payload[:0], dAtA[iNdEx:postIndex]...)
			if m.Payload == nil {
				m.Payload = []byte{}
			}
			iNdEx = postIndex
		case 3:
			if wireType != 0 {
				return fmt.Errorf("proto: wrong wireType = %d for field IsBroadcast", wireType)
			}
			var v int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMessage
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				v |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			m.IsBroadcast = bool(v != 0)
		case 4:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field SessionID", wireType)
			}
			var stringLen uint64
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMessage
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				stringLen |= uint64(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			intStringLen := int(stringLen)
			if intStringLen < 0 {
				return ErrInvalidLengthMessage
			}
			postIndex := iNdEx + intStringLen
			if postIndex < 0 {
				return ErrInvalidLengthMessage
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.SessionID = string(dAtA[iNdEx:postIndex])
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipMessage(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthMessage
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthMessage
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *ReadyMessage) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowMessage
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: ReadyMessage: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: ReadyMessage: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field SenderID", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMessage
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthMessage
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthMessage
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.SenderID = append(m.SenderID[:0], dAtA[iNdEx:postIndex]...)
			if m.SenderID == nil {
				m.SenderID = []byte{}
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipMessage(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthMessage
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthMessage
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func (m *AnnounceMessage) Unmarshal(dAtA []byte) error {
	l := len(dAtA)
	iNdEx := 0
	for iNdEx < l {
		preIndex := iNdEx
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return ErrIntOverflowMessage
			}
			if iNdEx >= l {
				return io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= uint64(b&0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		fieldNum := int32(wire >> 3)
		wireType := int(wire & 0x7)
		if wireType == 4 {
			return fmt.Errorf("proto: AnnounceMessage: wiretype end group for non-group")
		}
		if fieldNum <= 0 {
			return fmt.Errorf("proto: AnnounceMessage: illegal tag %d (wire type %d)", fieldNum, wire)
		}
		switch fieldNum {
		case 1:
			if wireType != 2 {
				return fmt.Errorf("proto: wrong wireType = %d for field SenderID", wireType)
			}
			var byteLen int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return ErrIntOverflowMessage
				}
				if iNdEx >= l {
					return io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				byteLen |= int(b&0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if byteLen < 0 {
				return ErrInvalidLengthMessage
			}
			postIndex := iNdEx + byteLen
			if postIndex < 0 {
				return ErrInvalidLengthMessage
			}
			if postIndex > l {
				return io.ErrUnexpectedEOF
			}
			m.SenderID = append(m.SenderID[:0], dAtA[iNdEx:postIndex]...)
			if m.SenderID == nil {
				m.SenderID = []byte{}
			}
			iNdEx = postIndex
		default:
			iNdEx = preIndex
			skippy, err := skipMessage(dAtA[iNdEx:])
			if err != nil {
				return err
			}
			if skippy < 0 {
				return ErrInvalidLengthMessage
			}
			if (iNdEx + skippy) < 0 {
				return ErrInvalidLengthMessage
			}
			if (iNdEx + skippy) > l {
				return io.ErrUnexpectedEOF
			}
			iNdEx += skippy
		}
	}

	if iNdEx > l {
		return io.ErrUnexpectedEOF
	}
	return nil
}
func skipMessage(dAtA []byte) (n int, err error) {
	l := len(dAtA)
	iNdEx := 0
	depth := 0
	for iNdEx < l {
		var wire uint64
		for shift := uint(0); ; shift += 7 {
			if shift >= 64 {
				return 0, ErrIntOverflowMessage
			}
			if iNdEx >= l {
				return 0, io.ErrUnexpectedEOF
			}
			b := dAtA[iNdEx]
			iNdEx++
			wire |= (uint64(b) & 0x7F) << shift
			if b < 0x80 {
				break
			}
		}
		wireType := int(wire & 0x7)
		switch wireType {
		case 0:
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowMessage
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				iNdEx++
				if dAtA[iNdEx-1] < 0x80 {
					break
				}
			}
		case 1:
			iNdEx += 8
		case 2:
			var length int
			for shift := uint(0); ; shift += 7 {
				if shift >= 64 {
					return 0, ErrIntOverflowMessage
				}
				if iNdEx >= l {
					return 0, io.ErrUnexpectedEOF
				}
				b := dAtA[iNdEx]
				iNdEx++
				length |= (int(b) & 0x7F) << shift
				if b < 0x80 {
					break
				}
			}
			if length < 0 {
				return 0, ErrInvalidLengthMessage
			}
			iNdEx += length
		case 3:
			depth++
		case 4:
			if depth == 0 {
				return 0, ErrUnexpectedEndOfGroupMessage
			}
			depth--
		case 5:
			iNdEx += 4
		default:
			return 0, fmt.Errorf("proto: illegal wireType %d", wireType)
		}
		if iNdEx < 0 {
			return 0, ErrInvalidLengthMessage
		}
		if depth == 0 {
			return iNdEx, nil
		}
	}
	return 0, io.ErrUnexpectedEOF
}

var (
	ErrInvalidLengthMessage        = fmt.Errorf("proto: negative length found during unmarshaling")
	ErrIntOverflowMessage          = fmt.Errorf("proto: integer overflow")
	ErrUnexpectedEndOfGroupMessage = fmt.Errorf("proto: unexpected end of group")
)
