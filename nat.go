package conntrack

import (
	"fmt"
	"log"
	"net"

	"github.com/mdlayher/netlink"
	"github.com/pkg/errors"
	"github.com/ti-mo/netfilter"
)

const (
	opUnNat      = "NAT unmarshal"
	opUnNatBadIP = "NAT unmarshal bad IPs"
	opUnNatProto = "NAT proto unmarshal"
)

var (
	errIncorrectIPFieldSize = errors.New("binary attribute data for IP address has incorrect size")
)

type NatMetadata struct {
	MinIPv4  net.IP
	MaxIPv4  net.IP
	MinIPv6  net.IP
	MaxIPv6  net.IP
	Proto    NatMetadataProto
	TraceMsg string
}

type NatMetadataProto struct {
	PortMin uint16
	PortMax uint16
}

// filled returns true if the NatMetadata instance contains at least one IP address
func (n NatMetadata) filled() bool {
	return n.MinIPv4.To4() != nil || n.MaxIPv4.To4() != nil || n.MinIPv6.To16() != nil || n.MaxIPv6.To16() != nil
}

func (n NatMetadata) marshal(at uint16) (netfilter.Attribute, error) {
	nfa := netfilter.Attribute{Type: at, Nested: true, Children: make([]netfilter.Attribute, 0, 5)}

	// Marshal only IPv4 if both protocols are present. (This behaviour aligns
	// with kernel logic.)
	if n.MinIPv4.To4() != nil || n.MaxIPv4.To4() != nil {
		if n.MinIPv4.To4() != nil {
			nfa.Children = append(nfa.Children, netfilter.Attribute{NetByteOrder: true, Type: uint16(ctaNatV4MinIP), Data: n.MinIPv4.To4()})
		}
		if n.MaxIPv4.To4() != nil {
			nfa.Children = append(nfa.Children, netfilter.Attribute{NetByteOrder: true, Type: uint16(ctaNatV4MaxIP), Data: n.MaxIPv4.To4()})
		}
	} else {
		if n.MinIPv6.To16() != nil {
			nfa.Children = append(nfa.Children, netfilter.Attribute{NetByteOrder: true, Type: uint16(ctaNatV6MinIP), Data: n.MinIPv6.To16()})
		}
		if n.MaxIPv6.To16() != nil {
			nfa.Children = append(nfa.Children, netfilter.Attribute{NetByteOrder: true, Type: uint16(ctaNatV6MaxIP), Data: n.MaxIPv6.To16()})
		}
	}

	if n.Proto.filled() {
		natProto, err := n.Proto.marshal()
		if err != nil {
			// log.Printf("[NatMetadata/marshal] DEBUG - nfa: %v - ERROR marshaling n.Proto: %q", nfa, err)
			return netfilter.Attribute{}, err
		}
		nfa.Children = append(nfa.Children, natProto)
	}
	// log.Printf("[NatMetadata/marshal] DEBUG - n.Proto.filled() reports: %t", n.Proto.filled())
	// log.Printf("[NatMetadata/marshal] DEBUG - nfa: %+v", nfa)
	return nfa, nil
}

func (n *NatMetadata) unmarshal(ad *netlink.AttributeDecoder) error {
	if ad.Len() < 1 {
		// log.Fatalf("[NatMetadata/unmarshal] ERROR - no child attributes found")
		n.TraceMsg = errNeedChildren.Error()
		return errors.Wrap(errNeedChildren, opUnNat)
	}

	var b []byte

	for ad.Next() {

		if natType(ad.Type()) != ctaNatProto {
			b = ad.Bytes()
			if len(b) != 4 && len(b) != 16 {
				log.Fatalf("[NatMetadata/unmarshal] DEBUG - n: %v - ERROR - incorrect IP field size", n)
				n.TraceMsg = errIncorrectIPFieldSize.Error()
				return errIncorrectIPFieldSize
			}
		}

		b = ad.Bytes()

		switch natType(ad.Type()) {
		case ctaNatUnspec:
			// No action to take?
		case ctaNatV4MinIP:
			n.MinIPv4 = net.IPv4(b[0], b[1], b[2], b[3])
		case ctaNatV4MaxIP:
			n.MaxIPv4 = net.IPv4(b[0], b[1], b[2], b[3])
		case ctaNatV6MinIP:
			n.MinIPv6 = net.IP(b)
		case ctaNatV6MaxIP:
			n.MaxIPv6 = net.IP(b)
		case ctaNatProto:
			var natProto NatMetadataProto
			ad.Nested(natProto.unmarshal)
			n.Proto = natProto
		default:
			n.TraceMsg = "hit default case for natType"
			// log.Fatalf("[NatMetadata/unmarshal] DEBUG - n: %v - ERROR - hit default case!", n)
			return errors.Wrap(fmt.Errorf(errAttributeChild, ad.Type()), opUnNat)
		}
	}
	log.Printf("[NatMetadata/unmarshal] DEBUG - n: %+v", n)
	return ad.Err()
}

// String returns a string representation of a NatMetadata.
func (n NatMetadata) String() string {
	// TODO: parse IPv4/IPv6 addresses
	return fmt.Sprintf("<TraceMsg: %q MinIPv4:%s MaxIPv4:%s MinIPv6:%s MaxIPv6:%s NatProto:%s>",
		n.TraceMsg, n.MinIPv4, n.MaxIPv4, n.MinIPv6, n.MaxIPv6, n.Proto,
	)
}

// filled returns true if the NatMetadataProto instance has at least one port defined
func (np NatMetadataProto) filled() bool {
	return np.PortMin != 0 || np.PortMax != 0
}

// marshal ...
func (np NatMetadataProto) marshal() (netfilter.Attribute, error) {
	// marshal is called only if at least one port is defined
	nfa := netfilter.Attribute{Type: uint16(ctaNatProto), Nested: true, Children: make([]netfilter.Attribute, 0)}

	if np.PortMin != 0 {
		nfa.Children = append(nfa.Children, netfilter.Attribute{NetByteOrder: true, Type: uint16(ctaProtoNatPortMin), Data: netfilter.Uint16Bytes(np.PortMin)})
	}
	if np.PortMax != 0 {
		nfa.Children = append(nfa.Children, netfilter.Attribute{NetByteOrder: true, Type: uint16(ctaProtoNatPortMax), Data: netfilter.Uint16Bytes(np.PortMax)})
	}
	log.Printf("[NatMetadataProto/marshal] DEBUG - n: %+v", np)
	return nfa, nil
}

// unmarshal ...
func (np *NatMetadataProto) unmarshal(ad *netlink.AttributeDecoder) error {
	if ad.Len() < 1 {
		// log.Println("[NatMetadataProto/unmarshal] ERROR - no child attributes found")
		return errors.Wrap(errNeedChildren, opUnNatProto)
	}
	for ad.Next() {
		switch protoNatType(ad.Type()) {
		case ctaProtoNatUnspec:
			// No action to take?
		case ctaProtoNatPortMin:
			np.PortMin = ad.Uint16()
			// np.PortMin = 12345
		case ctaProtoNatPortMax:
			np.PortMax = ad.Uint16()
			// np.PortMax = 54321
		default:
			log.Printf("[NatMetadataProto/unmarshal] DEBUG - np: %v - ERROR - hit default case!", np)
			return errors.Wrap(fmt.Errorf(errAttributeChild, ad.Type()), opUnNatProto)
		}
	}
	// log.Printf("[NatMetadataProto/unmarshal] DEBUG - n: %+v", np)
	return ad.Err()
}

// String returns a string representation of a NatMetadata.
func (np NatMetadataProto) String() string {
	// TODO: parse port numbers
	return fmt.Sprintf("<PortMin:%d, PortMax:%d>", np.PortMin, np.PortMax)
}

// enrichFlowNat conditionally populates NatSrc/NatDst fields based
// on the flow status field, behaviour similar to libnetfilter-conntrack's
// nfct_nlmsg_build().
//
// FIXME: implement actual logic for various NAT scenarios (DNAT, DPAT, SNAT, SPAT)
//
func enrichFlowNat(f *Flow) error {
	// Exit early if Flow.Status indicates this is not a NAT flow
	if (f.Status.Value&StatusNATMask == 0) &&
		(f.Status.Value&StatusNATDoneMask == 0) {
		return nil
	}

	var natSrc NatMetadata
	// var natDst NatMetadata
	// var natSrcProto NatMetadataProto
	// var natDstProto NatMetadataProto

	// Marshal only IPv4 if both protocols are present. (This behaviour aligns
	// with kernel logic.)
	// Ref: libnetfilter-conntrack's setobjopt_undo_snat()
	if f.TupleReply.IP.SourceAddress.To4() != nil {
		natSrc.MinIPv4 = f.TupleReply.IP.DestinationAddress.To4()
		natSrc.MaxIPv4 = natSrc.MinIPv4
		// natDst.MinIPv4 = f.TupleReply.IP.SourceAddress.To4()
		// natDst.MaxIPv4 = natDst.MinIPv4
	} else if f.TupleReply.IP.SourceAddress.To16() != nil {
		natSrc.MinIPv6 = f.TupleReply.IP.DestinationAddress.To16()
		natSrc.MaxIPv6 = natSrc.MinIPv6
		// 	natDst.MinIPv6 = f.TupleReply.IP.SourceAddress.To16()
		// 	natDst.MaxIPv6 = natDst.MinIPv6
	}
	// natSrcProto.PortMin = f.TupleOrig.Proto.DestinationPort
	// natSrcProto.PortMax = natSrcProto.PortMin
	// natSrc.Proto = natSrcProto

	// natDstProto.PortMin = f.TupleReply.Proto.DestinationPort
	// natDstProto.PortMax = natDstProto.PortMin
	// natDst.Proto = natDstProto

	f.NatSrc = natSrc
	// f.NatDst = natDst

	return nil
}
