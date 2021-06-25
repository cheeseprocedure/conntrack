package conntrack

import (
	"net"

	"github.com/mdlayher/netlink"
	"github.com/pkg/errors"
	"github.com/ti-mo/netfilter"
)

// Flow represents a snapshot of a Conntrack connection.
type Flow struct {
	ID        uint32
	Timeout   uint32
	Timestamp Timestamp

	Status    Status
	ProtoInfo ProtoInfo
	Helper    Helper

	// Adding NAT attributes
	NatSrc NatMetadata
	NatDst NatMetadata

	Zone uint16

	CountersOrig, CountersReply Counter

	SecurityContext Security

	TupleOrig, TupleReply, TupleMaster Tuple

	SeqAdjOrig, SeqAdjReply SequenceAdjust

	Labels, LabelsMask []byte

	Mark, Use uint32

	SynProxy SynProxy
}

// NewFlow returns a new Flow object with the minimum necessary attributes to create a Conntrack entry.
// Writes values into the Status, Timeout, TupleOrig and TupleReply fields of the Flow.
//
// proto is the layer 4 protocol number of the connection.
// status is a StatusFlag value, or an ORed combination thereof.
// srcAddr and dstAddr are the source and destination addresses.
// srcPort and dstPort are the source and destination ports.
// timeout is the non-zero time-to-live of a connection in seconds.
func NewFlow(proto uint8, status StatusFlag, srcAddr, destAddr net.IP, srcPort, destPort uint16, timeout, mark uint32) Flow {
	// func NewFlow(proto uint8, status StatusFlag, srcAddr, destAddr net.IP, srcPort, destPort uint16, natSrc, natDst NatMetadata, timeout, mark uint32) Flow {

	var f Flow

	f.Status.Value = status

	f.Timeout = timeout
	f.Mark = mark

	f.TupleOrig.IP.SourceAddress = srcAddr
	f.TupleOrig.IP.DestinationAddress = destAddr
	f.TupleOrig.Proto.SourcePort = srcPort
	f.TupleOrig.Proto.DestinationPort = destPort
	f.TupleOrig.Proto.Protocol = proto

	// Set up TupleReply with source and destination inverted
	f.TupleReply.IP.SourceAddress = destAddr
	f.TupleReply.IP.DestinationAddress = srcAddr
	f.TupleReply.Proto.SourcePort = destPort
	f.TupleReply.Proto.DestinationPort = srcPort
	f.TupleReply.Proto.Protocol = proto

	return f
}

// unmarshal unmarshals a list of netfilter.Attributes into a Flow structure.
func (f *Flow) unmarshal(ad *netlink.AttributeDecoder) error {

	var at attributeType

	for ad.Next() {

		at = attributeType(ad.Type())

		// log.Printf("[*Flow.unmarshal] DEBUG - attribute type: %d", at)

		switch at {
		// CTA_TIMEOUT is the time until the Conntrack entry is automatically destroyed.
		case ctaTimeout:
			f.Timeout = ad.Uint32()
		// CTA_ID is the tuple hash value generated by the kernel. It can be relied on for flow identification.
		case ctaID:
			f.ID = ad.Uint32()
		// CTA_USE is the flow's kernel-internal refcount.
		case ctaUse:
			f.Use = ad.Uint32()
		// CTA_MARK is the connection's connmark
		case ctaMark:
			f.Mark = ad.Uint32()

		// CTA_NAT_SRC ...
		case ctaNatSrc:
			// log.Println("[*Flow.unmarshal] DEBUG - found ctaNatSrc attribute")
			if !nestedFlag(ad.TypeFlags()) {
				return errors.Wrap(errNotNested, opUnNat)
			}
			ad.Nested(f.NatSrc.unmarshal)
			// CTA_NAT_DST ...
		case ctaNatDst:
			// log.Println("[*Flow.unmarshal] DEBUG - found ctaNatDst attribute")
			if !nestedFlag(ad.TypeFlags()) {
				return errors.Wrap(errNotNested, opUnNat)
			}

		// CTA_ZONE describes the Conntrack zone the flow is placed in. This can be combined with a CTA_TUPLE_ZONE
		// to specify which zone an event originates from.
		case ctaZone:
			f.Zone = ad.Uint16()
		// CTA_LABELS is a binary bitfield attached to a connection that is sent in
		// events when changed, as well as in response to dump queries.
		case ctaLabels:
			f.Labels = ad.Bytes()
		// CTA_LABELS_MASK is never sent by the kernel, but it can be used
		// in set / update queries to mask label operations on the kernel state table.
		// it needs to be exactly as wide as the CTA_LABELS field it intends to mask.
		case ctaLabelsMask:
			f.LabelsMask = ad.Bytes()
		// CTA_STATUS is a bitfield of the state of the connection
		// (eg. if packets are seen in both directions, etc.)
		case ctaStatus:
			f.Status.Value = StatusFlag(ad.Uint32())
		// CTA_TUPLE_* attributes are nested and contain source and destination values for:
		// - the IPv4/IPv6 addresses involved
		// - ports used in the connection
		// - (optional) the Conntrack Zone of the originating/replying side of the flow
		case ctaTupleOrig:
			if !nestedFlag(ad.TypeFlags()) {
				return errors.Wrap(errNotNested, opUnTup)
			}
			ad.Nested(f.TupleOrig.unmarshal)
		case ctaTupleReply:
			if !nestedFlag(ad.TypeFlags()) {
				return errors.Wrap(errNotNested, opUnTup)
			}
			ad.Nested(f.TupleReply.unmarshal)
		case ctaTupleMaster:
			if !nestedFlag(ad.TypeFlags()) {
				return errors.Wrap(errNotNested, opUnTup)
			}
			ad.Nested(f.TupleMaster.unmarshal)
		// CTA_PROTOINFO is sent for TCP, DCCP and SCTP protocols only. It conveys extra metadata
		// about the state flags seen on the wire. Update events are sent when these change.
		case ctaProtoInfo:
			if !nestedFlag(ad.TypeFlags()) {
				return errors.Wrap(errNotNested, opUnProtoInfo)
			}
			ad.Nested(f.ProtoInfo.unmarshal)
		case ctaHelp:
			if !nestedFlag(ad.TypeFlags()) {
				return errors.Wrap(errNotNested, opUnHelper)
			}
			ad.Nested(f.Helper.unmarshal)
		// CTA_COUNTERS_* attributes are nested and contain byte and packet counters for flows in either direction.
		case ctaCountersOrig:
			if !nestedFlag(ad.TypeFlags()) {
				return errors.Wrap(errNotNested, opUnCounter)
			}
			ad.Nested(f.CountersOrig.unmarshal)
		case ctaCountersReply:
			if !nestedFlag(ad.TypeFlags()) {
				return errors.Wrap(errNotNested, opUnCounter)
			}
			f.CountersReply.Direction = true
			ad.Nested(f.CountersReply.unmarshal)
		// CTA_SECCTX is the SELinux security context of a Conntrack entry.
		case ctaSecCtx:
			if !nestedFlag(ad.TypeFlags()) {
				return errors.Wrap(errNotNested, opUnSecurity)
			}
			ad.Nested(f.SecurityContext.unmarshal)
		// CTA_TIMESTAMP is a nested attribute that describes the start and end timestamp of a flow.
		// It is sent by the kernel with dumps and DESTROY events.
		case ctaTimestamp:
			if !nestedFlag(ad.TypeFlags()) {
				return errors.Wrap(errNotNested, opUnTimestamp)
			}
			ad.Nested(f.Timestamp.unmarshal)
		// CTA_SEQADJ_* is generalized TCP window adjustment metadata. It is not (yet) emitted in Conntrack events.
		// The reason for its introduction is outlined in https://lwn.net/Articles/563151.
		// Patch set is at http://www.spinics.net/lists/netdev/msg245785.html.
		case ctaSeqAdjOrig:
			if !nestedFlag(ad.TypeFlags()) {
				return errors.Wrap(errNotNested, opUnSeqAdj)
			}
			ad.Nested(f.SeqAdjOrig.unmarshal)
		case ctaSeqAdjReply:
			if !nestedFlag(ad.TypeFlags()) {
				return errors.Wrap(errNotNested, opUnSeqAdj)
			}
			f.SeqAdjReply.Direction = true
			ad.Nested(f.SeqAdjReply.unmarshal)
		// CTA_SYNPROXY are the connection's SYN proxy parameters
		case ctaSynProxy:
			if !nestedFlag(ad.TypeFlags()) {
				return errors.Wrap(errNotNested, opUnSynProxy)
			}
			ad.Nested(f.SynProxy.unmarshal)
		}
	}

	// Populate NAT attributes in Flow (as the kernel does not)
	enrichFlowNat(f)

	return ad.Err()
}

// marshal marshals a Flow object into a list of netfilter.Attributes.
func (f Flow) marshal() ([]netfilter.Attribute, error) {

	// Flow updates need one of TupleOrig or TupleReply,
	// so we enforce having either of those.
	if !f.TupleOrig.filled() && !f.TupleReply.filled() {
		return nil, errNeedTuples
	}

	attrs := make([]netfilter.Attribute, 0, 12)

	if f.TupleOrig.filled() {
		to, err := f.TupleOrig.marshal(uint16(ctaTupleOrig))
		if err != nil {
			return nil, err
		}
		attrs = append(attrs, to)
	}

	if f.TupleReply.filled() {
		// Mimickign behaviour of conntrackd here to enable replication of NAT
		// state
		modifiedTupleReply := f.TupleReply
		modifiedTupleReply.IP.DestinationAddress = f.TupleOrig.IP.SourceAddress
		tr, err := modifiedTupleReply.marshal(uint16(ctaTupleReply))
		if err != nil {
			return nil, err
		}
		attrs = append(attrs, tr)
	}

	// Optional attributes appended to the list when filled
	if f.Timeout != 0 {
		a := netfilter.Attribute{Type: uint16(ctaTimeout)}
		a.PutUint32(f.Timeout)
		attrs = append(attrs, a)
	}

	if f.Status.Value != 0 {
		attrs = append(attrs, f.Status.marshal())
	}

	if f.Mark != 0 {
		a := netfilter.Attribute{Type: uint16(ctaMark)}
		a.PutUint32(f.Mark)
		attrs = append(attrs, a)
	}

	if f.NatSrc.filled() {
		nat, err := f.NatSrc.marshal(uint16(ctaNatSrc))
		if err != nil {
			return nil, err
		}
		attrs = append(attrs, nat)
	}

	if f.NatDst.filled() {
		nat, err := f.NatDst.marshal(uint16(ctaNatDst))
		if err != nil {
			return nil, err
		}
		attrs = append(attrs, nat)
	}

	if f.Zone != 0 {
		a := netfilter.Attribute{Type: uint16(ctaZone)}
		a.PutUint16(f.Zone)
		attrs = append(attrs, a)
	}

	if f.ProtoInfo.filled() {
		attrs = append(attrs, f.ProtoInfo.marshal())
	}

	if f.Helper.filled() {
		attrs = append(attrs, f.Helper.marshal())
	}

	if f.TupleMaster.filled() {
		tm, err := f.TupleMaster.marshal(uint16(ctaTupleMaster))
		if err != nil {
			return nil, err
		}
		attrs = append(attrs, tm)
	}

	if f.SeqAdjOrig.filled() {
		attrs = append(attrs, f.SeqAdjOrig.marshal())
	}

	if f.SeqAdjReply.filled() {
		attrs = append(attrs, f.SeqAdjReply.marshal())
	}

	if f.SynProxy.filled() {
		attrs = append(attrs, f.SynProxy.marshal())
	}

	// Non-nested netlink conntrack attributes are supposed to be in network
	// (big-endian) order, not native
	for _, a := range attrs {
		if a.Nested {
			continue
		}
		a.NetByteOrder = true
	}
	return attrs, nil
}

// unmarshalFlow unmarshals a Flow from a netlink.Message.
// The Message must contain valid attributes.
func unmarshalFlow(nlm netlink.Message) (Flow, error) {

	var f Flow

	_, ad, err := netfilter.DecodeNetlink(nlm)
	if err != nil {
		return f, err
	}

	err = f.unmarshal(ad)
	if err != nil {
		return f, err
	}

	return f, nil
}

// unmarshalFlows unmarshals a list of flows from a list of Netlink messages.
// This method can be used to parse the result of a dump or get query.
func unmarshalFlows(nlm []netlink.Message) ([]Flow, error) {

	// Pre-allocate to avoid re-allocating output slice on every op
	out := make([]Flow, 0, len(nlm))

	for i := 0; i < len(nlm); i++ {

		f, err := unmarshalFlow(nlm[i])
		if err != nil {
			return nil, err
		}

		out = append(out, f)
	}

	return out, nil
}
