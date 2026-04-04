package core

// PropagationAspect is the destination aspect for LXMF propagation nodes.
const PropagationAspect = "propagation"

// MessageGetPath is the RNS link request path used for all propagation node
// client operations (list, get, and cleanup).
const MessageGetPath = "/get"

// PropagationTransferState tracks the state of a message download from a
// propagation node.
type PropagationTransferState int

const (
	PRIdle             PropagationTransferState = 0x00
	PRPathRequested    PropagationTransferState = 0x01
	PRLinkEstablishing PropagationTransferState = 0x02
	PRLinkEstablished  PropagationTransferState = 0x03
	PRRequestSent      PropagationTransferState = 0x04
	PRReceiving        PropagationTransferState = 0x05
	PRResponseReceived PropagationTransferState = 0x06
	PRComplete         PropagationTransferState = 0x07
	PRNoPath           PropagationTransferState = 0xf0
	PRLinkFailed       PropagationTransferState = 0xf1
	PRTransferFailed   PropagationTransferState = 0xf2
	PRNoIdentityRcvd   PropagationTransferState = 0xf3
	PRNoAccess         PropagationTransferState = 0xf4
	PRFailed           PropagationTransferState = 0xfe
)

// Error codes returned by propagation nodes in request responses.
const (
	PNErrorNoIdentity = 0xf0
	PNErrorNoAccess   = 0xf1
)
