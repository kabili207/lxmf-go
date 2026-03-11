package core

// LXMF message field keys (int keys in the fields msgpack dict).
const (
	FieldEmbeddedLXMs   = 0x01 // nested LXMF messages (for store-and-forward)
	FieldTelemetry      = 0x02 // sensor/telemetry data
	FieldTelemetryStream = 0x03
	FieldIconAppearance = 0x04 // Sideband icon/color
	FieldFileAttachments = 0x05
	FieldImage          = 0x06
	FieldAudio          = 0x07
	FieldThread         = 0x08 // reply-to / thread root hash
	FieldCommands       = 0x09
	FieldResults        = 0x0A
	FieldGroup          = 0x0B
	FieldTicket         = 0x0C // PoW bypass ticket (16 bytes)
	FieldEvent          = 0x0D
	FieldRNRRefs        = 0x0E // NomadNet page references
	FieldRenderer       = 0x0F // RENDERER_PLAIN/MICRON/MARKDOWN/BBCODE
	FieldCustomType     = 0xFB
	FieldCustomData     = 0xFC
	FieldCustomMeta     = 0xFD
	FieldNonSpecific    = 0xFE
	FieldDebug          = 0xFF
)

// Renderer field values (used with FieldRenderer).
const (
	RendererPlain    = 0x00
	RendererMicron   = 0x01
	RendererMarkdown = 0x02
	RendererBBCode   = 0x03
)
