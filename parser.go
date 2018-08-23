package ipfix

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"io"
	"sync"
)

// The version field in IPFIX messages should always have the value 10. If it
// does not, you get this error. It's probably a sign of a bug in the parser or
// the exporter and that we have lost synchronization with the data stream.
// Reestablishing the session is the only way forward at this point.
var ErrVersion = errors.New("incorrect version field in message header - out of sync?")

// ErrRead is returned when a packet is not long enough for the field it is
// supposed to contain. This is a sign of an earlier read error or a corrupted
// packet.
var ErrRead = errors.New("short read - malformed packet?")

// ErrProtocol is returned when impossible values that constitute a protocol
// error are encountered.
var ErrProtocol = errors.New("protocol error")

// ErrUnknownTemplate is returned when a message's data set refers to a template
// which has not yet been seen by the parser.
var ErrUnknownTemplate = errors.New("unknown template")

// A Message is the top level construct representing an IPFIX message. A well
// formed message contains one or more sets of data or template information.
type Message struct {
	Header          MessageHeader
	DataRecords     []DataRecord
	TemplateRecords []TemplateRecord
}

// The MessageHeader provides metadata for the entire Message. The sequence
// number and domain ID can be used to gain knowledge of messages lost on an
// unreliable transport such as UDP.
type MessageHeader struct {
	Version        uint16 // Always 0x0a
	Length         uint16
	ExportTime     uint32 // Epoch seconds
	SequenceNumber uint32
	DomainID       uint32
}

func (h *MessageHeader) unmarshal(s *slice) {
	h.Version = s.Uint16()
	h.Length = s.Uint16()
	h.ExportTime = s.Uint32()
	h.SequenceNumber = s.Uint32()
	h.DomainID = s.Uint32()
}

type setHeader struct {
	SetID  uint16
	Length uint16
}

func (h *setHeader) unmarshal(s *slice) {
	h.SetID = s.Uint16()
	h.Length = s.Uint16()
}

type templateHeader struct {
	TemplateID uint16
	FieldCount uint16
}

func (h *templateHeader) unmarshal(s *slice) {
	h.TemplateID = s.Uint16()
	h.FieldCount = s.Uint16()
}

// The DataRecord represents a single exported flow. The Fields each describe
// different aspects of the flow (source and destination address, counters,
// service, etc.).
type DataRecord struct {
	TemplateID uint16
	Fields     [][]byte
}

// The TemplateRecord describes a data template, as used by DataRecords.
type TemplateRecord struct {
	TemplateID      uint16
	FieldSpecifiers []TemplateFieldSpecifier
}

// The TemplateFieldSpecifier describes the ID and size of the corresponding
// Fields in a DataRecord.
type TemplateFieldSpecifier struct {
	EnterpriseID uint32
	FieldID      uint16
	Length       uint16
}

// An option can be passed to New()
type Option func(*Session)

// WithIDAliasing enables or disables template id aliasing. The default is disabled.
func WithIDAliasing(v bool) Option {
	return func(s *Session) {
		s.withIDAliasing = v
	}
}

// The Session is the context for IPFIX messages.
type Session struct {
	buffers *sync.Pool

	withIDAliasing bool

	mut        sync.RWMutex
	minRecord  map[uint16]uint16
	signatures map[[sha1.Size]byte]uint16
	specifiers map[uint16][]TemplateFieldSpecifier
	aliases    map[uint16]uint16
	nextID     uint16
}

// NewSession initializes a new Session based on the provided io.Reader.
func NewSession(opts ...Option) *Session {
	var s Session
	s.buffers = &sync.Pool{
		New: func() interface{} {
			return make([]byte, 65536)
		},
	}

	for _, opt := range opts {
		opt(&s)
	}

	if s.withIDAliasing {
		s.signatures = make(map[[sha1.Size]byte]uint16)
		s.aliases = make(map[uint16]uint16)
		s.nextID = 256
	}

	s.specifiers = make(map[uint16][]TemplateFieldSpecifier)
	s.minRecord = make(map[uint16]uint16)

	return &s
}

const (
	msgHeaderLength = 2 + 2 + 4 + 4 + 4
	setHeaderLength = 2 + 2
)

// ParseReader extracts and returns one message from the IPFIX stream. As long
// as err is nil, further messages can be read from the stream. Errors are not
// recoverable -- once an error has been returned, ParseReader should not be
// called again on the same session.
//
// Deprecated: use ParseBuffer instead.
func (s *Session) ParseReader(r io.Reader) (Message, error) {
	bs := s.buffers.Get().([]byte)
	bs, hdr, err := Read(r, bs)
	if err != nil {
		return Message{}, err
	}

	sl := newSlice(bs[msgHeaderLength:])
	var msg Message
	msg.Header = hdr

	msg.TemplateRecords, msg.DataRecords, err = s.readBuffer(sl)
	s.buffers.Put(bs)
	return msg, err
}

// ParseBuffer extracts one message from the given buffer and returns it. Err
// is nil if the buffer could be parsed correctly. ParseBuffer is goroutine safe.
func (s *Session) ParseBuffer(bs []byte) (Message, error) {
	var msg Message
	var err error

	sl := newSlice(bs)
	msg.Header.unmarshal(sl)
	msg.TemplateRecords, msg.DataRecords, err = s.readBuffer(sl)
	return msg, err
}

// ParseBufferAll extracts all message from the given buffer and returns them.
// Err is nil if the buffer could be parsed correctly. ParseBufferAll is
// goroutine safe.
func (s *Session) ParseBufferAll(bs []byte) ([]Message, error) {
	var msgs []Message
	var err error

	sl := newSlice(bs)

	for sl.Len() > 0 {
		var msg Message
		msg.Header.unmarshal(sl)
		length := int(msg.Header.Length - msgHeaderLength)

		cut := newSlice(sl.Cut(length))
		if msg.TemplateRecords, msg.DataRecords, err = s.readBuffer(cut); err != nil {
			break
		}

		msgs = append(msgs, msg)
	}
	return msgs, err
}

func (s *Session) readBuffer(sl *slice) ([]TemplateRecord, []DataRecord, error) {
	var ts, trecs []TemplateRecord
	var ds, drecs []DataRecord
	var err error

	for sl.Len() > 0 {
		// Read a set header
		var setHdr setHeader
		setHdr.unmarshal(sl)

		if debug {
			dl.Printf("setHdr: %+v", setHdr)
		}

		if setHdr.Length < setHeaderLength {
			// Set cannot be shorter than its header
			if debug {
				dl.Println("setHdr too short")
			}
			return nil, nil, io.ErrUnexpectedEOF
		}

		// Grab the bytes representing the set
		setLen := int(setHdr.Length) - setHeaderLength
		setSl := newSlice(sl.Cut(setLen))
		if err := sl.Error(); err != nil {
			if debug {
				dl.Println("slice error")
			}
			return nil, nil, err
		}

		// Parse them
		ts, ds, err = s.readSet(setHdr, setSl)
		if err != nil {
			if debug {
				dl.Println("readSet:", err)
			}
			return nil, nil, err
		}

		trecs = append(trecs, ts...)
		drecs = append(drecs, ds...)
	}

	return trecs, drecs, nil
}

func (s *Session) readSet(setHdr setHeader, sl *slice) ([]TemplateRecord, []DataRecord, error) {
	var trecs []TemplateRecord
	var drecs []DataRecord

	minLen := int(s.getMinRecLen(setHdr.SetID))

	for sl.Len() > 0 && sl.Error() == nil {
		if sl.Len() < minLen {
			if debug {
				dl.Println("ignoring padding")
			}
			// Padding
			return trecs, drecs, sl.Error()
		}

		// Set ID
		//
		// Identifies the Set.  A value of 2 is reserved for Template Sets. A
		// value of 3 is reserved for Options Template Sets.  Values from 4 to
		// 255 are reserved for future use.  Values 256 and above are used for
		// Data Sets.  The Set ID values of 0 and 1 are not used, for
		// historical reasons [RFC3954].

		switch {
		case setHdr.SetID < 2:
			// Unused, shouldn't happen
			if debug {
				dl.Println("bad SetID", setHdr.SetID)
			}
			return nil, nil, ErrProtocol

		case setHdr.SetID == 2:
			// Template Set
			if debug {
				dl.Println("parsing template set")
			}
			tr := s.readTemplateRecord(sl)
			s.registerTemplateRecord(&tr)
			trecs = append(trecs, tr)

		case setHdr.SetID == 3:
			// Options Template Set, not handled
			if debug {
				dl.Println("skipping option template set")
			}
			sl.Cut(sl.Len())

		case setHdr.SetID > 3 && setHdr.SetID < 256:
			// Reserved, shouldn't happen
			if debug {
				dl.Println("bad SetID", setHdr.SetID)
			}
			return nil, nil, ErrProtocol

		default:
			// Data set
			if debug {
				dl.Println("parsing data set")
			}
			tpl := s.lookupTemplateFieldSpecifiers(setHdr.SetID)

			if tpl != nil {
				// Data set
				ds, err := s.readDataRecord(sl, tpl)
				if err != nil {
					return nil, nil, err
				}
				ds.TemplateID = s.unaliasTemplateID(setHdr.SetID)
				drecs = append(drecs, ds)
			} else {
				// Data set with unknown template
				// We can't trust set length, because we might be out of sync.
				// Consume rest of message.
				return trecs, drecs, sl.Error()
			}
		}
	}

	return trecs, drecs, sl.Error()
}

func (s *Session) unaliasTemplateID(tid uint16) uint16 {
	if s.withIDAliasing {
		s.mut.RLock()
		tid = s.aliases[tid]
		s.mut.RUnlock()
	}
	return tid
}

func (s *Session) readDataRecord(sl *slice, tpl []TemplateFieldSpecifier) (DataRecord, error) {
	var dr DataRecord
	dr.Fields = make([][]byte, len(tpl))

	var err error
	total := 0
	for i := range tpl {
		var val []byte
		if tpl[i].Length == 65535 {
			val, err = s.readVariableLength(sl)
			if err != nil {
				return DataRecord{}, err
			}
		} else {
			l := int(tpl[i].Length)
			val = sl.Cut(l)
		}
		dr.Fields[i] = val
		total += len(val)
	}

	// The loop above keeps slices of the original buffer. But that buffer
	// will be recycled so we need to copy them to separate storage. It's more
	// efficient to do it this way, with a single allocation at the end than
	// doing individual allocations along the way.

	cp := make([]byte, total)
	next := 0
	for i := range dr.Fields {
		ln := copy(cp[next:], dr.Fields[i])
		dr.Fields[i] = cp[next : next+ln]
		next += ln
	}

	return dr, sl.Error()
}

func (s *Session) readTemplateRecord(sl *slice) TemplateRecord {
	var th templateHeader
	th.unmarshal(sl)
	if debug {
		dl.Printf("templateHeader: %+v", th)
	}

	var tr TemplateRecord
	tr.TemplateID = th.TemplateID
	tr.FieldSpecifiers = make([]TemplateFieldSpecifier, th.FieldCount)
	for i := 0; i < int(th.FieldCount); i++ {
		f := TemplateFieldSpecifier{}
		f.FieldID = sl.Uint16()
		f.Length = sl.Uint16()
		if f.FieldID >= 0x8000 {
			f.FieldID -= 0x8000
			f.EnterpriseID = sl.Uint32()
		}
		tr.FieldSpecifiers[i] = f
	}

	return tr
}

func (s *Session) registerTemplateRecord(tr *TemplateRecord) {
	if s.withIDAliasing {
		tr.TemplateID = s.registerAliasedTemplateRecord(*tr)
	} else {
		s.registerUnaliasedTemplateRecord(*tr)
	}
}

func (s *Session) registerUnaliasedTemplateRecord(tr TemplateRecord) {
	// Update templates and minimum record cache
	tid := tr.TemplateID
	tpl := tr.FieldSpecifiers
	minLen := calcMinRecLen(tpl)
	s.mut.Lock()
	defer s.mut.Unlock()
	if minLen == 0 {
		delete(s.specifiers, tid)
	} else {
		s.specifiers[tid] = tpl
	}
	s.minRecord[tid] = minLen
}

func (s *Session) registerAliasedTemplateRecord(tr TemplateRecord) uint16 {
	var tid uint16
	if len(tr.FieldSpecifiers) == 0 {
		s.withdrawAliasedTemplateRecord(tr)
		tid = tr.TemplateID
	} else {
		tid = s.aliasTemplateRecord(tr)
	}

	if debug {
		dl.Printf("Mapped template id %d -> %d", tr.TemplateID, tid)
	}
	return tid
}

func (s *Session) aliasTemplateRecord(tr TemplateRecord) uint16 {
	var buffer bytes.Buffer
	binary.Write(&buffer, binary.BigEndian, tr.FieldSpecifiers)
	hash := sha1.Sum(buffer.Bytes())

	var ntid uint16
	s.mut.Lock()
	defer s.mut.Unlock()

	if id, ok := s.signatures[hash]; ok {
		ntid = id
	} else {
		ntid = s.nextID
		s.signatures[hash] = ntid
		s.specifiers[ntid] = tr.FieldSpecifiers
		s.nextID++

		if s.nextID == 65535 {
			panic("IPFIX has run out of virtual template ids!")
		}

		s.minRecord[ntid] = calcMinRecLen(tr.FieldSpecifiers)
	}

	if _, ok := s.aliases[tr.TemplateID]; !ok {
		s.aliases[tr.TemplateID] = ntid
	}

	return ntid
}

func (s *Session) withdrawAliasedTemplateRecord(tr TemplateRecord) {
	s.mut.Lock()
	defer s.mut.Unlock()
	delete(s.aliases, tr.TemplateID)
}

func calcMinRecLen(tpl []TemplateFieldSpecifier) uint16 {
	var minLen uint16
	for i := range tpl {
		if tpl[i].Length == 65535 {
			minLen++
		} else {
			minLen += tpl[i].Length
		}
	}
	return minLen
}

// LookupTemplateRecords returns the list of template records referred to by the data sets
// in the given message. It also includes any templates already extant in the message.
func (s *Session) LookupTemplateRecords(m Message) ([]TemplateRecord, error) {
	tr := m.TemplateRecords
dataLoop:
	for _, dr := range m.DataRecords {
		// First walk and make sure this template isn't already in the return list
		for _, t := range tr {
			if t.TemplateID == dr.TemplateID {
				continue dataLoop
			}
		}
		// If we got this far, we haven't seen the template ID yet
		tfs := s.lookupTemplateFieldSpecifiers(dr.TemplateID)
		if len(tfs) == 0 {
			return nil, ErrUnknownTemplate
		}
		tr = append(tr, TemplateRecord{TemplateID: dr.TemplateID, FieldSpecifiers: tfs})
	}
	return tr, nil
}

func (s *Session) lookupTemplateFieldSpecifiers(tid uint16) []TemplateFieldSpecifier {
	var tpl []TemplateFieldSpecifier

	if s.withIDAliasing {
		tpl = s.lookupAliasedTemplateFieldSpecifiers(tid)
	} else {
		tpl = s.lookupUnaliasedTemplateFieldSpecifiers(tid)
	}

	return tpl
}

func (s *Session) lookupUnaliasedTemplateFieldSpecifiers(tid uint16) []TemplateFieldSpecifier {
	var tpl []TemplateFieldSpecifier

	s.mut.RLock()
	defer s.mut.RUnlock()
	if id, ok := s.specifiers[tid]; ok {
		tpl = id
	}

	return tpl
}

func (s *Session) lookupAliasedTemplateFieldSpecifiers(tid uint16) []TemplateFieldSpecifier {
	var tpl []TemplateFieldSpecifier

	s.mut.RLock()
	if id, ok := s.aliases[tid]; ok {
		tpl = s.specifiers[id]
	}
	s.mut.RUnlock()

	return tpl
}

func (s *Session) getMinRecLen(tid uint16) uint16 {
	var minLen uint16

	s.mut.RLock()
	defer s.mut.RUnlock()
	if s.withIDAliasing {
		minLen = s.minRecord[s.aliases[tid]]
	} else {
		minLen = s.minRecord[tid]
	}

	return minLen
}

func (s *Session) readVariableLength(sl *slice) (val []byte, err error) {
	var l int

	l0 := sl.Uint8()
	if l0 < 255 {
		l = int(l0)
	} else {
		l = int(sl.Uint16())
	}

	return sl.Cut(l), sl.Error()
}

func (s *Session) ExportTemplateRecords() []TemplateRecord {
	trecs := make([]TemplateRecord, 0, len(s.specifiers))
	s.mut.RLock()
	defer s.mut.RUnlock()

	if s.withIDAliasing {
		for t, a := range s.aliases {
			tr := TemplateRecord{
				TemplateID:      t,
				FieldSpecifiers: s.specifiers[a],
			}

			trecs = append(trecs, tr)
		}
	} else {
		for t, fs := range s.specifiers {
			tr := TemplateRecord{
				TemplateID:      t,
				FieldSpecifiers: fs,
			}
			trecs = append(trecs, tr)
		}
	}

	return trecs
}

func (s *Session) LoadTemplateRecords(trecs []TemplateRecord) {
	for _, tr := range trecs {
		s.registerTemplateRecord(&tr)
	}
}

// Returns overall length of the message, the length of the template set, and
// the length of the data set(s).
func (s *Session) calculateMarshalledLength(m Message) (int, int, int, error) {
	var length int
	var tmplLen, dataLen int
	length += msgHeaderLength // there will always be a header
	if len(m.TemplateRecords) > 0 {
		// We will be creating a template set
		tmplLen += setHeaderLength
		for _, rec := range m.TemplateRecords {
			// Each template record implies a record header
			tmplLen += 4
			for _, field := range rec.FieldSpecifiers {
				if field.EnterpriseID == 0 {
					tmplLen += 4
				} else {
					tmplLen += 8
				}
			}
		}
	}
	if len(m.DataRecords) > 0 {
		currentTemplate := m.DataRecords[0].TemplateID
		tpl := s.lookupTemplateFieldSpecifiers(currentTemplate)
		dataLen += setHeaderLength
		for _, dr := range m.DataRecords {
			if dr.TemplateID != currentTemplate {
				dataLen += setHeaderLength
				tpl = s.lookupTemplateFieldSpecifiers(dr.TemplateID)
				currentTemplate = dr.TemplateID
			}
			for i, field := range dr.Fields {
				if i > len(tpl) {
					return 0, 0, 0, errors.New("too many fields for template")
				}
				// Handle variable-length fields
				if tpl[i].Length == 0xffff {
					if len(field) < 0xff {
						dataLen += 1          // 1 byte for the length
						dataLen += len(field) // and then the field itself
					} else {
						dataLen += 3          // 3 bytes for the length
						dataLen += len(field) // and then the field itself
					}
				} else {
					dataLen += int(tpl[i].Length)
				}
			}
		}
	}
	length += tmplLen
	length += dataLen
	return length, tmplLen, dataLen, nil
}

// Marshall a Message struct back into a raw IPFIX buffer
func (s *Session) Marshal(m Message) ([]byte, error) {
	// First we'll calculate how big the message will be
	length, tmplLen, _, err := s.calculateMarshalledLength(m)
	if err != nil {
		return []byte{}, nil
	}

	// Now make the empty buffer (brings us down to 1 allocation per call to Marshal)
	message := make([]byte, length)

	// Populate the header
	binary.BigEndian.PutUint16(message[:2], m.Header.Version)
	binary.BigEndian.PutUint32(message[4:8], m.Header.ExportTime)
	binary.BigEndian.PutUint32(message[8:12], m.Header.SequenceNumber)
	binary.BigEndian.PutUint32(message[12:16], m.Header.DomainID)
	binary.BigEndian.PutUint16(message[2:4], uint16(length))
	offset := msgHeaderLength

	// Build template records set
	if len(m.TemplateRecords) > 0 {
		// construct template set header
		binary.BigEndian.PutUint16(message[offset:offset+2], 2)                 // type is always 2 for templates
		binary.BigEndian.PutUint16(message[offset+2:offset+4], uint16(tmplLen)) // we calculated earlier
		offset += 4

		for _, rec := range m.TemplateRecords {
			// Build the record header (template ID + number of field specifiers)
			binary.BigEndian.PutUint16(message[offset:offset+2], rec.TemplateID)
			binary.BigEndian.PutUint16(message[offset+2:offset+4], uint16(len(rec.FieldSpecifiers)))
			offset += 4
			// Now build out the fields
			for _, field := range rec.FieldSpecifiers {
				if field.EnterpriseID == 0 {
					// No enterprise needed
					binary.BigEndian.PutUint16(message[offset:offset+2], field.FieldID)
					binary.BigEndian.PutUint16(message[offset+2:offset+4], field.Length)
					offset += 4
				} else {
					binary.BigEndian.PutUint16(message[offset:offset+2], field.FieldID+0x8000)
					binary.BigEndian.PutUint16(message[offset+2:offset+4], field.Length)
					binary.BigEndian.PutUint32(message[offset+4:offset+8], field.EnterpriseID)
					offset += 8
				}
			}
		}
	}

	// Build data record section
	// It's possible that there were multiple sets with alternating templates,
	// e.g. set 0 used template 256, set 1 used template 300, set 2 used 256 again.
	if len(m.DataRecords) > 0 {
		currentTemplate := m.DataRecords[0].TemplateID
		tpl := s.lookupTemplateFieldSpecifiers(currentTemplate)
		setStart := offset // where the current set started
		// initialize the first set header
		// We only write the template ID now, since we won't be sure of length until later
		binary.BigEndian.PutUint16(message[offset:offset+2], currentTemplate)
		offset += 4
		for _, dr := range m.DataRecords {
			if dr.TemplateID != currentTemplate {
				// We've transitioned templates, make a new set
				if offset-setStart > setHeaderLength {
					binary.BigEndian.PutUint16(message[setStart+2:setStart+4], uint16(offset-setStart))
				}
				// now set up for the next set
				setStart = offset
				currentTemplate = dr.TemplateID
				tpl = s.lookupTemplateFieldSpecifiers(dr.TemplateID)
				// We only write the template ID now, since we won't be sure of length until later
				binary.BigEndian.PutUint16(message[offset:offset+2], dr.TemplateID)
				offset += 4
			}
			for i, field := range dr.Fields {
				if i > len(tpl) {
					return message, errors.New("too many fields for template")
				}
				// Handle variable-length fields
				if tpl[i].Length == 0xffff {
					if len(field) < 0xff {
						message[offset] = uint8(len(field))
						offset++
						copy(message[offset:offset+len(field)], field)
						offset += len(field)
					} else {
						message[offset] = 0xff
						binary.BigEndian.PutUint16(message[offset+1:offset+3], uint16(len(field)))
						offset += 3
						copy(message[offset:offset+len(field)], field)
						offset += len(field)
					}
				} else {
					copy(message[offset:offset+len(field)], field)
					offset += len(field)
				}
			}
		}
		// Emit the final set length
		if offset-setStart > setHeaderLength {
			binary.BigEndian.PutUint16(message[setStart+2:setStart+4], uint16(offset-setStart))
		}

	}

	return message, nil
}
