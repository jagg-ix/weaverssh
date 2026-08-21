package terminalsession

type replayRing struct {
	maxBytes int
	bytes    int
	dropped  uint64
	frames   []Frame
}

func newReplayRing(maxBytes int) *replayRing { return &replayRing{maxBytes: maxBytes} }

func (r *replayRing) append(frame Frame) {
	frame.Payload = append([]byte(nil), frame.Payload...)
	if r.maxBytes <= 0 {
		r.dropped += uint64(len(frame.Payload))
		return
	}
	if len(frame.Payload) > r.maxBytes {
		r.dropped += uint64(r.bytes + len(frame.Payload) - r.maxBytes)
		r.frames = []Frame{{Type: frame.Type, Flags: frame.Flags | FlagTruncated, Sequence: frame.Sequence, Payload: append([]byte(nil), frame.Payload[len(frame.Payload)-r.maxBytes:]...)}}
		r.bytes = r.maxBytes
		return
	}
	for r.bytes+len(frame.Payload) > r.maxBytes && len(r.frames) > 0 {
		r.bytes -= len(r.frames[0].Payload)
		r.dropped += uint64(len(r.frames[0].Payload))
		r.frames = r.frames[1:]
	}
	r.frames = append(r.frames, frame)
	r.bytes += len(frame.Payload)
}

func (r *replayRing) bounds(nextSequence uint64) (uint64, uint64) {
	ceiling := uint64(0)
	if nextSequence > 0 {
		ceiling = nextSequence - 1
	}
	if len(r.frames) == 0 {
		return ceiling + 1, ceiling
	}
	return r.frames[0].Sequence, r.frames[len(r.frames)-1].Sequence
}

func (r *replayRing) after(sequence uint64) []Frame {
	out := make([]Frame, 0, len(r.frames))
	for _, frame := range r.frames {
		if frame.Sequence <= sequence {
			continue
		}
		copyFrame := frame
		copyFrame.Flags |= FlagReplay
		copyFrame.Payload = append([]byte(nil), frame.Payload...)
		out = append(out, copyFrame)
	}
	if len(out) > 0 && sequence+1 < out[0].Sequence {
		out[0].Flags |= FlagTruncated
	}
	return out
}
