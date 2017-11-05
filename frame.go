package level_ip

type Frame interface {
	encode() []byte
	decode(b []byte)
}
