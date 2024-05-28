package subtle

func ConstantTimeAllZero(bytes []byte) int {
	var b uint8
	for _, v := range bytes {
		b |= v
	}
	return int((uint32(b) - 1) >> 31)
}
