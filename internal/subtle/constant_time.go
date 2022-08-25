package subtle

func ConstantTimeAllZero(bytes []byte) bool {
	var b uint8
	for _, v := range bytes {
		b |= v
	}
	return b == 0
}
