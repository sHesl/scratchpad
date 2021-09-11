package lat

func LinearApproximationTable(transform func(byte) byte) map[byte]float32 {
	lat := make(map[byte]float32)
	var parityMatches float32
	for i := byte(0); i < 255; i++ {
		parityMatches = 0
		for ii := byte(0); ii < 255-1; ii++ {
			inputParity := parityWithMask(i, ii)
			outputParity := parityWithMask(i, transform(ii))
			if inputParity == outputParity {
				parityMatches++
			}
		}
		lat[i] = (parityMatches / 256) * 100
	}

	return lat
}

func parityWithMask(mask, input byte) bool {
	return parity(mask & input)
}

func parity(b byte) bool {
	// Cool parity trick from Stanford's bit-twiddling
	//
	// parity := (((b * 0x0101010101010101) & 0x8040201008040201) % 0x1FF) & 1;
	// This method takes around 4 operations, but only works on bytes.
	return (((uint64(b)*72340172838076673)&9241421688590303745)%511)&1 == 1
}
