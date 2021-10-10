package rfc6962

import (
	"math"
)

type hashFunc func([]byte) [32]byte

type leaf [32]byte

func merkleTreeHash(hf hashFunc, certs [][]byte) leaf {
	n := len(certs)
	switch n {
	case 0:
		return hf([]byte{})
	case 1:
		return hf(append([]byte{byte(0x00)}, certs[0]...))
	default:
		// let k be the largest power of two smaller than n (i.e., k < n <= 2k)
		k := minPow2(n)

		// D = certs
		// MTH(D[n]) = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n]))
		left := merkleTreeHash(hf, certs[0:k])
		right := merkleTreeHash(hf, certs[k:n])

		return hf(append(append([]byte{byte(0x01)}, left[:]...), right[:]...))
	}
}

func auditPath(hf hashFunc, m int, certs [][]byte) [][]byte {
	n := len(certs)
	k := minPow2(n)

	switch {
	case n <= 1:
		// PATH(0, {d(0)}) = {}
		return nil
	case m < k:
		// PATH(m, D[n]) = PATH(m, D[0:k]) : MTH(D[k:n])
		path := auditPath(hf, m, certs[0:k])
		node := merkleTreeHash(hf, certs[k:n])
		return append(path, node[:])
	default:
		// PATH(m, D[n]) = PATH(m - k, D[k:n]) : MTH(D[0:k])
		path := auditPath(hf, m-k, certs[k:n])
		node := merkleTreeHash(hf, certs[0:k])
		return append(path, node[:])
	}
}

func proof(hf hashFunc, m int, certs [][]byte) [][]byte {
	return subProof(hf, m, certs, true) // PROOF(m, D[n]) = SUBPROOF(m, D[n], true)
}

func subProof(hf hashFunc, m int, certs [][]byte, b bool) [][]byte {
	n := len(certs)
	k := minPow2(n)

	switch {
	case m == n:
		if b {
			return nil // SUBPROOF(m, D[m], true) = {}
		}

		//  SUBPROOF(m, D[m], false) = {MTH(D[m])}
		mth := merkleTreeHash(hf, certs)
		return append([][]byte{}, mth[:])
	case m < n && m <= k:
		// SUBPROOF(m, D[n], b) = SUBPROOF(m, D[0:k], b) : MTH(D[k:n])
		mth := merkleTreeHash(hf, certs[k:n])
		sp := subProof(hf, m, certs[0:k], b)
		return append(append([][]byte{}, sp...), mth[:])
	case m < n:
		// SUBPROOF(m, D[n], b) = SUBPROOF(m - k, D[k:n], false) : MTH(D[0:k])
		mth := merkleTreeHash(hf, certs[0:k])
		sp := subProof(hf, m-k, certs[k:n], false)
		return append(append([][]byte{}, sp...), mth[:])
	default:
		return nil
	}
}

func minPow2(x int) int {
	log := math.Log2(float64(x))
	if math.Trunc(log) == log {
		log -= 1
	} else {
		log = math.Floor(log)
	}

	return int(math.Exp2(log))
}
