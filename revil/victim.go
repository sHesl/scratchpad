package revil

import "golang.org/x/crypto/nacl/box"

type Victim struct {
	Systems map[string]*System
}

type System struct {
	PubKey              BoxECCKey
	SysPrivKeyEncrypted []byte
	Files               []*File
}

type File struct {
	PubKey   BoxECCKey
	Nonce    BoxNonce
	Contents []byte
}

func (v *Victim) DecryptSystem(name string, decryptor func(*File) Decryptor) {
	for _, f := range v.Systems[name].Files {
		d := decryptor(f)
		f.Contents, _ = box.OpenAfterPrecomputation(nil, f.Contents, d.Nonce, d.Key)
	}
}

func (v *Victim) DecryptFile(f *File, d Decryptor) {
	f.Contents, _ = box.OpenAfterPrecomputation(nil, f.Contents, d.Nonce, d.Key)
}
