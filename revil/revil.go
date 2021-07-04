package revil

import (
	"crypto/rand"

	"golang.org/x/crypto/nacl/box"
)

type REvil struct {
	Operators           map[string]*Operator
	OperatorPrivateKeys map[string]BoxECCKey
}

type Operator struct {
	OperatorPubKey BoxECCKey
	Campaigns      map[string]*Campaign
}

type Campaign struct {
	campaignPrivKey BoxECCKey
	CampaignPubKey  BoxECCKey
}

func (r *REvil) NewOperator(name string) *Operator {
	if r.Operators == nil {
		r.Operators = make(map[string]*Operator)
	}

	if r.OperatorPrivateKeys == nil {
		r.OperatorPrivateKeys = make(map[string]BoxECCKey)
	}

	// Give every operator a unique key pair
	// By witholding the priv key, yet forcing their malware to encrypt system keys with this key,
	// REvil can be sure they can decrypt everything encrypted by their malware, even without the cooperation
	// of their operators.
	opPub, opPriv, _ := box.GenerateKey(rand.Reader)

	r.Operators[name] = &Operator{
		OperatorPubKey: opPub,
		Campaigns:      make(map[string]*Campaign),
	}

	r.OperatorPrivateKeys[name] = opPriv

	return r.Operators[name]
}

func (o *Operator) NewCampaign(name string) *Campaign {
	if o.Campaigns == nil {
		o.Campaigns = make(map[string]*Campaign)
	}

	// The campaign key serves as a 'breakglass' for the operator.
	// Giving it to the victim will allow them to facilitate decryption for any infected systems.
	// (e.g the attacker has accidentally hit a US federal target and fears retribution)
	pub, priv, _ := box.GenerateKey(rand.Reader)
	o.Campaigns[name] = &Campaign{
		campaignPrivKey: priv,
		CampaignPubKey:  pub,
	}

	return o.Campaigns[name]
}

func (c *Campaign) EncryptSystems(v *Victim) {
	for _, sys := range v.Systems {
		sysPub, sysPriv, _ := box.GenerateKey(rand.Reader) // Encrypt every system under a new keypair

		sys.PubKey = sysPub

		// Encrypt the system private key using the campaign key, rendering it usuable to the victim.
		// As well as providing per-system decryptors, they can also just provide this key unencrypted,
		// allowing the victim to produce their own decryptors (like a breakglass).
		sys.SysPrivKeyEncrypted, _ = box.SealAnonymous(nil, sysPriv[:], c.CampaignPubKey, rand.Reader)

		for _, f := range sys.Files {
			// Encrypt every file using a new keypair...
			filePub, filePriv, _ := box.GenerateKey(rand.Reader)
			f.Nonce = nonce()
			f.Contents = box.Seal(nil, f.Contents, f.Nonce, sysPub, filePriv)

			f.PubKey = filePub // ....storing the pub key...
			filePriv = nil     // ...but discarding the private.

			// The attacker doesn't need the private file key to derive the shared key (box.Precompute).
			// All that is needed is the sysPriv key and the filePub to compute the encryption key.
			// This works because ECDH is used to derive the _actual_ encryption (XSalsa20) key.
			// This is because of math, more specifically, because of ECC scalar multiplication math, which
			// allows pub1 x priv2 to compute the same trapdoor output as pub2 x priv1. Maths is mad yo....
		}
	}
}

// DecryptAllSystems shows the 'breakglass' approach where the operator decrypts the sys priv key using the campaign key
func (c *Campaign) DecryptAllSystems(v *Victim) {
	for _, sys := range v.Systems {
		decryptionKey, _ := box.OpenAnonymous(nil, sys.SysPrivKeyEncrypted, c.CampaignPubKey, c.campaignPrivKey)

		var sysPrivKey [32]byte
		copy(sysPrivKey[:], decryptionKey)

		for _, f := range sys.Files {
			f.Contents, _ = box.Open(nil, f.Contents, f.Nonce, f.PubKey, &sysPrivKey)
		}
	}
}

// BuildDecryptor shows how the operator can develop a decryptor that can work against any file for a system
func (c *Campaign) BuildDecryptor(sys *System) func(*File) Decryptor {
	decryptionKey, _ := box.OpenAnonymous(nil, sys.SysPrivKeyEncrypted, c.CampaignPubKey, c.campaignPrivKey)

	var sysPrivKey [32]byte
	copy(sysPrivKey[:], decryptionKey)

	return func(f *File) Decryptor {
		var decryptorKey [32]byte
		box.Precompute(&decryptorKey, f.PubKey, &sysPrivKey)

		return Decryptor{
			Nonce: f.Nonce,
			Key:   &decryptorKey,
		}
	}
}

// BuildFileDecryptor shows how the operator could develop a specific decryptor per file if they wished.
func (c *Campaign) BuildFileDecryptor(sys *System, f *File) Decryptor {
	decryptionKey, _ := box.OpenAnonymous(nil, sys.SysPrivKeyEncrypted, c.CampaignPubKey, c.campaignPrivKey)

	var sysPrivKey [32]byte
	copy(sysPrivKey[:], decryptionKey)

	var decryptorKey [32]byte
	box.Precompute(&decryptorKey, f.PubKey, &sysPrivKey)

	return Decryptor{
		Nonce: f.Nonce,
		Key:   &decryptorKey,
	}
}
