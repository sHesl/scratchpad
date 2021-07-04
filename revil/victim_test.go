package revil_test

import (
	"fmt"
	"testing"

	"github.com/sHesl/scratchpad/revil"
)

func TestVictim(t *testing.T) {
	r := revil.REvil{}
	toxicorp := r.NewOperator("toxicorp")
	c1 := toxicorp.NewCampaign("1")

	v := &revil.Victim{}
	v.Systems = map[string]*revil.System{
		"prod": {
			Files: []*revil.File{
				{Contents: []byte("hello prod")},
				{Contents: []byte("PII everywhere!")},
			},
		},
		"PCI": {
			Files: []*revil.File{
				{Contents: []byte("hello CDE")},
				{Contents: []byte("CHD everywhere!")},
			},
		},
	}

	for _, sys := range v.Systems {
		for _, f := range sys.Files {
			fmt.Printf("%s\n", f.Contents)
		}
	}

	c1.EncryptSystems(v)

	for _, sys := range v.Systems {
		for _, f := range sys.Files {
			fmt.Printf("%s\n", f.Contents)
		}
	}

	c1.DecryptAllSystems(v)

	for _, sys := range v.Systems {
		for _, f := range sys.Files {
			fmt.Printf("%s\n", f.Contents)
		}
	}
}

func TestSystemDecryptor(t *testing.T) {
	r := revil.REvil{}
	toxicorp := r.NewOperator("toxicorp")
	c1 := toxicorp.NewCampaign("3")

	v := &revil.Victim{}
	v.Systems = map[string]*revil.System{
		"prod": {
			Files: []*revil.File{
				{Contents: []byte("hello prod")},
				{Contents: []byte("PII everywhere!")},
			},
		},
	}

	f := v.Systems["prod"].Files[0]
	fmt.Printf("Pre-Encrypt: %s\n", f.Contents)
	c1.EncryptSystems(v)
	fmt.Printf("Post-Encrypt: %s\n", f.Contents)

	d := c1.BuildDecryptor(v.Systems["prod"])
	v.DecryptSystem("prod", d)
	fmt.Printf("Decrypted: %s\n", f.Contents)
}

func TestFileDecryptor(t *testing.T) {
	r := revil.REvil{}
	toxicorp := r.NewOperator("toxicorp")
	c1 := toxicorp.NewCampaign("3")

	v := &revil.Victim{}
	v.Systems = map[string]*revil.System{
		"prod": {
			Files: []*revil.File{
				{Contents: []byte("hello prod")},
				{Contents: []byte("PII everywhere!")},
			},
		},
	}

	f := v.Systems["prod"].Files[0]
	fmt.Printf("Pre-Encrypt: %s\n", f.Contents)
	c1.EncryptSystems(v)
	fmt.Printf("Post-Encrypt: %s\n", f.Contents)

	decryptor := c1.BuildFileDecryptor(v.Systems["prod"], f)

	v.DecryptFile(f, decryptor)
	fmt.Printf("Decrypted: %s\n", f.Contents)

	v.DecryptFile(v.Systems["prod"].Files[1], decryptor)

	fmt.Printf("%s\n", v.Systems["prod"].Files[1].Contents)
}
