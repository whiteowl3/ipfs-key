package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	b64 "encoding/base64"

	ci "github.com/libp2p/go-libp2p-crypto"
	peer "github.com/libp2p/go-libp2p-peer"
)

type Identity struct {
	ID      string `json:"ID"`
	PrivKey string `json:"PrivKey"`
}

func main() {
	size := flag.Int("bitsize", 2048, "select the bitsize of the key to generate")
	typ := flag.String("type", "ed25519", "select type of key to generate (RSA or Ed25519)")
	quant := flag.Int("quantity", 1, "select the number of keys to generate")

	flag.Parse()

	var atyp int
	switch strings.ToLower(*typ) {
	case "rsa":
		atyp = ci.RSA
	case "ed25519":
		atyp = ci.Ed25519
	default:
		fmt.Fprintln(os.Stderr, "unrecognized key type: ", *typ)
		os.Exit(1)
	}

	//m := make(map[string]Identity)
	m := make(map[string]string)
	for i := 0; i < *quant; i++ {
		//fmt.Fprintf(os.Stderr, "Generating a %d bit %s key...\n", *size, *typ)
		priv, pub, err := ci.GenerateKeyPair(atyp, *size)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		//fmt.Fprintln(os.Stderr, "Success!")

		pid, err := peer.IDFromPublicKey(pub)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		//fmt.Println(pid.Pretty())

		data, err := priv.Bytes()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		//m[fmt.Sprint(i)] = Identity{
		//	ID:      pid.Pretty(),
		//	PrivKey: b64.StdEncoding.EncodeToString(data),
		//}

		m[pid.Pretty()] = b64.StdEncoding.EncodeToString(data)

	}
	jsonStr, _ := json.Marshal(m)
	fmt.Print(string(jsonStr))
}
