package main

import (
	hex "encoding/hex"
	"fmt"
	"github.com/urfave/cli/v2"
	"log"
	poc "massnet.org/mass/poc"
	"massnet.org/mass/poc/engine"
	massdb_v1 "massnet.org/mass/poc/engine/massdb/massdb.v1"
	"massnet.org/mass/poc/pocutil"
	"massnet.org/mass/pocec"
	"os"
	"strings"

	strconv "strconv"
)

type bitString string

// CreateDB returns the pointer to created database
// bl: bitLength
func CreateDB(bl int, directory string, pubkey string) (*massdb_v1.MassDBV1, error) {

	pkByte, _ := hex.DecodeString(pubkey)
	pk, _ := pocec.ParsePubKey(pkByte, pocec.S256())

	fmt.Println(hex.EncodeToString(pk.SerializeCompressed()))

	mdb, err := massdb_v1.NewMassDBV1(directory, engine.UnknownOrdinal, pk, bl)

	if err != nil {
		return nil, err
	}

	result := mdb.Plot()
	if err := <-result; err != nil {
		return nil, err
	}

	return mdb, nil
}

// ByteArrayToString codes a byte array into string
func ByteArrayToString(arr []byte) (result string) {
	result = ""
	for _, b := range arr {
		bInt := int64(b)
		str := strconv.FormatInt(bInt, 2)

		// Add leading 0 bits
		for i := len(str); i < 8; i++ {
			result += "0"
		}
		result += str
	}
	return result
}

// Method for bitString (string) to convert into a []byte for proof
func (b bitString) AsByteSlice() []byte {
	var out []byte
	var str string

	for i := len(b); i > 0; i -= 8 {
		if i-8 < 0 {
			str = string(b[0:i])
		} else {
			str = string(b[i-8 : i])
		}
		v, err := strconv.ParseUint(str, 2, 8)
		if err != nil {
			panic(err)
		}
		out = append([]byte{byte(v)}, out...)
	}
	return out
}

// GenerateProof challenges the mdb located in filepath, given the challenge string/byte
func GenerateProof(directory string, pubkey string, bl int, challenge pocutil.Hash) (result string, proof *poc.Proof, err error) {
	pkByte, _ := hex.DecodeString(pubkey)
	pk, _ := pocec.ParsePubKey(pkByte, pocec.S256())
	mdb, err := massdb_v1.NewMassDBV1(directory, engine.UnknownOrdinal, pk, bl)
	if err != nil {
		fmt.Println("Couldn't open massdb")
		return "", nil, err
	}

	cShort := pocutil.CutHash(challenge, mdb.BitLength())
	proof = &poc.Proof{BitLength: mdb.BitLength()}
	proof.X, proof.XPrime, err = mdb.HashMapB.Get(cShort)

	if err != nil {
		return "", nil, err
	}
	fmt.Println()
	xString := ByteArrayToString(proof.X)
	xPrimeString := ByteArrayToString(proof.XPrime)
	result = xString + "," + xPrimeString
	return result, proof, nil

}

// VerifyProof verifies the proof and returns whether proof is successful
func VerifyProof(proof *poc.Proof, pkHash pocutil.Hash, challenge pocutil.Hash) (result bool, err error) {
	err = poc.VerifyProof(proof, pkHash, challenge)
	if err != nil {
		return false, err
	}
	return true, nil
}

func main() {
	app := &cli.App{
		Commands: []*cli.Command{
			{
				Name:  "init",
				Usage: "initialize a database, params: bitlength, directory, pubkey",
				Action: func(c *cli.Context) error {
					if len(os.Args) != 5 {
						fmt.Println("Usage: ./mass init bitlength directory pubkey")
						os.Exit(0)
					}
					bl, err := strconv.Atoi(os.Args[2])
					if err != nil {
						log.Fatal(err)
					}
					directory := os.Args[3]
					pubkey := os.Args[4]
					_, err = CreateDB(bl, directory, pubkey)
					if err != nil {
						log.Fatal(err)
					}
					return nil
				},
			},
			{
				Name:        "generate",
				Usage:       "./mass generate directory challengestring pubkeystring bitlength",
				Description: "generates challenge for given challenge parameter",
				Action: func(c *cli.Context) error {
					if len(os.Args) != 6 {
						fmt.Println("Usage: ./mass generate directory challengestring pubkeystring bitlength")
						os.Exit(0)
					}
					directory := os.Args[2]
					challenge, err := pocutil.DecodeStringToHash(os.Args[3])
					if err != nil {
						log.Fatal(err)
					}

					pubkey := os.Args[4]
					pkByte, _ := hex.DecodeString(pubkey)
					pk, err := pocec.ParsePubKey(pkByte, pocec.S256())
					if err != nil {
						log.Fatal(err)
					}
					pubKeyHash := pocutil.PubKeyHash(pk)

					bl, err := strconv.Atoi(os.Args[5])
					if err != nil {
						log.Fatal(err)
					}
					result, proof, _ := GenerateProof(directory, pubkey, bl, challenge)
					validProof, err := VerifyProof(proof, pubKeyHash, challenge)
					numRehash := 0
					for !validProof {
						challenge = pocutil.SHA256(challenge[:])
						result, proof, _ = GenerateProof(directory, pubkey, bl, challenge)
						validProof, err = VerifyProof(proof, pubKeyHash, challenge)
						numRehash++
					}
					fmt.Printf("Proof string: %s\n", result)
					fmt.Printf("Challenge was rehashed %d times for valid proof\n", numRehash)
					return nil
				},
			},
			{
				Name:  "verify",
				Usage: "verifies challenge with challenge parameter",
				Action: func(c *cli.Context) error {
					if len(os.Args) != 6 {
						fmt.Println("Usage: ./mass verify proofstring challengestring pubkeystring bitlength")
						os.Exit(0)
					}
					proofString := os.Args[2]
					challenge, err := pocutil.DecodeStringToHash(os.Args[3])
					if err != nil {
						log.Fatal(err)
					}

					pubkey := os.Args[4]
					bl, err := strconv.Atoi(os.Args[5])
					if err != nil {
						log.Fatal(err)
					}

					proofSplit := strings.Split(proofString, ",")

					x := bitString(proofSplit[0]).AsByteSlice()
					xp := bitString(proofSplit[1]).AsByteSlice()
					proof := &poc.Proof{X: x,
						XPrime:    xp,
						BitLength: bl}

					pkByte, _ := hex.DecodeString(pubkey)
					pk, err := pocec.ParsePubKey(pkByte, pocec.S256())
					if err != nil {
						log.Fatal(err)
					}
					pubKeyHash := pocutil.PubKeyHash(pk)

					result, err := VerifyProof(proof, pubKeyHash, challenge)

					if err != nil {
						log.Fatal(err)
					}

					if result {
						fmt.Println("Successful proof")
					} else {
						fmt.Println("Unsuccessful proof")
					}

					return nil
				},
			},
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}
