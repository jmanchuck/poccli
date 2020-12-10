package massdb_v1_test

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"strconv"
	"testing"
	"time"

	"massnet.org/mass/logging"
	"massnet.org/mass/poc"
	"massnet.org/mass/poc/engine"
	massdb_v1 "massnet.org/mass/poc/engine/massdb/massdb.v1"
	"massnet.org/mass/poc/pocutil"
	"massnet.org/mass/pocec"
	"massnet.org/mass/testutil"
)

func init() {
	rand.Seed(time.Now().UnixNano())
	logging.Init("/tmp", "tmp-mass.log", logging.DebugLevel, 1, false)
}

func TestPlot(t *testing.T) {
	// testutil.SkipCI(t)

	var bl = 24
	sk, err := pocec.NewPrivateKey(pocec.S256())
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	pk := sk.PubKey()

	t.Log(hex.EncodeToString(pk.SerializeCompressed()))

	mdb, err := massdb_v1.NewMassDBV1("testdata", engine.UnknownOrdinal, pk, bl)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	result := mdb.Plot()
	if err = <-result; err != nil {
		t.Error(err)
	}
}

func TestStopPlot(t *testing.T) {
	testutil.SkipCI(t)

	var bl = 24
	sk, err := pocec.NewPrivateKey(pocec.S256())
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	pk := sk.PubKey()

	t.Log(hex.EncodeToString(pk.SerializeCompressed()))

	mdb, err := massdb_v1.NewMassDBV1("testdata", engine.UnknownOrdinal, pk, bl)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	result := mdb.Plot()
	result2 := mdb.Plot()

	time.Sleep(3 * time.Second)
	result3 := mdb.StopPlot()

	e := <-result
	e2 := <-result2
	e3 := <-result3

	t.Log("e", e)
	t.Log("e2", e2)
	t.Log("e3", e3)
}

func TestValid(t *testing.T) {
	// testutil.SkipCI(t)

	var bl = 24

	//sk, err := pocec.NewPrivateKey(pocec.S256())
	//if err != nil {
	//	t.Error(err)
	//	t.FailNow()
	//}
	//pk := sk.PubKey()

	pkByte, _ := hex.DecodeString("0372a265421441050884d204292775565b9e7d16dd574a47e64cefff0ec1829ad3")
	pk, _ := pocec.ParsePubKey(pkByte, pocec.S256())

	t.Log(hex.EncodeToString(pk.SerializeCompressed()))

	mdb, err := massdb_v1.NewMassDBV1("testdata", engine.UnknownOrdinal, pk, bl)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	result := mdb.Plot()
	if err := <-result; err != nil {
		t.Error(err)
		t.FailNow()
	}

	var validCount = 0
	var testRound = 5
	challenge := pocutil.SHA256([]byte(strconv.Itoa(rand.Int())))
	pkHash := mdb.PubKeyHash()
	t.Logf("challenge %s\n", challenge)

	for i := 0; i < testRound; i++ {
		challenge = pocutil.SHA256(challenge[:])

		if _, err := getProof(mdb, challenge, pkHash); err == nil {
			validCount++
		}
	}
	t.Logf("valid count %d/%d (%f)\n", validCount, testRound, float64(validCount)/float64(testRound))
}

func TestReadHashMap(t *testing.T) {
	var bl = 24

	pkByte, _ := hex.DecodeString("0372a265421441050884d204292775565b9e7d16dd574a47e64cefff0ec1829ad3")
	pk, _ := pocec.ParsePubKey(pkByte, pocec.S256())

	t.Log(hex.EncodeToString(pk.SerializeCompressed()))

	mdb, err := massdb_v1.NewMassDBV1("testdata", engine.UnknownOrdinal, pk, bl)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

	result := mdb.Plot()
	if err := <-result; err != nil {
		t.Error(err)
		t.FailNow()
	}
	pkHash := mdb.PubKeyHash()
	printHashMapB(mdb, pkHash)
}

func getProof(mdb *massdb_v1.MassDBV1, challenge pocutil.Hash, pkHash pocutil.Hash) (proof *poc.Proof, err error) {
	cShort := pocutil.CutHash(challenge, mdb.BitLength())
	proof = &poc.Proof{BitLength: mdb.BitLength()}
	proof.X, proof.XPrime, err = mdb.HashMapB.Get(cShort)
	fmt.Printf("cshort: %d\n", cShort)
	fmt.Printf("x: %08b, x': %08b\n", proof.X, proof.XPrime)
	if err != nil {
		return
	}
	if err = poc.VerifyProof(proof, pkHash, challenge); err != nil {
		return nil, err
	}
	return proof, nil
}

func printHashMapB(mdb *massdb_v1.MassDBV1, pkHash pocutil.Hash) {
	for z := pocutil.PoCValue(0); z < 100; z++ {
		X, XPrime, _ := mdb.HashMapB.Get(z)
		fmt.Printf("z[%d] = x: %08b, x': %08b   ", z, X, XPrime)
		fmt.Printf("FB(x, x', bl, pubKeyHash) = %d\n", pocutil.FB(X, XPrime, mdb.BitLength(), pkHash))
	}
}
