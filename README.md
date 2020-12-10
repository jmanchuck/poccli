# CLI for MassNet PoC

## Build

`go build`

## CLI Commands

### Initialize data and plot

Creates HashMap B at some directory.

`./mass init bitlength directory pubKey`

bitlength: larger bitlength results in larger file but easier to find proof
directory: an existing directory that will contain the .massdb file
pubKey: public key string

### Generate proof

Generates a verifiable proof from a HashMap B (.massdb) file by rehashing challenge until a valid proof is generated.

`./mass generate directory pubKey challenge bitlength`

directory: the directory that contains the massdb file
pubKey: public key string
challenge: challenge parameter string
bitlength: bit length of the data (from init)

Outputs to terminal:
Proof string: a bitstring representation of X and XPrime

Example: 110100011010101111011101,010111010100101011100101

### Verify proof

Verifies a proof.

`./mass verify proofString pubKey challenge bitlength`

proofString: the proof string from generate proof
pubKey: public key string
challenge: challenge parameter string
bitlength: bitlength of the data from proof provider

# Full example

PubKey: 0372a265421441050884d204292775565b9e7d16dd574a47e64cefff0ec1829ad3
Bitlength: 24
Challenge: 0372a265421441050884d204292775565b9e7d16dd574a47e64cefff0ec1829ad3
Directory: test_24bl

## Initialize

`mkdir test_24bl`
`./mass init 24 test_24bl 0372a265421441050884d204292775565b9e7d16dd574a47e64cefff0ec1829ad3 0372a265421441050884d204292775565b9e7d16dd574a47e64cefff0ec1829ad3`

## Generate proof

`./mass generate test_24bl f17a8b5534fb1a9d34c831d0766fbc77b0b718500412c6647f48fda0dd8fa780 0372a265421441050884d204292775565b9e7d16dd574a47e64cefff0ec1829ad3 24`

Proof string: 110100011010101111011101,010111010100101011100101

## Verify proof

`./mass verify 110100011010101111011101,010111010100101011100101 f17a8b5534fb1a9d34c831d0766fbc77b0b718500412c6647f48fda0dd8fa780 0372a265421441050884d204292775565b9e7d16dd574a47e64cefff0ec1829ad3 24`
