package htOTP

import (
	"crypto/hmac"
	"encoding/binary"
	"fmt"
	"hash"
	"math"
	"strconv"
	"time"
)

//Password struct contains values for hotp/totp calculations
//and is used to call latter functions
type Password struct {
	Secret  string
	Counter int
	Digits  int
	Step    time.Duration
	Base    time.Time
	Hash    func() hash.Hash
}

//HOTP func returns a string that represents calculated hotp password
func (p *Password) HOTP() string {
	if p.Digits > 10 {
		p.Digits = 10
	}
	if p.Digits < 1 {
		p.Digits = 1
	}
	//due to nature of Go func hmac.New does not take a counter arg
	//like for example Pythons hmac.new does
	//that is the reason for using binary.Write
	hmac := hmac.New(p.Hash, []byte(p.Secret))

	//counter is passed as an uint64 for correct calculations
	//uint32 gives different results
	binary.Write(hmac, binary.BigEndian, uint64(p.Counter))

	sha := hmac.Sum(nil)

	offset := sha[19] & 0xf

	binCode := ((uint64(sha[offset]))<<24 | (uint64(sha[offset+1]))<<16 |
		(uint64(sha[offset+2]))<<8 | (uint64(sha[offset+3]))) & 0x7fffffff

	hotp := binCode % uint64(math.Pow10(p.Digits))

	hotpAsString := strconv.Itoa(int(hotp))

	//filling up with zeros if password is not long enough
	for len(hotpAsString) < int(p.Digits) {
		hotpAsString = "0" + hotpAsString
	}

	return hotpAsString
}

//TOTP func calls hotp with changed counter based on time
//passed since unix base time and returns hotp result
func (p *Password) TOTP() string {

	totp := time.Now().UnixNano()

	p.Counter = int(totp / int64(p.Step))

	return p.HOTP()
}
