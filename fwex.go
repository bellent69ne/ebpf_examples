package main

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/sirupsen/logrus"
)

func main() {
	subnet := []byte{0b01011100, 0b01100011, 0b01100000, 0b00000000}
	fmt.Println(subnet)
	addr := []byte{0b01011100, 0b01100011, 0b01100100, 0b01010011}
	fmt.Println(addr)
	s, err := convertToInt([]byte(subnet))
	if err != nil {
		logrus.Fatal(err)
	}
	a, err := convertToInt(addr)
	if err != nil {
		logrus.Fatal(err)
	}
	fmt.Println(s, a)
	if match(subnet, addr) {
		logrus.Warn("WE DID IT")
	}
}

func areEqual(subnet, addr []byte) bool {
	for i := range subnet {
		if subnet[i] != addr[i] {
			return false
		}
	}
	return true
}

func matchByte(subnet, addr []byte, byteNum int) bool {
	logrus.Infoln(subnet, addr)
	b := &addr[byteNum]
	bb := *b ^ 0b00000001
	*b = bb & *b
	logrus.Infoln(subnet, addr)
	if areEqual(subnet, addr) {
		return true
	}
	bb = *b ^ 0b00000010
	*b = bb & *b
	logrus.Infoln(subnet, addr)
	if areEqual(subnet, addr) {
		return true
	}
	bb = *b ^ 0b00000100
	*b = bb & *b
	logrus.Infoln(subnet, addr)
	if areEqual(subnet, addr) {
		return true
	}
	bb = *b ^ 0b00001000
	*b = bb & *b
	logrus.Infoln(subnet, addr)
	if areEqual(subnet, addr) {
		return true
	}
	bb = *b ^ 0b00010000
	*b = bb & *b
	logrus.Infoln(subnet, addr)
	if areEqual(subnet, addr) {
		return true
	}
	bb = *b ^ 0b00100000
	*b = bb & *b
	logrus.Infoln(subnet, addr)
	if areEqual(subnet, addr) {
		return true
	}
	bb = *b ^ 0b01000000
	*b = bb & *b
	logrus.Infoln(subnet, addr)
	if areEqual(subnet, addr) {
		return true
	}
	bb = *b ^ 0b10000000
	*b = bb & *b
	logrus.Infoln(subnet, addr)
	if areEqual(subnet, addr) {
		return true
	}
	return false
}

func match(subnet, addr []byte) bool {
	if areEqual(subnet, addr) {
		return true
	}
	if matchByte(subnet, addr, 3) {
		return true
	}
	if matchByte(subnet, addr, 2) {
		return true
	}
	if matchByte(subnet, addr, 1) {
		return true
	}
	if matchByte(subnet, addr, 0) {
		return true
	}
	return false
}

func convertToInt(b []byte) (uint32, error) {
	buf := bytes.NewBuffer(b)
	var n uint32
	err := binary.Read(buf, binary.BigEndian, &n)
	return n, err
}
