package data

import (
	"fmt"
)

type IPattack interface {
	Parse()
}

type IPgetMAC struct {
	Addr []byte
	MAC  []byte
}

func (i *IPgetMAC) Parse() {
	fmt.Println("Hellow broh!")
}
