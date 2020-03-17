package dos

import (
	"log"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetInterfaces(t *testing.T) {
	ifaces, err := getInterfaces()
	if err != nil {
		log.Fatal(err)
	}
	assert.NotEmpty(t, ifaces)
}
