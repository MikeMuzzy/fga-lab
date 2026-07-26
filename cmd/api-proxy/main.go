package main

import (
	"fga-lib/pkg/authz"
	"log"
)

func main() {
	if _, err := authz.NewFGA(); err != nil {
		log.Fatal(err)
	}
}
