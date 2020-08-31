package main

import (
	"io/ioutil"
	"os"
	"testing"
)

func Fatal(err error, t *testing.T) {
	if err != nil {
		t.Fatal(err)
	}
}
func PanicError(err error) {
	if err != nil {
		panic(err)
	}
}
func ReadFile(filename string, t *testing.T) []byte {
	content, err := ioutil.ReadFile(filename)
	Fatal(err, t)
	return content
}
func WriteFile(content []byte, filename string, t *testing.T) {
	file, err := os.Create(filename)
	Fatal(err, t)
	defer func() {
		err = file.Close()
		Fatal(err, t)
	}()
	_, err = file.Write(content)
	Fatal(err, t)
}
