package main

import (
	"html/template"
	"os"
)

func main() {
	t, err := template.ParseFiles("hello.gohtml")
	if err != nil {
		panic(err)
	}

	data := struct {
		Name    string
		Email   string
		Friends []string
	}{
		Name:    "John Smith",
		Email:   "john@smith.com",
		Friends: []string{"Alice", "Bob", "Charlie"},
	}

	err = t.Execute(os.Stdout, data)
	if err != nil {
		panic(err)
	}
}
