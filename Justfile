help:
    just --list

gen:
    go generate ./ent

run: gen
    go run main.go