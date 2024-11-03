help:
    just --list

gen:
    go generate ./ent

run: gen
    go run main.go --config config.yaml server

migrate: gen
    go run main.go --config config.yaml migrate
