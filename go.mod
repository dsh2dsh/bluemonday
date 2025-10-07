module github.com/dsh2dsh/bluemonday

go 1.24.0

require (
	github.com/aymerick/douceur v0.2.0
	github.com/stretchr/testify v1.11.1
	golang.org/x/net v0.44.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/gorilla/css v1.0.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

retract [v1.0.0, v1.0.25] // Retract older versions as only latest is to be depended upon
