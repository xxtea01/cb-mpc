module github.com/xxtea01/cb-mpc/demo-go-access-structure

go 1.23.0

toolchain go1.24.2

require github.com/xxtea01/cb-mpc/demos-go/cb-mpc-go v0.0.0-20240501131245-1eee31b51009

require (
	github.com/stretchr/testify v1.10.0 // indirect
	golang.org/x/sync v0.15.0 // indirect
)

replace github.com/xxtea01/cb-mpc/demos-go/cb-mpc-go => ../../cb-mpc-go
