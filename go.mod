module github.com/openshift-online/rosa-boundary

go 1.26.0

toolchain go1.27.4

require (
	github.com/aws/aws-sdk-go-v2 v1.48.0
	github.com/aws/aws-sdk-go-v2/credentials v1.21.3
	github.com/aws/aws-sdk-go-v2/service/ecs v1.106.0
	github.com/aws/aws-sdk-go-v2/service/efs v1.51.6
	github.com/aws/aws-sdk-go-v2/service/lambda v1.118.0
	github.com/aws/aws-sdk-go-v2/service/s3 v1.116.0
	github.com/aws/aws-sdk-go-v2/service/sts v1.53.0
	github.com/aws/smithy-go v1.28.9
	github.com/dustinkirkland/golang-petname v0.0.0-20261016130456-fdd95a3d0543
	github.com/spf13/cobra v1.10.2
	golang.org/x/oauth2 v0.38.0
	golang.org/x/term v0.48.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.7.27 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.5.12 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.8.12 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.5.12 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.25 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.11.13 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.14.12 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.20.12 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/spf13/pflag v1.1.0 // indirect
	golang.org/x/sys v0.50.0 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
)
