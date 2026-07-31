// Module api holds the binpass wire contract: the protobuf/gRPC definitions and
// generated Go code shared by the binpass client and the binpassd server.
module github.com/71g3pf4c3/binpass/api

go 1.26.5

require (
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.29.0
	google.golang.org/genproto/googleapis/api v0.0.0-20260729162451-8efbd57d26e0
	google.golang.org/grpc v1.83.0
	google.golang.org/protobuf v1.36.11
)

require (
	golang.org/x/net v0.55.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
	golang.org/x/text v0.37.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260727163830-6c54dddc4772 // indirect
)
