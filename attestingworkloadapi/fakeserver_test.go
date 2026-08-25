package attestingworkloadapi

import (
	"context"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/defakto-security/spiffe-defakto-go/attestingworkloadapi/internal/serverlessapi"
)

const bufSize = 1024 * 1024

// dialFakeServer starts srv in-process over a bufconn listener and returns a
// gRPC connection to it. The server and connection are closed automatically
// when the test ends.
func dialFakeServer(t *testing.T, srv serverlessapi.SpiffeWorkloadAPIServer) *grpc.ClientConn {
	t.Helper()

	lis := bufconn.Listen(bufSize)
	s := grpc.NewServer()
	serverlessapi.RegisterSpiffeWorkloadAPIServer(s, srv)
	go func() { _ = s.Serve(lis) }()
	t.Cleanup(s.Stop)

	dialer := func(context.Context, string) (net.Conn, error) { return lis.Dial() }
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(dialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial fake server: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// fakeServer is a scriptable serverlessapi.SpiffeWorkloadAPIServer for
// tests: each Fetch* method returns whatever response/error is queued, and
// records the last request it saw.
type fakeServer struct {
	serverlessapi.UnimplementedSpiffeWorkloadAPIServer

	x509Resp *serverlessapi.FetchX509SVIDResponse
	x509Err  error
	lastX509 *serverlessapi.FetchX509SVIDRequest

	jwtSVIDResp *serverlessapi.FetchJWTSVIDResponse
	jwtSVIDErr  error
	lastJWTSVID *serverlessapi.FetchJWTSVIDRequest

	jwtBundlesResp *serverlessapi.FetchJWTBundlesResponse
	jwtBundlesErr  error
}

func (f *fakeServer) FetchX509SVID(_ context.Context, req *serverlessapi.FetchX509SVIDRequest) (*serverlessapi.FetchX509SVIDResponse, error) {
	f.lastX509 = req
	if f.x509Err != nil {
		return nil, f.x509Err
	}
	return f.x509Resp, nil
}

func (f *fakeServer) FetchJWTSVID(_ context.Context, req *serverlessapi.FetchJWTSVIDRequest) (*serverlessapi.FetchJWTSVIDResponse, error) {
	f.lastJWTSVID = req
	if f.jwtSVIDErr != nil {
		return nil, f.jwtSVIDErr
	}
	return f.jwtSVIDResp, nil
}

func (f *fakeServer) FetchJWTBundles(_ context.Context, _ *serverlessapi.FetchJWTBundlesRequest) (*serverlessapi.FetchJWTBundlesResponse, error) {
	if f.jwtBundlesErr != nil {
		return nil, f.jwtBundlesErr
	}
	return f.jwtBundlesResp, nil
}
