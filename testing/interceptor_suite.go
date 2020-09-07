// Copyright 2016 Michal Witkowski. All Rights Reserved.
// See LICENSE for licensing terms.

package grpc_testing

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"time"

	pb_testproto "github.com/grpc-ecosystem/go-grpc-middleware/testing/testproto"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	testCertFilename = "cert.pem"
	testKeyFilename  = "key.pem"
)

var (
	flagTls = flag.Bool("use_tls", true, "whether all gRPC middleware tests should use tls")
)

func getTestingCertsPath() string {
	_, callerPath, _, _ := runtime.Caller(0)
	return path.Join(path.Dir(callerPath), "certs")
}

// InterceptorTestSuite is a testify/Suite that starts a gRPC PingService server and a client.
type InterceptorTestSuite struct {
	suite.Suite

	TestService pb_testproto.TestServiceServer
	ServerOpts  []grpc.ServerOption
	ClientOpts  []grpc.DialOption

	serverAddr     string
	ServerListener net.Listener
	Server         *grpc.Server
	clientConn     *grpc.ClientConn
	Client         pb_testproto.TestServiceClient

	restartServerWithDelayedStart chan time.Duration
	serverRunning                 chan bool
}

func (s *InterceptorTestSuite) SetupSuite() {
	if err := generateTestCerts(); err != nil {
		s.T().Fatal("failed to generate test certificate: " + err.Error())
	}
	s.restartServerWithDelayedStart = make(chan time.Duration)
	s.serverRunning = make(chan bool)

	s.serverAddr = "127.0.0.1:0"

	go func() {
		for {
			var err error
			s.ServerListener, err = net.Listen("tcp", s.serverAddr)
			s.serverAddr = s.ServerListener.Addr().String()
			require.NoError(s.T(), err, "must be able to allocate a port for serverListener")
			if *flagTls {
				certFile := path.Join(getTestingCertsPath(), testCertFilename)
				keyFile := path.Join(getTestingCertsPath(), testKeyFilename)
				localhostCert, err := tls.LoadX509KeyPair(certFile, keyFile)
				require.NoError(s.T(), err, "failed loading server credentials for localhostCert")
				creds := credentials.NewServerTLSFromCert(&localhostCert)
				s.ServerOpts = append(s.ServerOpts, grpc.Creds(creds))
			}
			// This is the point where we hook up the interceptor
			s.Server = grpc.NewServer(s.ServerOpts...)
			// Crete a service of the instantiator hasn't provided one.
			if s.TestService == nil {
				s.TestService = &TestPingService{T: s.T()}
			}
			pb_testproto.RegisterTestServiceServer(s.Server, s.TestService)

			go func() {
				s.Server.Serve(s.ServerListener)
			}()
			if s.Client == nil {
				s.Client = s.NewClient(s.ClientOpts...)
			}

			s.serverRunning <- true

			d := <-s.restartServerWithDelayedStart
			s.Server.Stop()
			time.Sleep(d)
		}
	}()

	select {
	case <-s.serverRunning:
	case <-time.After(2 * time.Second):
		s.T().Fatal("server failed to start before deadline")
	}
}

func (s *InterceptorTestSuite) RestartServer(delayedStart time.Duration) <-chan bool {
	s.restartServerWithDelayedStart <- delayedStart
	time.Sleep(10 * time.Millisecond)
	return s.serverRunning
}

func (s *InterceptorTestSuite) NewClient(dialOpts ...grpc.DialOption) pb_testproto.TestServiceClient {
	newDialOpts := append(dialOpts, grpc.WithBlock())
	if *flagTls {
		creds, err := credentials.NewClientTLSFromFile(
			path.Join(getTestingCertsPath(), testCertFilename), "localhost")
		require.NoError(s.T(), err, "failed reading client credentials for "+testCertFilename)
		newDialOpts = append(newDialOpts, grpc.WithTransportCredentials(creds))
	} else {
		newDialOpts = append(newDialOpts, grpc.WithInsecure())
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	clientConn, err := grpc.DialContext(ctx, s.ServerAddr(), newDialOpts...)
	require.NoError(s.T(), err, "must not error on client Dial")
	return pb_testproto.NewTestServiceClient(clientConn)
}

func (s *InterceptorTestSuite) ServerAddr() string {
	return s.serverAddr
}

func (s *InterceptorTestSuite) SimpleCtx() context.Context {
	ctx, _ := context.WithTimeout(context.TODO(), 2*time.Second)
	return ctx
}

func (s *InterceptorTestSuite) DeadlineCtx(deadline time.Time) context.Context {
	ctx, _ := context.WithDeadline(context.TODO(), deadline)
	return ctx
}

func (s *InterceptorTestSuite) TearDownSuite() {
	time.Sleep(10 * time.Millisecond)
	if s.ServerListener != nil {
		s.Server.GracefulStop()
		s.T().Logf("stopped grpc.Server at: %v", s.ServerAddr())
		s.ServerListener.Close()
	}
	if s.clientConn != nil {
		s.clientConn.Close()
	}
}

type keycert struct {
	Key, Cert string
}

func generateTestCerts() error {
	oldDir, err := os.Getwd()
	if err != nil {
		return err
	}
	newDir := getTestingCertsPath()
	if newDir == "" {
		return errors.New("error generating test certificates - unable to get testing certs path")
	}
	if err := os.Chdir(newDir); err != nil {
		return errors.New("error generating test certificates - unable to chdir to " + newDir)
	}

	defer os.Chdir(oldDir)
	if fileExists("cert.pem") && fileExists("key.pem") {
		fmt.Fprintf(os.Stderr, "DMDEBUG - cert & key already exists, skip regen\n")
		return nil
	}
	goroot := runtime.GOROOT()
	cmd := exec.Command(filepath.Join(goroot, "bin/go"),
		"run",
		filepath.Join(goroot, "src/crypto/tls/generate_cert.go"),
		"--ca",
		"--rsa-bits", "2048",
		"--host", "localhost,example.com",
		"--start-date", "Jan 1 00:00:00 2020",
		"--duration=1000000h")
	if _, err := cmd.CombinedOutput(); err != nil {
		return err
	}
	keyBytes, err := ioutil.ReadFile("key.pem")
	if err != nil {
		return err
	}
	certBytes, err := ioutil.ReadFile("cert.pem")
	if err != nil {
		return err
	}
	data := keycert{
		Key:  string(keyBytes),
		Cert: string(certBytes),
	}
	// localhost.go template
	const tmpl = `package certs

var LocalhostKey = []byte(` + "`" + `{{.Key}}` + "`" + `)

var LocalhostCert = []byte(` + "`" + `{{.Cert}}` + "`" + `)
`

	t := template.Must(template.New("keycert-go").Parse(tmpl))
	f, err := os.OpenFile("localhost.go", os.O_RDWR|os.O_TRUNC|os.O_CREATE, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := t.Execute(f, data); err != nil {
		return err
	}
	return nil
}

func fileExists(fname string) bool {
	info, err := os.Stat(fname)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}
