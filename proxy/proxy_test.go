package proxy

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/flashbots/cvm-reverse-proxy/common"
	"github.com/flashbots/cvm-reverse-proxy/internal/atls"
	"github.com/stretchr/testify/require"
)

func getTestLogger() *slog.Logger {
	return common.SetupLogger(&common.LoggingOpts{
		Debug:   true,
		JSON:    false,
		Service: "test",
		Version: "test",
	})
}

func Test_Handlers_Healthcheck_Drain_Undrain(t *testing.T) {
	testEchoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "checkcheck")
	}))
	defer testEchoServer.Close()

	proxy := NewProxy(getTestLogger(), testEchoServer.URL, []atls.Validator{})

	{ // Check green path
		req := httptest.NewRequest(http.MethodGet, "http://proxyhost.should.not.matter/", nil) //nolint:goconst,nolintlint
		w := httptest.NewRecorder()
		proxy.ServeHTTP(w, req)
		resp := w.Result()
		defer resp.Body.Close()
		respBody, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode, "Must return `Ok`")
		require.Equal(t, []byte("checkcheck"), respBody)
	}

	// Check failure if measurement header is present
	for _, header := range []string{AttestationTypeHeader, MeasurementHeader} {
		req := httptest.NewRequest(http.MethodGet, "http://proxyhost.should.not.matter/", nil) //nolint:goconst,nolintlint
		req.Header.Add(header, "xx")
		w := httptest.NewRecorder()
		proxy.ServeHTTP(w, req)
		resp := w.Result()
		defer resp.Body.Close()
		respBody, err := io.ReadAll(resp.Body)
		require.NoError(t, err)
		require.Equal(t, http.StatusForbidden, resp.StatusCode, "Must return `Forbidden` on measurements header")
		require.Contains(t, string(respBody), "unexpected")
	}
}
