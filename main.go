package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	maxBodyBytes = 1 << 20 // 1 MiB
)

type requestInput struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    json.RawMessage   `json:"body,omitempty"`
}

type loopInput struct {
	requestInput
	Count int `json:"count"`
}

type responseOutput struct {
	StatusCode int                 `json:"status_code"`
	Headers    map[string][]string `json:"headers"`
	Body       string              `json:"body"`
	Truncated  bool                `json:"truncated"`
}

type loopResponse struct {
	Requested int              `json:"requested"`
	Completed int              `json:"completed"`
	Results   []responseOutput `json:"results"`
	Errors    []string         `json:"errors,omitempty"`
}

type loopResult struct {
	index  int
	result responseOutput
	err    error
}

type errorOutput struct {
	Error string `json:"error"`
}

func main() {
	addr := getenv("PORT", "8080")
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", healthHandler)
	mux.HandleFunc("POST /bot/request", requestHandler)
	mux.HandleFunc("POST /bot/loop", loopHandler)

	server := &http.Server{
		Addr:              ":" + addr,
		Handler:           loggingMiddleware(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      5 * time.Minute,
		IdleTimeout:       60 * time.Second,
	}

	log.Printf("Go HTTP bot listening on http://localhost:%s", addr)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}

func healthHandler(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func requestHandler(w http.ResponseWriter, r *http.Request) {
	var input requestInput
	if !decodeJSON(w, r, &input) {
		return
	}
	result, err := executeRequest(r.Context(), input)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func loopHandler(w http.ResponseWriter, r *http.Request) {
	var input loopInput
	if !decodeJSON(w, r, &input) {
		return
	}
	if input.Count < 1 {
		writeError(w, http.StatusBadRequest, "count must be at least 1")
		return
	}

	results := make(chan loopResult, input.Count)
	var workers sync.WaitGroup
	workers.Add(input.Count)
	for index := 0; index < input.Count; index++ {
		go func(index int) {
			defer workers.Done()
			result, err := executeRequest(r.Context(), input.requestInput)
			results <- loopResult{index: index, result: result, err: err}
		}(index)
	}
	workers.Wait()
	close(results)

	ordered := make([]loopResult, input.Count)
	for result := range results {
		ordered[result.index] = result
	}
	output := loopResponse{Requested: input.Count, Results: []responseOutput{}}
	for index, result := range ordered {
		if result.err != nil {
			output.Errors = append(output.Errors, fmt.Sprintf("request %d: %s", index+1, result.err.Error()))
			continue
		}
		output.Results = append(output.Results, result.result)
		output.Completed++
	}
	writeJSON(w, http.StatusOK, output)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, destination any) bool {
	if !strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/json") {
		writeError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
		return false
	}
	decoder := json.NewDecoder(io.LimitReader(r.Body, maxBodyBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return false
	}
	return true
}

func executeRequest(ctx context.Context, input requestInput) (responseOutput, error) {
	method := strings.ToUpper(strings.TrimSpace(input.Method))
	if method == "" {
		method = http.MethodGet
	}
	if !allowedMethod(method) {
		return responseOutput{}, fmt.Errorf("method must be one of GET, POST, PUT, PATCH, DELETE, HEAD, or OPTIONS")
	}

	target, err := validateURL(input.URL)
	if err != nil {
		return responseOutput{}, err
	}

	var body io.Reader
	if len(input.Body) > 0 && string(input.Body) != "null" {
		body = strings.NewReader(string(input.Body))
	}
	outbound, err := http.NewRequestWithContext(ctx, method, target.String(), body)
	if err != nil {
		return responseOutput{}, fmt.Errorf("could not create request: %w", err)
	}
	for key, value := range input.Headers {
		if strings.EqualFold(key, "Host") || strings.EqualFold(key, "Content-Length") {
			continue
		}
		outbound.Header.Set(key, value)
	}
	if outbound.Body != nil && outbound.Header.Get("Content-Type") == "" {
		outbound.Header.Set("Content-Type", "application/json")
	}

	response, err := httpClient().Do(outbound)
	if err != nil {
		return responseOutput{}, fmt.Errorf("outbound request failed: %w", err)
	}
	defer response.Body.Close()

	const maxResponseBytes = 2 << 20 // 2 MiB
	data, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		return responseOutput{}, fmt.Errorf("could not read outbound response: %w", err)
	}
	truncated := len(data) > maxResponseBytes
	if truncated {
		data = data[:maxResponseBytes]
	}

	headers := make(map[string][]string, len(response.Header))
	for key, values := range response.Header {
		headers[key] = values
	}
	return responseOutput{StatusCode: response.StatusCode, Headers: headers, Body: string(data), Truncated: truncated}, nil
}

func httpClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				host, _, splitErr := net.SplitHostPort(address)
				if splitErr != nil {
					return nil, splitErr
				}
				if isPrivateOrLocalHost(host) {
					return nil, fmt.Errorf("requests to private or local addresses are not allowed")
				}
				dialer := &net.Dialer{}
				return dialer.DialContext(ctx, network, address)
			},
		},
	}
}

func validateURL(raw string) (*url.URL, error) {
	target, err := url.ParseRequestURI(strings.TrimSpace(raw))
	if err != nil || target.Scheme == "" || target.Hostname() == "" {
		return nil, fmt.Errorf("url must be an absolute HTTP or HTTPS URL")
	}
	if target.Scheme != "http" && target.Scheme != "https" {
		return nil, fmt.Errorf("only HTTP and HTTPS URLs are supported")
	}
	if isPrivateOrLocalHost(target.Hostname()) {
		return nil, fmt.Errorf("requests to private or local addresses are not allowed")
	}
	return target, nil
}

func allowedMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodHead, http.MethodOptions:
		return true
	default:
		return false
	}
}

func isPrivateOrLocalHost(host string) bool {
	if strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, errorOutput{Error: message})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		started := time.Now()
		next.ServeHTTP(w, r)
		log.Printf("%s %s %s", r.Method, r.URL.Path, time.Since(started).Round(time.Millisecond))
	})
}

func getenv(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	if _, err := strconv.Atoi(value); err != nil {
		return fallback
	}
	return value
}
