package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestBasicRequest(t *testing.T) {
	// Build the server executable
	cmd := exec.Command("go", "build", "-o", "./tmp/server", "../")
	err := cmd.Run()
	if err != nil {
		t.Fatalf("failed to build server: %v", err)
	}
	defer os.Remove("./tmp/server") // Clean up after the test
	defer os.Remove("./tmp")
	// Start the server
	serverCmd := exec.Command("./tmp/server")
	serverCmd.Stdout = os.Stdout
	serverCmd.Stderr = os.Stderr
	if err := serverCmd.Start(); err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer serverCmd.Process.Kill() // Clean up after the test

	// Wait for the server to start up
	time.Sleep(2 * time.Second)

	// Define test cases
	goodTestCases := []struct {
		url     string
		payload string
	}{
		{url: "http://localhost:8080/login", payload: ""},
		{url: "http://localhost:8080/logout", payload: ""},
		{url: "http://localhost:8080/signup", payload: ""},
	}

	badTestCases := []struct {
		url     string
		payload string
	}{
		{url: "http://localhost:8080/invalid", payload: ""},
		{url: "http://localhost:8081/login", payload: ""},
	}

	// Send requests and check responses
	for _, tc := range goodTestCases {
		// Create a new request with the appropriate URL and payload
		req, err := http.NewRequest("POST", tc.url, bytes.NewBufferString(tc.payload))
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}

		// Set the Host header to indicate port 3000
		req.Header.Set("Origin", "http://localhost:3000")

		// Send the request
		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("failed to send request: %v", err)
		}
		defer resp.Body.Close()

		// Read the response body
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("failed to read response body: %v", err)
		}

		// Check if the response status code is 200 OK
		if resp.StatusCode != http.StatusOK {
			t.Errorf("expected status code 200, got %d", resp.StatusCode)
		}

		// Optionally, you can also check the response body if needed
		fmt.Printf("Response body: %s\n", string(body))
	}

	for _, tc := range badTestCases {
		// Create a new request with the appropriate URL and payload
		req, err := http.NewRequest("POST", tc.url, bytes.NewBufferString(tc.payload))
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}
		// Set the Host header to indicate port 3000
		req.Header.Set("Origin", "http://localhost:3000")

		// Send the request
		client := &http.Client{}
		resp, err := client.Do(req)

		if strings.Contains(tc.url, "8080") {
			if err != nil {
				t.Fatalf("failed to send request: %v", err)
			}
			// Check if the response status code is 404 not found
			if resp.StatusCode != http.StatusNotFound {
				t.Errorf("expected status code 404, got %d", resp.StatusCode)
			}
		} else {
			if err == nil {
				t.Errorf("This request was expected to fail but it worked: %s", tc.url)
			}
		}
	}

	// Test bad origin
	for _, tc := range goodTestCases {
		// Create a new request with the appropriate URL and payload
		req, err := http.NewRequest("POST", tc.url, bytes.NewBufferString(tc.payload))
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}
		// Set the Host header to indicate a non-allowed port
		req.Header.Set("Origin", "http://localhost:5000")

		// Send the request
		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("failed to send request: %v", err)
		}

		// Check if the response status code is not 200 OK
		if resp.StatusCode == http.StatusOK {
			t.Errorf("When testing bad origin, did not expect status code 200")
		}
	}

	// Test bad method
	for _, tc := range goodTestCases {
		req, err := http.NewRequest("PUT", tc.url, bytes.NewBufferString(tc.payload))
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}
		// Set the Host header to indicate port 3000
		req.Header.Set("Origin", "http://localhost:3000")

		// Send the request
		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("failed to send request: %v", err)
		}
		defer resp.Body.Close()
		// Check if the response status code is not 200 OK
		if resp.StatusCode == http.StatusOK {
			t.Errorf("When testing bad method, did not expect status code 200")
		}

	}

}
