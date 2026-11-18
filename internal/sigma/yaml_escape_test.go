// SPDX-FileCopyrightText: 2026 Rashik Adhikari
// SPDX-License-Identifier: Apache-2.0

package sigma

import "testing"

// A code point past Unicode's last, however large, is no character: the
// escape is left as it was written, never turned into another character by
// wrapping around.
func TestAnEscapePastTheLastCodePointIsLeftAsWritten(t *testing.T) {
	for in, want := range map[string]string{
		`\U0001F600`: "\U0001F600",
		`A`:          "A",
		`\U00110000`: `\U00110000`,
		`\U7FFFFFFF`: `\U7FFFFFFF`,
		`\UFFFFFFFF`: `\UFFFFFFFF`,
		`\U80000041`: `\U80000041`,
	} {
		if got := unescape(in); got != want {
			t.Errorf("unescape(%q) = %q, want %q", in, got, want)
		}
	}
}
