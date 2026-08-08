// Package binary handles base64-encoded binary secrets in the password store.
//
// Binary entries follow the gopass convention: they are stored as regular
// encrypted entries whose name ends in ".b64" and whose plaintext content is
// the base64 representation of the original binary data.
//
// Operations:
//   - Cat: decode a .b64 entry and stream to a writer
//   - Sum: compute SHA-256 of the decoded binary content
//   - Store: read binary data, base64-encode, and store as a .b64 entry
//   - StoreAndHash: Store that also returns the SHA-256 of the input
//   - IsBinary: check if a name has the .b64 suffix
//   - DetectBinary: heuristic detection of base64-only secrets
//
// Streaming: Cat and Sum decode base64 on the fly without buffering the full
// decoded output. Store encodes the input in one pass but the resulting
// base64 string must fit in memory (the underlying crypto layer requires the
// full plaintext).
package binary
