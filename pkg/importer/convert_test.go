package importer

import "testing"

// TestAttachmentStorePathSanitisesTheName covers a crafted export: the
// attachment name is chosen by whoever wrote the file being imported, and it
// used to be concatenated into a store path verbatim. storage still blocked
// an escape out of the store, so the damage was bounded to planting entries
// at attacker-chosen paths inside it — which is still the attacker choosing
// what a later `binpass show <name>` reads.
func TestAttachmentStorePathSanitisesTheName(t *testing.T) {
	tests := []struct {
		name string
		// attachment is the untrusted name from the import file.
		attachment string
		want       string
		wantErr    bool
	}{
		{name: "ordinary name", attachment: "file.pdf", want: "doc/file.pdf.b64"},
		{name: "traversal", attachment: "../../x", want: "doc/x.b64"},
		{name: "single parent", attachment: "../x", want: "doc/x.b64"},
		{name: "traversal in the middle", attachment: "a/../../x", want: "doc/a/x.b64"},
		{name: "absolute path", attachment: "/etc/passwd", want: "doc/etc/passwd.b64"},
		{name: "windows separator", attachment: `..\..\x`, want: "doc/._._x.b64"},
		{name: "only traversal", attachment: "../..", want: "doc/attachment-1.b64"},
		{name: "empty name", attachment: "", want: "doc/attachment-1.b64"},
		{name: "subdirectory is kept", attachment: "notes/a.txt", want: "doc/notes/a.txt.b64"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &Entry{
				Title:       "doc",
				Attachments: []Attachment{{Name: tt.attachment, Data: []byte("x")}},
			}
			got, err := e.AttachmentStorePath(0)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("AttachmentStorePath = %q, want an error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("AttachmentStorePath: %v", err)
			}
			if got != tt.want {
				t.Errorf("AttachmentStorePath = %q, want %q", got, tt.want)
			}
			if !ValidatePath(got) {
				t.Errorf("AttachmentStorePath = %q, which ValidatePath rejects", got)
			}
		})
	}
}
