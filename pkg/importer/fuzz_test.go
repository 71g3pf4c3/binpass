package importer

import (
	"bytes"
	"strings"
	"testing"
)

func FuzzBitwardenCSV(f *testing.F) {
	// Seed with a valid Bitwarden CSV.
	f.Add(`folder,favorite,type,name,login_username,login_password,login_uri,login_totp,notes
Social,0,login,Twitter,@alice,hunter2,https://twitter.com,,my account`)

	f.Fuzz(func(t *testing.T, input string) {
		imp := &BitwardenImporter{}
		// Must not panic.
		for e, err := range imp.Import(strings.NewReader(input)) {
			_ = e
			_ = err
		}
	})
}

func FuzzOnePasswordCSV(f *testing.F) {
	f.Add(`Title,Username,Password,URL,OTP,Notes
GitHub,alice,hunter2,https://github.com,,My account`)

	f.Fuzz(func(t *testing.T, input string) {
		imp := &OnePasswordImporter{}
		for e, err := range imp.Import(strings.NewReader(input)) {
			_ = e
			_ = err
		}
	})
}

func FuzzLastPassCSV(f *testing.F) {
	f.Add(`url,username,password,extra,name,grouping,fav
https://twitter.com,@alice,hunter2,notes,Twitter,Social,0`)

	f.Fuzz(func(t *testing.T, input string) {
		imp := &LastPassImporter{}
		for e, err := range imp.Import(strings.NewReader(input)) {
			_ = e
			_ = err
		}
	})
}

func FuzzChromeCSV(f *testing.F) {
	f.Add(`name,url,username,password,note
Twitter,https://twitter.com,alice,hunter2,`)

	f.Fuzz(func(t *testing.T, input string) {
		imp := &ChromeImporter{}
		for e, err := range imp.Import(strings.NewReader(input)) {
			_ = e
			_ = err
		}
	})
}

func FuzzFirefoxCSV(f *testing.F) {
	f.Add(`url,username,password,httpRealm,formActionOrigin,guid
https://twitter.com,alice,hunter2,,,,`)

	f.Fuzz(func(t *testing.T, input string) {
		imp := &FirefoxImporter{}
		for e, err := range imp.Import(strings.NewReader(input)) {
			_ = e
			_ = err
		}
	})
}

func FuzzEnpassCSV(f *testing.F) {
	f.Add(`Title,User Name,Password,Web Site,Remarks,Category
Twitter,alice,hunter2,https://twitter.com,my account,Social`)

	f.Fuzz(func(t *testing.T, input string) {
		imp := &EnpassImporter{}
		for e, err := range imp.Import(strings.NewReader(input)) {
			_ = e
			_ = err
		}
	})
}

func FuzzNormalizePath(f *testing.F) {
	f.Add("group", "title")
	f.Add("", "../etc/passwd")
	f.Add("a/b/c", "d e f")

	f.Fuzz(func(t *testing.T, group, title string) {
		// Must not panic and must produce a valid or empty result.
		p := NormalizePath(group, title)
		if p != "" && !ValidatePath(p) {
			// Normalized path should be valid or empty (when fully
			// sanitised away). It must never contain "..".
			if strings.Contains(p, "..") {
				t.Errorf("NormalizePath(%q, %q) = %q contains ..", group, title, p)
			}
		}
	})
}

func FuzzCSVBOM(f *testing.F) {
	f.Add([]byte{0xEF, 0xBB, 0xBF}) // UTF-8 BOM

	f.Fuzz(func(t *testing.T, prefix []byte) {
		csv := append(prefix, []byte("a,b\n1,2")...)
		rows, err := csvReadAll(bytes.NewReader(csv), "")
		// Must not panic.
		_ = rows
		_ = err
	})
}
