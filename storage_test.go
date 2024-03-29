// MIT License
//
// Copyright (c) 2021-2023 TTBT Enterprises LLC
// Copyright (c) 2021-2023 Robin Thellend <rthellend@rthellend.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package storage

import (
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/c2FmZQ/tpm"
	"github.com/google/go-tpm-tools/simulator"

	"github.com/c2FmZQ/storage/crypto"
)

var globalTPM *tpm.TPM
var tpmOnce sync.Once

func aesEncryptionKey() crypto.EncryptionKey {
	mk, err := crypto.CreateAESMasterKeyForTest()
	if err != nil {
		panic(err)
	}
	return mk.(crypto.EncryptionKey)
}

func ccEncryptionKey() crypto.EncryptionKey {
	mk, err := crypto.CreateChacha20Poly1305MasterKeyForTest()
	if err != nil {
		panic(err)
	}
	return mk.(crypto.EncryptionKey)
}

func tpmEncryptionKey() crypto.EncryptionKey {
	tpmOnce.Do(func() {
		rwc, err := simulator.Get()
		if err != nil {
			panic(err)
		}
		tpm, err := tpm.New(tpm.WithTPM(rwc))
		if err != nil {
			panic(err)
		}
		globalTPM = tpm
	})
	mk, err := crypto.CreateAESMasterKey(crypto.WithTPM(globalTPM), crypto.WithStrictWipe(false))
	if err != nil {
		panic(err)
	}
	return mk.(crypto.EncryptionKey)
}

func TestLock(t *testing.T) {
	dir := t.TempDir()
	s := New(dir, aesEncryptionKey())
	fn := "foo"

	if err := s.Lock(fn); err != nil {
		t.Fatalf("Lock() failed: %v", err)
	}
	go func() {
		time.Sleep(100 * time.Millisecond)
		s.Unlock(fn)
	}()
	if err := s.Lock(fn); err != nil {
		t.Errorf("Lock() failed: %v", err)
	}
	if err := s.Unlock(fn); err != nil {
		t.Errorf("Unlock() failed: %v", err)
	}
}

func TestOpenForUpdate(t *testing.T) {
	testcases := []struct {
		name string
		mk   crypto.EncryptionKey
	}{
		{"AES", aesEncryptionKey()},
		{"Chacha20Poly1305", ccEncryptionKey()},
		{"TPM", tpmEncryptionKey()},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			fn := "test.json"
			s := New(dir, tc.mk)

			type Foo struct {
				Foo string `json:"foo"`
			}
			foo := Foo{"foo"}
			if err := s.SaveDataFile(fn, foo); err != nil {
				t.Fatalf("s.SaveDataFile failed: %v", err)
			}
			var bar Foo
			commit, err := s.OpenForUpdate(fn, &bar)
			if err != nil {
				t.Fatalf("s.OpenForUpdate failed: %v", err)
			}
			if !reflect.DeepEqual(foo, bar) {
				t.Fatalf("s.OpenForUpdate() got %+v, want %+v", bar, foo)
			}
			bar.Foo = "bar"
			if err := commit(true, nil); err != nil {
				t.Errorf("done() failed: %v", err)
			}
			if err := commit(false, nil); err != ErrAlreadyCommitted {
				t.Errorf("unexpected error. Want %v, got %v", ErrAlreadyCommitted, err)
			}

			if err := s.ReadDataFile(fn, &foo); err != nil {
				t.Fatalf("s.ReadDataFile() failed: %v", err)
			}
			if !reflect.DeepEqual(foo, bar) {
				t.Fatalf("d.openForUpdate() got %+v, want %+v", foo, bar)
			}
		})
	}
}

func TestRollback(t *testing.T) {
	dir := t.TempDir()
	fn := "test.json"
	s := New(dir, aesEncryptionKey())

	type Foo struct {
		Foo string `json:"foo"`
	}
	foo := Foo{"foo"}
	if err := s.SaveDataFile(fn, foo); err != nil {
		t.Fatalf("s.SaveDataFile failed: %v", err)
	}
	var bar Foo
	commit, err := s.OpenForUpdate(fn, &bar)
	if err != nil {
		t.Fatalf("s.OpenForUpdate failed: %v", err)
	}
	if !reflect.DeepEqual(foo, bar) {
		t.Fatalf("s.OpenForUpdate() got %+v, want %+v", bar, foo)
	}
	bar.Foo = "bar"
	if err := commit(false, nil); err != ErrRolledBack {
		t.Errorf("unexpected error. Want %v, got %v", ErrRolledBack, err)
	}
	if err := commit(true, nil); err != ErrAlreadyRolledBack {
		t.Errorf("unexpected error. Want %v, got %v", ErrAlreadyRolledBack, err)
	}

	var foo2 Foo
	if err := s.ReadDataFile(fn, &foo2); err != nil {
		t.Fatalf("s.ReadDataFile() failed: %v", err)
	}
	if !reflect.DeepEqual(foo, foo2) {
		t.Fatalf("s.OpenForUpdate() got %+v, want %+v", foo2, foo)
	}
}

func TestOpenForUpdateDeferredDone(t *testing.T) {
	dir := t.TempDir()
	s := New(dir, aesEncryptionKey())

	// This function should return os.ErrNotExist because the file open for
	// update can't be saved.
	f := func() (retErr error) {
		fn := filepath.Join("sub", "test.json")
		type Foo struct {
			Foo string `json:"foo"`
		}
		if err := s.CreateEmptyFile(fn, Foo{}); err != nil {
			t.Fatalf("s.CreateEmptyFile failed: %v", err)
		}
		var foo Foo
		commit, err := s.OpenForUpdate(fn, &foo)
		if err != nil {
			t.Fatalf("s.OpenForUpdate failed: %v", err)
		}
		defer commit(true, &retErr)
		if err := os.RemoveAll(filepath.Join(dir, "sub")); err != nil {
			t.Fatalf("of.RemoveAll(sub): %v", err)
		}
		return nil
	}

	if err := f(); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("f returned unexpected error: %v", err)
	}
}

func TestEncodeByteSlice(t *testing.T) {
	testcases := []struct {
		name string
		mk   crypto.EncryptionKey
	}{
		{"AES", aesEncryptionKey()},
		{"Chacha20Poly1305", ccEncryptionKey()},
		{"TPM", tpmEncryptionKey()},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			want := []byte("Hello world")
			dir := t.TempDir()
			s := New(dir, tc.mk)
			if err := s.CreateEmptyFile("file", (*[]byte)(nil)); err != nil {
				t.Fatalf("s.CreateEmptyFile failed: %v", err)
			}
			if err := s.SaveDataFile("file", &want); err != nil {
				t.Fatalf("s.WriteDataFile() failed: %v", err)
			}
			var got []byte
			if err := s.ReadDataFile("file", &got); err != nil {
				t.Fatalf("s.ReadDataFile() failed: %v", err)
			}
			if !reflect.DeepEqual(want, got) {
				t.Errorf("Unexpected msg. Want %q, got %q", want, got)
			}
		})
	}
}

func TestEncodeBinary(t *testing.T) {
	testcases := []struct {
		name string
		mk   crypto.EncryptionKey
	}{
		{"AES", aesEncryptionKey()},
		{"Chacha20Poly1305", ccEncryptionKey()},
		{"TPM", tpmEncryptionKey()},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			want := time.Now()
			dir := t.TempDir()
			s := New(dir, tc.mk)
			if err := s.CreateEmptyFile("file", &time.Time{}); err != nil {
				t.Fatalf("s.CreateEmptyFile failed: %v", err)
			}
			if err := s.SaveDataFile("file", &want); err != nil {
				t.Fatalf("s.WriteDataFile() failed: %v", err)
			}
			var got time.Time
			if err := s.ReadDataFile("file", &got); err != nil {
				t.Fatalf("s.ReadDataFile() failed: %v", err)
			}
			if got.UnixNano() != want.UnixNano() {
				t.Errorf("Unexpected time. Want %q, got %q", want, got)
			}
		})
	}
}

func TestBlobs(t *testing.T) {
	const (
		temp    = "tempfile"
		final   = "finalfile"
		content = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	)

	testcases := []struct {
		name string
		mk   crypto.EncryptionKey
	}{
		{"AES", aesEncryptionKey()},
		{"Chacha20Poly1305", ccEncryptionKey()},
		{"TPM", tpmEncryptionKey()},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			s := New(dir, tc.mk)

			w, err := s.OpenBlobWrite(temp, final)
			if err != nil {
				t.Fatalf("s.OpenBlobWrite failed: %v", err)
			}
			if _, err := w.Write([]byte(content)); err != nil {
				t.Fatalf("w.Write failed: %v", err)
			}
			if err := w.Close(); err != nil {
				t.Fatalf("w.Close failed: %v", err)
			}

			var buf []byte
			if err := s.ReadDataFile(temp, &buf); err == nil {
				t.Fatalf("s.ReadDataFile() didn't fail. Got: %s", buf)
			}
			if err := os.Rename(filepath.Join(dir, temp), filepath.Join(dir, final)); err != nil {
				t.Fatalf("os.Rename failed: %v", err)
			}
			if err := s.ReadDataFile(final, &buf); err != nil {
				t.Fatalf("s.ReadDataFile() failed: %v", err)
			}
			if want, got := content, string(buf); want != got {
				t.Errorf("Unexpected content. Want %q, got %q", want, got)
			}

			r, err := s.OpenBlobRead(final)
			if err != nil {
				t.Fatalf("s.OpenBlobRead failed: %v", err)
			}

			// Test SeekStart.
			off, err := r.Seek(5, io.SeekStart)
			if err != nil {
				t.Fatalf("r.Seek(5, io.SeekStart) failed: %v", err)
			}
			if want, got := int64(5), off; want != got {
				t.Errorf("Unexpected seek offset. Want %d, got %d", want, got)
			}
			if got, err := io.ReadAll(r); err != nil || string(got) != content[5:] {
				t.Errorf("Unexpected content. Want %q, got %s", content[5:], got)
			}

			// Test SeekCurrent.
			if _, err := r.Seek(5, io.SeekStart); err != nil {
				t.Fatalf("r.Seek(5, io.SeekStart) failed: %v", err)
			}
			if off, err = r.Seek(10, io.SeekCurrent); err != nil {
				t.Fatalf("r.Seek(10, io.SeekCurrent) failed: %v", err)
			}
			if want, got := int64(15), off; want != got {
				t.Errorf("Unexpected seek offset. Want %d, got %d", want, got)
			}
			if got, err := io.ReadAll(r); err != nil || string(got) != content[15:] {
				t.Errorf("Unexpected content. Want %q, got %s", content[15:], got)
			}

			// Test SeekEnd.
			if off, err = r.Seek(-3, io.SeekEnd); err != nil {
				t.Fatalf("r.Seek(-3, io.SeekEnd) failed: %v", err)
			}
			if want, got := int64(len(content)-3), off; want != got {
				t.Errorf("Unexpected seek offset. Want %d, got %d", want, got)
			}
			if got, err := io.ReadAll(r); err != nil || string(got) != "XYZ" {
				t.Errorf("Unexpected content. Want %q, got %s", "XYZ", got)
			}

			// Test SeekEnd.
			if off, err = r.Seek(0, io.SeekEnd); err != nil {
				t.Fatalf("r.Seek(0, io.SeekEnd) failed: %v", err)
			}
			if want, got := int64(len(content)), off; want != got {
				t.Errorf("Unexpected seek offset. Want %d, got %d", want, got)
			}
			if got, err := io.ReadAll(r); err != nil || string(got) != "" {
				t.Errorf("Unexpected content. Want %q, got %s", "", got)
			}

			if err := r.Close(); err != nil {
				t.Fatalf("r.Close failed: %v", err)
			}
		})
	}
}

func RunBenchmarkOpenForUpdate(b *testing.B, kb int, k crypto.EncryptionKey, compress, useGOB bool) {
	dir := b.TempDir()
	file := filepath.Join(dir, "testfile")
	s := New(dir, k)
	s.compress = compress
	s.useGOB = useGOB

	obj := struct {
		M map[string]string `json:"m"`
	}{}
	obj.M = make(map[string]string)
	for i := 0; i < kb; i++ {
		key := make([]byte, 32)
		value := make([]byte, 1024)
		if _, err := rand.Read(key); err != nil {
			b.Fatalf("io.ReadFull: %v", err)
		}
		if _, err := rand.Read(value); err != nil {
			b.Fatalf("io.ReadFull: %v", err)
		}
		obj.M[string(key)] = string(value)
	}
	if err := s.writeFile(context("testfile"), "testfile", &obj); err != nil {
		b.Fatalf("s.writeFile: %v", err)
	}
	fi, err := os.Stat(file)
	if err != nil {
		b.Fatalf("os.Stat: %v", err)
	}
	b.ResetTimer()
	b.SetBytes(fi.Size())
	for i := 0; i < b.N; i++ {
		commit, err := s.OpenForUpdate("testfile", &obj)
		if err != nil {
			b.Fatalf("s.OpenForUpdate: %v", err)
		}
		if err := commit(true, nil); err != nil {
			b.Fatalf("commit: %v", err)
		}
	}
}

func BenchmarkOpenForUpdate_JSON_1KB_AES(b *testing.B) {
	RunBenchmarkOpenForUpdate(b, 1, aesEncryptionKey(), false, false)
}

func BenchmarkOpenForUpdate_JSON_1MB_AES(b *testing.B) {
	RunBenchmarkOpenForUpdate(b, 1024, aesEncryptionKey(), false, false)
}

func BenchmarkOpenForUpdate_JSON_10MB_AES(b *testing.B) {
	RunBenchmarkOpenForUpdate(b, 10240, aesEncryptionKey(), false, false)
}

func BenchmarkOpenForUpdate_JSON_20MB_AES(b *testing.B) {
	RunBenchmarkOpenForUpdate(b, 20480, aesEncryptionKey(), false, false)
}

func BenchmarkOpenForUpdate_JSON_1KB_CHACHA20POLY1305(b *testing.B) {
	RunBenchmarkOpenForUpdate(b, 1, ccEncryptionKey(), false, false)
}

func BenchmarkOpenForUpdate_JSON_1MB_CHACHA20POLY1305(b *testing.B) {
	RunBenchmarkOpenForUpdate(b, 1024, ccEncryptionKey(), false, false)
}

func BenchmarkOpenForUpdate_JSON_10MB_CHACHA20POLY1305(b *testing.B) {
	RunBenchmarkOpenForUpdate(b, 10240, ccEncryptionKey(), false, false)
}

func BenchmarkOpenForUpdate_JSON_20MB_CHACHA20POLY1305(b *testing.B) {
	RunBenchmarkOpenForUpdate(b, 20480, ccEncryptionKey(), false, false)
}

func BenchmarkOpenForUpdate_JSON_1KB_PlainText(b *testing.B) {
	RunBenchmarkOpenForUpdate(b, 1, nil, false, false)
}

func BenchmarkOpenForUpdate_JSON_1MB_PlainText(b *testing.B) {
	RunBenchmarkOpenForUpdate(b, 1024, nil, false, false)
}

func BenchmarkOpenForUpdate_JSON_10MB_PlainText(b *testing.B) {
	RunBenchmarkOpenForUpdate(b, 10240, nil, false, false)
}

func BenchmarkOpenForUpdate_JSON_20MB_PlainText(b *testing.B) {
	RunBenchmarkOpenForUpdate(b, 20480, nil, false, false)
}

func BenchmarkOpenForUpdate_GOB_1KB_AES(b *testing.B) {
	RunBenchmarkOpenForUpdate(b, 1, aesEncryptionKey(), false, true)
}

func BenchmarkOpenForUpdate_GOB_1MB_AES(b *testing.B) {
	RunBenchmarkOpenForUpdate(b, 1024, aesEncryptionKey(), false, true)
}

func BenchmarkOpenForUpdate_GOB_10MB_AES(b *testing.B) {
	RunBenchmarkOpenForUpdate(b, 10240, aesEncryptionKey(), false, true)
}

func BenchmarkOpenForUpdate_GOB_20MB_AES(b *testing.B) {
	RunBenchmarkOpenForUpdate(b, 20480, aesEncryptionKey(), false, true)
}

func BenchmarkOpenForUpdate_GOB_1KB_CHACHA20POLY1305(b *testing.B) {
	RunBenchmarkOpenForUpdate(b, 1, ccEncryptionKey(), false, true)
}

func BenchmarkOpenForUpdate_GOB_1MB_CHACHA20POLY1305(b *testing.B) {
	RunBenchmarkOpenForUpdate(b, 1024, ccEncryptionKey(), false, true)
}

func BenchmarkOpenForUpdate_GOB_10MB_CHACHA20POLY1305(b *testing.B) {
	RunBenchmarkOpenForUpdate(b, 10240, ccEncryptionKey(), false, true)
}

func BenchmarkOpenForUpdate_GOB_20MB_CHACHA20POLY1305(b *testing.B) {
	RunBenchmarkOpenForUpdate(b, 20480, ccEncryptionKey(), false, true)
}

func BenchmarkOpenForUpdate_GOB_1KB_TPM_AES(b *testing.B) {
	RunBenchmarkOpenForUpdate(b, 1, tpmEncryptionKey(), false, true)
}

func BenchmarkOpenForUpdate_GOB_1MB_TPM_AES(b *testing.B) {
	RunBenchmarkOpenForUpdate(b, 1024, tpmEncryptionKey(), false, true)
}

func BenchmarkOpenForUpdate_GOB_10MB_TPM_AES(b *testing.B) {
	RunBenchmarkOpenForUpdate(b, 10240, tpmEncryptionKey(), false, true)
}

func BenchmarkOpenForUpdate_GOB_20MB_TPM_AES(b *testing.B) {
	RunBenchmarkOpenForUpdate(b, 20480, tpmEncryptionKey(), false, true)
}

func BenchmarkOpenForUpdate_GOB_1KB_PlainText(b *testing.B) {
	RunBenchmarkOpenForUpdate(b, 1, nil, false, true)
}

func BenchmarkOpenForUpdate_GOB_1MB_PlainText(b *testing.B) {
	RunBenchmarkOpenForUpdate(b, 1024, nil, false, true)
}

func BenchmarkOpenForUpdate_GOB_10MB_PlainText(b *testing.B) {
	RunBenchmarkOpenForUpdate(b, 10240, nil, false, true)
}

func BenchmarkOpenForUpdate_GOB_20MB_PlainText(b *testing.B) {
	RunBenchmarkOpenForUpdate(b, 20480, nil, false, true)
}

func BenchmarkOpenForUpdate_GOB_1KB_PlainText_GZIP(b *testing.B) {
	RunBenchmarkOpenForUpdate(b, 1, nil, true, true)
}

func BenchmarkOpenForUpdate_GOB_1MB_PlainText_GZIP(b *testing.B) {
	RunBenchmarkOpenForUpdate(b, 1024, nil, true, true)
}

func BenchmarkOpenForUpdate_GOB_10MB_PlainText_GZIP(b *testing.B) {
	RunBenchmarkOpenForUpdate(b, 10240, nil, true, true)
}

func BenchmarkOpenForUpdate_GOB_20MB_PlainText_GZIP(b *testing.B) {
	RunBenchmarkOpenForUpdate(b, 20480, nil, true, true)
}
