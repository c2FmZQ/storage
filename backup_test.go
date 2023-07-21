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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestBackupRestore(t *testing.T) {
	dir := t.TempDir()
	s := New(dir, aesEncryptionKey())

	if err := os.Mkdir(filepath.Join(dir, "data"), 0700); err != nil {
		t.Fatalf("os.Mkdir: %v", err)
	}
	var files []string
	for i := 1; i <= 10; i++ {
		file := filepath.Join("data", fmt.Sprintf("file%d", i))
		if err := os.WriteFile(filepath.Join(dir, file), []byte(fmt.Sprintf("This is file %d", i)), 0600); err != nil {
			t.Fatalf("os.WriteFile: %v", err)
		}
		files = append(files, file)
	}
	bck, err := s.createBackup(files)
	if err != nil {
		t.Fatalf("s.createBackup: %v", err)
	}

	var got backup
	if err := s.ReadDataFile(filepath.Join("pending", fmt.Sprintf("%d", bck.TS.UnixNano())), &got); err != nil {
		t.Fatalf("s.ReadDataFile: %v", err)
	}
	if want := files; !reflect.DeepEqual(want, got.Files) {
		t.Errorf("Unexpected pending op files. Want %+v, got %+v", want, got)
	}

	for i := 1; i <= 10; i++ {
		file := filepath.Join(dir, "data", fmt.Sprintf("file%d", i))
		if err := os.WriteFile(file+".tmp", []byte("XXXXXX"), 0600); err != nil {
			t.Fatalf("os.WriteFile: %v", err)
		}
		if err := os.Rename(file+".tmp", file); err != nil {
			t.Fatalf("os.Rename: %v", err)
		}
		files = append(files, file)
	}
	bck.restore()
	if err := s.ReadDataFile(filepath.Join("pending", fmt.Sprintf("%d", bck.TS.UnixNano())), &got); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("pending ops file should have been deleted: %v", err)
	}

	for i := 1; i <= 10; i++ {
		file := filepath.Join("data", fmt.Sprintf("file%d", i))
		b, err := os.ReadFile(filepath.Join(dir, file))
		if err != nil {
			t.Fatalf("os.ReadFile: %v", err)
		}
		if want, got := fmt.Sprintf("This is file %d", i), string(b); want != got {
			t.Errorf("Unexpected file content after restore. Want %q, got %q", want, got)
		}

	}
}

func TestBackupDelete(t *testing.T) {
	dir := t.TempDir()
	s := New(dir, aesEncryptionKey())

	if err := os.Mkdir(filepath.Join(dir, "data"), 0700); err != nil {
		t.Fatalf("os.Mkdir: %v", err)
	}
	var files []string
	for i := 1; i <= 10; i++ {
		file := filepath.Join("data", fmt.Sprintf("file%d", i))
		if err := os.WriteFile(filepath.Join(dir, file), []byte(fmt.Sprintf("This is file %d", i)), 0600); err != nil {
			t.Fatalf("os.WriteFile: %v", err)
		}
		files = append(files, file)
	}
	bck, err := s.createBackup(files)
	if err != nil {
		t.Fatalf("s.createBackup: %v", err)
	}

	var got backup
	if err := s.ReadDataFile(filepath.Join("pending", fmt.Sprintf("%d", bck.TS.UnixNano())), &got); err != nil {
		t.Fatalf("s.ReadDataFile: %v", err)
	}
	if want := files; !reflect.DeepEqual(want, got.Files) {
		t.Errorf("Unexpected pending op files. Want %+v, got %+v", want, got)
	}

	for i := 1; i <= 10; i++ {
		file := filepath.Join("data", fmt.Sprintf("file%d", i))
		if err := os.WriteFile(filepath.Join(dir, file), []byte("XXXXXX"), 0600); err != nil {
			t.Fatalf("os.WriteFile: %v", err)
		}
		files = append(files, file)
	}
	bck.delete()
	if err := s.ReadDataFile(filepath.Join("pending", fmt.Sprintf("%d", bck.TS.UnixNano())), &got); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("pending ops file should have been deleted: %v", err)
	}

	for i := 1; i <= 10; i++ {
		file := filepath.Join("data", fmt.Sprintf("file%d", i))
		b, err := os.ReadFile(filepath.Join(dir, file))
		if err != nil {
			t.Fatalf("os.ReadFile: %v", err)
		}
		if want, got := "XXXXXX", string(b); want != got {
			t.Errorf("Unexpected file content after restore. Want %q, got %q", want, got)
		}

	}
}

func TestRestorePendingOps(t *testing.T) {
	dir := t.TempDir()
	ed := aesEncryptionKey()
	s := New(dir, ed)

	if err := os.Mkdir(filepath.Join(dir, "data"), 0700); err != nil {
		t.Fatalf("os.Mkdir: %v", err)
	}
	var files []string
	for i := 1; i <= 10; i++ {
		file := filepath.Join("data", fmt.Sprintf("file%d", i))
		if err := os.WriteFile(filepath.Join(dir, file), []byte(fmt.Sprintf("This is file %d", i)), 0600); err != nil {
			t.Fatalf("os.WriteFile: %v", err)
		}
		files = append(files, file)
	}
	if _, err := s.createBackup(files); err != nil {
		t.Fatalf("s.createBackup: %v", err)
	}
	for i := 1; i <= 10; i++ {
		file := filepath.Join(dir, "data", fmt.Sprintf("file%d", i))
		if err := os.WriteFile(file+".tmp", []byte("XXXXXX"), 0600); err != nil {
			t.Fatalf("os.WriteFile: %v", err)
		}
		if err := os.Rename(file+".tmp", file); err != nil {
			t.Fatalf("os.Rename: %v", err)
		}
		files = append(files, file)
	}

	// New will notice the aborted operation and roll it back.
	s = New(dir, ed)

	for i := 1; i <= 10; i++ {
		file := filepath.Join("data", fmt.Sprintf("file%d", i))
		b, err := os.ReadFile(filepath.Join(dir, file))
		if err != nil {
			t.Fatalf("os.ReadFile: %v", err)
		}
		if want, got := fmt.Sprintf("This is file %d", i), string(b); want != got {
			t.Errorf("Unexpected file content after restore. Want %q, got %q", want, got)
		}

	}
}
