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

package crypto

import (
	"bytes"
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/c2FmZQ/tpm"
	"github.com/google/go-tpm-tools/simulator"
)

func TestAESMasterKey(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key")

	mk, err := CreateAESMasterKey()
	if err != nil {
		t.Fatalf("CreateMasterKey: %v", err)
	}
	defer mk.Wipe()
	if err := mk.Save([]byte("foo"), keyFile); err != nil {
		t.Fatalf("mk.Save: %v", err)
	}

	got, err := ReadAESMasterKey([]byte("foo"), keyFile)
	if err != nil {
		t.Fatalf("ReadMasterKey('foo'): %v", err)
	}
	defer got.Wipe()
	if want := mk; !reflect.DeepEqual(want.(*AESMasterKey).key(), got.(*AESMasterKey).key()) {
		t.Errorf("Mismatch keys: %v != %v", want.(*AESMasterKey).key(), got.(*AESMasterKey).key())
	}
	if _, err := ReadAESMasterKey([]byte("bar"), keyFile); err == nil {
		t.Errorf("ReadMasterKey('bar') should have failed, but didn't")
	}
}

func TestTPMAESMasterKey(t *testing.T) {
	passphrase := []byte("foo")
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key")

	rwc, err := simulator.Get()
	if err != nil {
		t.Fatalf("simulator.Get: %v", err)
	}

	tpm, err := tpm.New(tpm.WithTPM(rwc), tpm.WithObjectAuth([]byte(passphrase)))
	if err != nil {
		t.Fatalf("tpm.New: %v", err)
	}
	defer tpm.Close()

	mk, err := CreateAESMasterKey(WithTPM(tpm))
	if err != nil {
		t.Fatalf("CreateMasterKey: %v", err)
	}
	defer mk.Wipe()
	if err := mk.Save(passphrase, keyFile); err != nil {
		t.Fatalf("mk.Save: %v", err)
	}

	mk2, err := ReadAESMasterKey(passphrase, keyFile, WithTPM(tpm))
	if err != nil {
		t.Fatalf("ReadMasterKey(%q): %v", passphrase, err)
	}
	defer mk2.Wipe()
	if got, want := mk2, mk; !reflect.DeepEqual(want.(*AESMasterKey).key(), got.(*AESMasterKey).key()) {
		t.Errorf("Mismatch keys: %v != %v", want.(*AESMasterKey).key(), got.(*AESMasterKey).key())
	}
	if _, err := ReadAESMasterKey([]byte("bar"), keyFile); err == nil {
		t.Errorf("ReadMasterKey('bar') should have failed, but didn't")
	}
}

func TestAESEncryptDecrypt(t *testing.T) {
	mk, err := CreateAESMasterKey()
	if err != nil {
		t.Fatalf("CreateMasterKey: %v", err)
	}
	defer mk.Wipe()

	m := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	for i := 1; i < len(m); i++ {
		enc, err := mk.Encrypt(m[:i])
		if err != nil {
			t.Fatalf("mk.Encrypt: %v", err)
		}
		dec, err := mk.Decrypt(enc)
		if err != nil {
			t.Fatalf("mk.Decrypt: %v", err)
		}
		if !reflect.DeepEqual(m[:i], dec) {
			t.Errorf("Decrypted data[%d] doesn't match. Want %#v, got %#v", i, m[:i], dec)
		}
	}
}

func TestAESEncryptedKey(t *testing.T) {
	mk, err := CreateAESMasterKey()
	if err != nil {
		t.Fatalf("CreateMasterKey: %v", err)
	}
	defer mk.Wipe()

	ek, err := mk.NewKey()
	if err != nil {
		t.Fatalf("mk.NewKey: %v", err)
	}
	defer ek.Wipe()

	var buf bytes.Buffer
	if err := ek.WriteEncryptedKey(&buf); err != nil {
		t.Fatalf("ek.WriteEncryptedKey: %v", err)
	}

	ek2, err := mk.ReadEncryptedKey(&buf)
	if err != nil {
		t.Fatalf("mk.ReadEncryptedKey: %v", err)
	}
	defer ek2.Wipe()
	if want, got := ek.(*AESKey).key(), ek2.(*AESKey).key(); !reflect.DeepEqual(want, got) {
		t.Errorf("Unexpected key. Want %+v, got %+v", want, got)
	}
}

func TestTPMAESEncryptedKey(t *testing.T) {
	passphrase := []byte("foo")
	rwc, err := simulator.Get()
	if err != nil {
		t.Fatalf("simulator.Get: %v", err)
	}
	tpm, err := tpm.New(tpm.WithTPM(rwc), tpm.WithObjectAuth([]byte(passphrase)))
	if err != nil {
		t.Fatalf("tpm.New: %v", err)
	}
	defer tpm.Close()

	mk, err := CreateAESMasterKey(WithTPM(tpm))
	if err != nil {
		t.Fatalf("CreateMasterKey: %v", err)
	}
	defer mk.Wipe()

	ek, err := mk.NewKey()
	if err != nil {
		t.Fatalf("mk.NewKey: %v", err)
	}
	defer ek.Wipe()

	var buf bytes.Buffer
	if err := ek.WriteEncryptedKey(&buf); err != nil {
		t.Fatalf("ek.WriteEncryptedKey: %v", err)
	}

	ek2, err := mk.ReadEncryptedKey(&buf)
	if err != nil {
		t.Fatalf("mk.ReadEncryptedKey: %v", err)
	}
	defer ek2.Wipe()
	if want, got := ek.(*AESKey).key(), ek2.(*AESKey).key(); !reflect.DeepEqual(want, got) {
		t.Errorf("Unexpected key. Want %+v, got %+v", want, got)
	}
}

func TestAESStreamRead(t *testing.T) {
	mk, err := CreateAESMasterKeyForTest()
	if err != nil {
		t.Fatalf("CreateMasterKey: %v", err)
	}
	var buf bytes.Buffer
	content := make([]byte, 10000)
	if _, err := rand.Read(content); err != nil {
		t.Fatalf("rand: %v", err)
	}
	ctx := []byte{0x12, 0x12, 0x12, 0x12}
	w, err := mk.StartWriter(ctx, &buf)
	if err != nil {
		t.Fatalf("StartWriter: %v", err)
	}
	if _, err := w.Write(content); err != nil {
		t.Fatalf("StartWriter.Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("StartWriter.Close: %v", err)
	}

	r, err := mk.StartReader(ctx, &buf)
	if err != nil {
		t.Fatalf("StartReader: %v", err)
	}
	var got []byte
	for s := 0; s < 1000; s++ {
		b := make([]byte, s)
		n, err := r.Read(b)
		got = append(got, b[:n]...)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("StartReader.Read: %v", err)
		}
	}
	if err := r.Close(); err != nil {
		t.Fatalf("StartReader.Close: %v", err)
	}
	if want := content; !reflect.DeepEqual(want, got) {
		t.Errorf("Read different content. Want %v, got %v", want, got)
	}
}

func TestAESStreamSeek(t *testing.T) {
	v := func(off int64) byte {
		return byte((off >> 24) + (off >> 16) + (off >> 8) + off)
	}
	dir := t.TempDir()

	mk, err := CreateAESMasterKeyForTest()
	if err != nil {
		t.Fatalf("CreateMasterKey: %v", err)
	}
	fn := filepath.Join(dir, "seekfile")
	tmp, err := os.Create(fn)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	ctx := []byte{0x12, 0x12, 0x12, 0x12}
	w, err := mk.StartWriter(ctx, tmp)
	if err != nil {
		t.Fatalf("StartWriter: %v", err)
	}
	const fileSize = 5 * 1024 * 1024
	for i := int64(0); i < fileSize; i++ {
		if _, err := w.Write([]byte{v(i)}); err != nil {
			t.Fatalf("StartWriter.Write: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("StartWriter.Close: %v", err)
	}

	if tmp, err = os.Open(fn); err != nil {
		t.Fatalf("Open: %v", err)
	}
	r, err := mk.StartReader(ctx, tmp)
	if err != nil {
		t.Fatalf("StartReader: %v", err)
	}

	want := int64(10)
	if got, _ := r.Seek(10, io.SeekStart); want != got {
		t.Errorf("Unexpected seek offset. Want %d, got %d", want, got)
	}
	want = 20
	if got, _ := r.Seek(10, io.SeekCurrent); want != got {
		t.Errorf("Unexpected seek offset. Want %d, got %d", want, got)
	}
	want = 15
	if got, _ := r.Seek(-5, io.SeekCurrent); want != got {
		t.Errorf("Unexpected seek offset. Want %d, got %d", want, got)
	}
	want = fileSize - 100
	if got, _ := r.Seek(-100, io.SeekEnd); want != got {
		t.Errorf("Unexpected seek offset. Want %d, got %d", want, got)
	}
	want = fileSize
	if got, _ := r.Seek(0, io.SeekEnd); want != got {
		t.Errorf("Unexpected seek offset. Want %d, got %d", want, got)
	}

	for _, off := range []int64{0, 1, 1024 * 1024, 1024*1024 - 10, 3 * 1024 * 1024} {
		if _, err := r.Seek(off, io.SeekStart); err != nil {
			t.Fatalf("Seek(%d): %v", off, err)
		}
		buf := make([]byte, 100)
		if _, err := io.ReadFull(r, buf); err != nil {
			t.Fatalf("ReadFull: %v", err)
		}
		for i := range buf {
			if want, got := v(off+int64(i)), buf[i]; want != got {
				t.Errorf("Unexpected byte off=%d i=%d. Want %d, got %d", off, i, want, got)
			}
		}
	}
}

func TestAESStreamInvalidMAC(t *testing.T) {
	mk, err := CreateAESMasterKey()
	if err != nil {
		t.Fatalf("CreateMasterKey: %v", err)
	}
	defer mk.Wipe()
	var buf bytes.Buffer
	content := make([]byte, 10000)
	if _, err := rand.Read(content); err != nil {
		t.Fatalf("rand: %v", err)
	}
	ctx := []byte{0x44, 0x33, 0x22, 0x11}
	w, err := mk.StartWriter(ctx, &buf)
	if err != nil {
		t.Fatalf("StartWriter: %v", err)
	}
	if _, err := w.Write(content); err != nil {
		t.Fatalf("StartWriter.Write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("StartWriter.Close: %v", err)
	}

	c := buf.Bytes()[buf.Len()-1]
	buf.Bytes()[buf.Len()-1] = ^c

	r, err := mk.StartReader(ctx, &buf)
	if err != nil {
		t.Fatalf("StartReader: %v", err)
	}
	b := make([]byte, 10000)
	if n, err := r.Read(b); err != ErrDecryptFailed {
		t.Errorf("StartReader.Read: %d, %v", n, err)
	}
}
