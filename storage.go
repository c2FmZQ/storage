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

// Package storage stores arbitrary data in encrypted files.
package storage

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"crypto/sha1"
	"encoding"
	"encoding/binary"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	mrand "math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/c2FmZQ/storage/crypto"
)

const (
	optJSONEncoded   = 0x01 // encoding/json
	optGOBEncoded    = 0x02 // encoding/gob
	optBinaryEncoded = 0x03 // with encoding.BinaryMarshaler
	optRawBytes      = 0x04 // []byte
	optEncodingMask  = 0x0F

	optEncrypted  = 0x10
	optCompressed = 0x20
	optPadded     = 0x40
)

var (
	// Indicates that the update was successfully rolled back.
	ErrRolledBack = errors.New("rolled back")
	// Indicates that the update was already rolled back by a previous call.
	ErrAlreadyRolledBack = errors.New("already rolled back")
	// Indicates that the update was already committed by a previous call.
	ErrAlreadyCommitted = errors.New("already committed")
)

// New returns a new Storage rooted at dir. The caller must provide an
// EncryptionKey that will be used to encrypt and decrypt per-file encryption
// keys.
func New(dir string, masterKey crypto.EncryptionKey) *Storage {
	s := &Storage{
		dir:       dir,
		masterKey: masterKey,
		useGOB:    true,
	}
	if masterKey != nil {
		s.logger = masterKey.Logger()
	} else {
		s.logger = crypto.StdLogger()
	}
	if err := s.rollbackPendingOps(); err != nil {
		masterKey.Logger().Fatalf("s.rollbackPendingOps: %v", err)
	}
	return s
}

// Storage offers the API to atomically read, write, and update encrypted files.
type Storage struct {
	dir       string
	masterKey crypto.EncryptionKey
	logger    crypto.Logger
	compress  bool
	useGOB    bool
}

// Dir returns the root directory of the storage.
func (s *Storage) Dir() string {
	return s.dir
}

// Logger returns the logger associated with the storage's master key.
func (s *Storage) Logger() crypto.Logger {
	return s.logger
}

// HashString returns a cryptographically secure hash of a string.
func (s *Storage) HashString(str string) string {
	return hex.EncodeToString(s.masterKey.Hash([]byte(str)))
}

func createParentIfNotExist(filename string) error {
	dir, _ := filepath.Split(filename)
	return os.MkdirAll(dir, 0700)
}

// Lock atomically creates a lock file for the given filename. When this
// function returns without error, the lock is acquired and nobody else can
// acquire it until it is released.
//
// There is logic in place to remove stale locks after a while.
func (s *Storage) Lock(fn string) error {
	lockf := filepath.Join(s.dir, fn) + ".lock"
	if err := createParentIfNotExist(lockf); err != nil {
		return err
	}
	deadline := time.Duration(600+mrand.Int()%60) * time.Second
	for {
		f, err := os.OpenFile(lockf, os.O_WRONLY|os.O_CREATE|os.O_EXCL|os.O_SYNC, 0600)
		if errors.Is(err, os.ErrExist) {
			s.tryToRemoveStaleLock(lockf, deadline)
			time.Sleep(time.Duration(100+mrand.Int()%100) * time.Millisecond)
			continue
		}
		if err != nil {
			return err
		}
		s.Logger().Debugf("Locked %s", fn)
		if err := f.Close(); err != nil {
			return err
		}
		return nil
	}
}

// LockMany locks multiple files such that if the exact same files are locked
// concurrently, there won't be any deadlock.
//
// When the function returns successfully, all the files are locked.
func (s *Storage) LockMany(filenames []string) error {
	sorted := make([]string, len(filenames))
	copy(sorted, filenames)
	sort.Strings(sorted)
	var locks []string
	for _, f := range sorted {
		if err := s.Lock(f); err != nil {
			s.UnlockMany(locks)
			return err
		}
		locks = append(locks, f)
	}
	return nil
}

// Unlock released the lock file for the given filename.
func (s *Storage) Unlock(fn string) error {
	lockf := filepath.Join(s.dir, fn) + ".lock"
	if err := os.Remove(lockf); err != nil {
		return err
	}
	s.Logger().Debugf("Unlocked %s", fn)
	return nil
}

// UnlockMany unlocks multiples files locked by LockMany().
func (s *Storage) UnlockMany(filenames []string) error {
	sorted := make([]string, len(filenames))
	copy(sorted, filenames)
	sort.Sort(sort.Reverse(sort.StringSlice(sorted)))
	for _, f := range sorted {
		if err := s.Unlock(f); err != nil {
			return err
		}
	}
	return nil
}

func (s *Storage) tryToRemoveStaleLock(lockf string, deadline time.Duration) {
	fi, err := os.Stat(lockf)
	if err != nil {
		return
	}
	if time.Since(fi.ModTime()) > deadline {
		if err := os.Remove(lockf); err == nil {
			s.Logger().Errorf("Removed stale lock %q", lockf)
		}
	}
}

// OpenForUpdate opens a file with the expectation that the object will be
// modified and then saved again.
//
// Example:
//
//	 func foo() (retErr error) {
//	   var foo FooStruct
//	   commit, err := s.OpenForUpdate(filename, &foo)
//	   if err != nil {
//	     panic(err)
//	   }
//	   defer commit(false, &retErr) // rollback unless first committed.
//	   // modify foo
//	   foo.Bar = X
//	   return commit(true, nil) // commit
//	}
func (s *Storage) OpenForUpdate(f string, obj interface{}) (func(commit bool, errp *error) error, error) {
	return s.OpenManyForUpdate([]string{f}, []interface{}{obj})
}

// OpenManyForUpdate is like OpenForUpdate, but for multiple files.
//
// Example:
//
//	 func foo() (retErr error) {
//	   file1, file2 := "file1", "file2"
//	   var foo FooStruct
//	   var bar BarStruct
//	   // foo is read from file1, bar is read from file2.
//	   commit, err := s.OpenManyForUpdate([]string{file1, file2}, []interface{}{&foo, &bar})
//	   if err != nil {
//	     panic(err)
//	   }
//	   defer commit(false, &retErr) // rollback unless first committed.
//	   // modify foo and bar
//	   foo.X = "new X"
//	   bar.Y = "new Y"
//	   return commit(true, nil) // commit
//	}
func (s *Storage) OpenManyForUpdate(files []string, objects interface{}) (func(commit bool, errp *error) error, error) {
	if reflect.TypeOf(objects).Kind() != reflect.Slice {
		s.Logger().Fatal("objects must be a slice")
	}
	objValue := reflect.ValueOf(objects)
	if len(files) != objValue.Len() {
		s.Logger().Fatalf("len(files) != len(objects), %d != %d", len(files), objValue.Len())
	}
	if err := s.LockMany(files); err != nil {
		return nil, err
	}
	type readValue struct {
		i   int
		err error
	}
	ch := make(chan readValue)
	for i := range files {
		go func(i int, file string, obj interface{}) {
			err := s.ReadDataFile(file, obj)
			ch <- readValue{i, err}
		}(i, files[i], objValue.Index(i).Interface())
	}

	var errorList []error
	for _ = range files {
		v := <-ch
		if v.err != nil {
			errorList = append(errorList, v.err)
		}
	}
	if errorList != nil {
		s.UnlockMany(files)
		return nil, fmt.Errorf("s.ReadDataFile: %w %v", errorList[0], errorList[1:])
	}

	var called, committed bool
	return func(commit bool, errp *error) (retErr error) {
		if called {
			if committed {
				return ErrAlreadyCommitted
			}
			return ErrAlreadyRolledBack
		}
		called = true
		if errp == nil || *errp != nil {
			errp = &retErr
		}
		if commit {
			// If some of the SaveDataFile calls fails and some succeed, the data could
			// be inconsistent. When we have more then one file, make a backup of the
			// original data, and restore it if anything goes wrong.
			//
			// If the process dies in the middle of saving the data, the backup will be
			// restored automatically when the process restarts. See New().
			var backup *backup
			if len(files) > 1 {
				var err error
				if backup, err = s.createBackup(files); err != nil {
					*errp = err
					return *errp
				}
			}
			ch := make(chan error)
			for i := range files {
				go func(file string, obj interface{}) {
					ch <- s.SaveDataFile(file, obj)
				}(files[i], objValue.Index(i).Interface())
			}
			var errorList []error
			for _ = range files {
				if err := <-ch; err != nil {
					errorList = append(errorList, err)
				}
			}
			if errorList != nil {
				if backup != nil {
					backup.restore()
				}
				if *errp == nil {
					*errp = fmt.Errorf("s.SaveDataFile: %w %v", errorList[0], errorList[1:])
				}
			} else {
				if backup != nil {
					backup.delete()
				}
				committed = true
			}
		}
		if err := s.UnlockMany(files); err != nil && *errp == nil {
			*errp = err
		}
		if !commit && *errp == nil {
			*errp = ErrRolledBack
		}
		return *errp
	}, nil
}

func context(s string) []byte {
	h := sha1.Sum([]byte(s))
	return h[:]
}

// ReadDataFile reads an object from a file.
func (s *Storage) ReadDataFile(filename string, obj interface{}) error {
	f, err := os.Open(filepath.Join(s.dir, filename))
	if err != nil {
		return err
	}
	defer f.Close()

	hdr := make([]byte, 5)
	if _, err := io.ReadFull(f, hdr); err != nil {
		return err
	}
	if string(hdr[:4]) != "KRIN" {
		return errors.New("wrong file type")
	}
	flags := hdr[4]
	if flags&optEncrypted != 0 && s.masterKey == nil {
		return errors.New("file is encrypted, but a master key was not provided")
	}

	var r io.ReadSeekCloser = f
	if flags&optEncrypted != 0 {
		// Read the encrypted file key.
		k, err := s.masterKey.ReadEncryptedKey(f)
		if err != nil {
			return err
		}
		defer k.Wipe()
		// Use the file key to decrypt the rest of the file.
		if r, err = k.StartReader(context(filename), f); err != nil {
			return err
		}
		// Read the header again.
		h := make([]byte, 5)
		if _, err := io.ReadFull(r, h); err != nil {
			return err
		}
		if bytes.Compare(hdr, h) != 0 {
			return errors.New("wrong encrypted header")
		}
		if flags&optPadded != 0 {
			if err := SkipPadding(r); err != nil {
				return err
			}
		}
	}
	var rc io.Reader = r
	if flags&optCompressed != 0 {
		// Decompress the content of the file.
		gz, err := gzip.NewReader(r)
		if err != nil {
			return err
		}
		defer gz.Close()
		rc = gz
	}

	switch enc := flags & optEncodingMask; enc {
	case optGOBEncoded:
		// Decode with GOB.
		if err := gob.NewDecoder(rc).Decode(obj); err != nil {
			s.Logger().Debugf("gob Decode: %v", err)
			return err
		}
	case optJSONEncoded:
		// Decode JSON object.
		if err := json.NewDecoder(rc).Decode(obj); err != nil {
			s.Logger().Debugf("json Decode: %v", err)
			return err
		}
	case optBinaryEncoded:
		// Decode with UnmarshalBinary.
		u, ok := obj.(encoding.BinaryUnmarshaler)
		if !ok {
			return fmt.Errorf("obj doesn't implement encoding.BinaryUnmarshaler: %T", obj)
		}
		b, err := io.ReadAll(rc)
		if err != nil {
			return err
		}
		if err := u.UnmarshalBinary(b); err != nil {
			return err
		}
	case optRawBytes:
		// Read raw bytes.
		b, ok := obj.(*[]byte)
		if !ok {
			return fmt.Errorf("obj isn't *[]byte: %T", obj)
		}
		buf := make([]byte, 1024)
		for {
			n, err := rc.Read(buf)
			if n > 0 {
				*b = append(*b, buf[:n]...)
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unexpected encoding %x", enc)
	}
	if r != f {
		if err := r.Close(); err != nil {
			return err
		}
	}
	return nil
}

// SaveDataFile atomically replace an object in a file.
func (s *Storage) SaveDataFile(filename string, obj interface{}) error {
	t := fmt.Sprintf("%s.tmp-%d", filename, time.Now().UnixNano())
	if err := s.writeFile(context(filename), t, obj); err != nil {
		return err
	}
	// Atomically replace the file.
	return os.Rename(filepath.Join(s.dir, t), filepath.Join(s.dir, filename))
}

// CreateEmptyFile creates an empty file.
func (s *Storage) CreateEmptyFile(filename string, empty interface{}) error {
	return s.writeFile(context(filename), filename, empty)
}

// writeFile writes obj to a file.
func (s *Storage) writeFile(ctx []byte, filename string, obj interface{}) (retErr error) {
	fn := filepath.Join(s.dir, filename)
	if err := createParentIfNotExist(fn); err != nil {
		return err
	}

	var flags byte
	if _, ok := obj.(encoding.BinaryMarshaler); ok {
		flags = optBinaryEncoded
	} else if _, ok := obj.(*[]byte); ok {
		flags = optRawBytes
	} else if s.useGOB {
		flags = optGOBEncoded
	} else {
		flags = optJSONEncoded
	}
	if s.masterKey != nil {
		flags |= optEncrypted
		flags |= optPadded
	}
	if s.compress {
		flags |= optCompressed
	}

	w, err := s.openWriteStream(ctx, fn, flags, 64*1024)
	if err != nil {
		return err
	}
	defer func() {
		if err := w.Close(); err != nil && retErr == nil {
			retErr = err
		}
	}()

	switch enc := flags & optEncodingMask; enc {
	case optGOBEncoded:
		// Encode with GOB.
		if err := gob.NewEncoder(w).Encode(obj); err != nil {
			return err
		}
	case optJSONEncoded:
		// Encode as JSON object.
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if err := enc.Encode(obj); err != nil {
			return err
		}
	case optBinaryEncoded:
		// Encode with BinaryMarshaler.
		m, ok := obj.(encoding.BinaryMarshaler)
		if !ok {
			return fmt.Errorf("obj doesn't implement encoding.BinaryMarshaler: %T", obj)
		}
		b, err := m.MarshalBinary()
		if err != nil {
			return err
		}
		if _, err := w.Write(b); err != nil {
			return err
		}
	case optRawBytes:
		// Write raw bytes.
		b, ok := obj.(*[]byte)
		if !ok {
			return fmt.Errorf("obj isn't *[]byte: %T", obj)
		}
		if b != nil {
			if _, err := w.Write(*b); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unexpected encoding %x", enc)
	}

	return nil
}

// OpenBlobWrite opens a blob file for writing.
// writeFileName is the name of the file where to write the data.
// finalFileName is the final name of the file. The caller is expected to rename
// the file to that name when it is done with writing.
func (s *Storage) OpenBlobWrite(writeFileName, finalFileName string) (io.WriteCloser, error) {
	fn := filepath.Join(s.dir, writeFileName)
	if err := createParentIfNotExist(fn); err != nil {
		return nil, err
	}
	var flags byte = optRawBytes
	if s.masterKey != nil {
		flags |= optEncrypted
		flags |= optPadded
	}
	return s.openWriteStream(context(finalFileName), fn, flags, 1024*1024)
}

// OpenBlobRead opens a blob file for reading.
func (s *Storage) OpenBlobRead(filename string) (stream io.ReadSeekCloser, retErr error) {
	f, err := os.Open(filepath.Join(s.dir, filename))
	if err != nil {
		return nil, err
	}
	defer func() {
		if retErr != nil {
			f.Close()
		}
	}()

	hdr := make([]byte, 5)
	if _, err := io.ReadFull(f, hdr); err != nil {
		return nil, err
	}
	if string(hdr[:4]) != "KRIN" {
		return nil, errors.New("wrong file type")
	}
	flags := hdr[4]
	if flags&optRawBytes == 0 {
		return nil, errors.New("blob files is not raw bytes")
	}
	if flags&optCompressed != 0 {
		return nil, errors.New("blob files cannot be compressed")
	}
	if flags&optEncrypted != 0 && s.masterKey == nil {
		return nil, errors.New("file is encrypted, but a master key was not provided")
	}

	var r io.ReadSeekCloser = f
	if flags&optEncrypted != 0 {
		// Read the encrypted file key.
		k, err := s.masterKey.ReadEncryptedKey(f)
		if err != nil {
			return nil, err
		}
		defer k.Wipe()
		// Use the file key to decrypt the rest of the file.
		if r, err = k.StartReader(context(filename), f); err != nil {
			return nil, err
		}
		// Read the header again.
		h := make([]byte, 5)
		if _, err := io.ReadFull(r, h); err != nil {
			return nil, err
		}
		if bytes.Compare(hdr, h) != 0 {
			return nil, errors.New("wrong encrypted header")
		}
		if flags&optPadded != 0 {
			if err := SkipPadding(r); err != nil {
				return nil, err
			}
		}
	}
	off, err := r.Seek(0, io.SeekCurrent)
	if err != nil {
		return nil, err
	}
	return &seekWrapper{r, off}, nil
}

// seekWrapper wraps a read stream such that Seek calls are relative to the
// start offset.
type seekWrapper struct {
	io.ReadSeekCloser
	start int64
}

func (w *seekWrapper) Seek(offset int64, whence int) (newOffset int64, err error) {
	switch whence {
	case io.SeekStart:
		newOffset, err = w.ReadSeekCloser.Seek(w.start+offset, whence)
	default:
		newOffset, err = w.ReadSeekCloser.Seek(offset, whence)
	}
	newOffset -= w.start
	if newOffset < 0 {
		err = fs.ErrInvalid
	}
	return
}

// openWriteStream opens a write stream.
func (s *Storage) openWriteStream(ctx []byte, fullPath string, flags byte, maxPadding int) (io.WriteCloser, error) {
	f, err := os.OpenFile(fullPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL|os.O_SYNC, 0600)
	if err != nil {
		return nil, err
	}
	if _, err := f.Write([]byte{'K', 'R', 'I', 'N', flags}); err != nil {
		f.Close()
		return nil, err
	}
	var w io.WriteCloser = f
	if flags&optEncrypted != 0 {
		k, err := s.masterKey.NewKey()
		if err != nil {
			return nil, err
		}
		defer k.Wipe()
		// Write the encrypted file key first.
		if err := k.WriteEncryptedKey(f); err != nil {
			f.Close()
			return nil, err
		}
		// Use the file key to encrypt the rest of the file.
		if w, err = k.StartWriter(ctx, f); err != nil {
			f.Close()
			return nil, err
		}
		// Write the header again.
		if _, err := w.Write([]byte{'K', 'R', 'I', 'N', flags}); err != nil {
			w.Close()
			return nil, err
		}
		if flags&optPadded != 0 {
			if err := AddPadding(w, maxPadding); err != nil {
				return nil, err
			}
		}
	}
	var wc io.WriteCloser = w
	if flags&optCompressed != 0 {
		// Compress the content.
		gz, err := gzip.NewWriterLevel(w, gzip.BestSpeed)
		if err != nil {
			return nil, err
		}
		wc = &gzipWrapper{gz, w}
	}
	return wc, nil
}

// gzipWrapper wraps a gzip.Writer so that its Close function also closes the
// underlying stream.
type gzipWrapper struct {
	*gzip.Writer
	w io.Closer
}

func (gz *gzipWrapper) Close() error {
	err := gz.Writer.Close()
	if e := gz.w.Close(); err == nil {
		err = e
	}
	return err
}

// EditDataFile opens a file in a text editor.
func (s *Storage) EditDataFile(filename string, obj interface{}) (retErr error) {
	commit, err := s.OpenForUpdate(filename, obj)
	if err != nil {
		return err
	}
	defer commit(false, &retErr)

	tmpdir := os.TempDir()
	if _, err := os.Stat("/dev/shm"); err == nil {
		tmpdir = "/dev/shm"
	}
	dir, err := ioutil.TempDir(tmpdir, "edit-*")
	if err != nil {
		return err
	}
	defer func() { os.RemoveAll(dir) }()
	if err := os.Chmod(dir, 0700); err != nil {
		return err
	}
	fn := filepath.Join(dir, "datafile")
	f, err := os.Create(fn)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(obj); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	var bin string
	for _, ed := range []string{os.Getenv("EDITOR"), "vim", "vi", "nano"} {
		if ed == "" {
			continue
		}
		if bin, err = exec.LookPath(ed); err == nil {
			break
		}
		s.Logger().Debugf("LookPath(%q): %v", ed, err)
		continue

	}
	if bin == "" {
		return errors.New("cannot find any text editor")
	}
	for {
		cmd := exec.Command(bin, fn)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return err
		}

		// Clear the object before unmarshalling into it again.
		data := reflect.Indirect(reflect.ValueOf(obj))
		data.Set(reflect.Zero(data.Type()))

		in, err := os.Open(fn)
		if err != nil {
			return err
		}
		if err := json.NewDecoder(in).Decode(obj); err != nil {
			in.Close()
			fmt.Fprintf(os.Stderr, "JSON: %v\n", err)
			fmt.Printf("\nRetry (Y/n) ? ")
			reply, _ := bufio.NewReader(os.Stdin).ReadString('\n')
			if reply = strings.ToLower(strings.TrimSpace(reply)); reply == "n" {
				return errors.New("aborted")
			}
			continue
		}
		in.Close()
		break
	}
	return commit(true, nil)
}

// AddPadding writes a random-sized padding in the range [0,max[ at the current
// write position.
func AddPadding(w io.Writer, max int) error {
	b := make([]byte, 3)
	if _, err := rand.Read(b); err != nil {
		return err
	}
	n := int(uint(b[0])<<16|uint(b[1])<<8|uint(b[2])) % max
	if err := binary.Write(w, binary.BigEndian, int32(n)); err != nil {
		return err
	}
	buf := bytes.Repeat(b, 1000)
	for n > 0 {
		l := len(buf)
		if l > n {
			l = n
		}
		nn, err := w.Write(buf[:l])
		if err != nil {
			return err
		}
		n -= nn
	}
	return nil
}

// SkipPadding skips the random-sized padding starting at the current read
// position.
func SkipPadding(r io.ReadSeeker) error {
	var n int32
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return err
	}
	if n < 0 {
		return errors.New("invalid padding")
	}
	_, err := r.Seek(int64(n), io.SeekCurrent)
	return err
}
