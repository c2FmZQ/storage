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

// Package crypto implements a few abstractions around the go crypto packages
// to manage encryption keys, encrypt small data, and streams.
package crypto

import (
	"errors"
	"io"
	"log"
	"os"
	"runtime"

	"github.com/c2FmZQ/tpm"
)

const (
	AES256           int = iota // AES256-GCM, AES256-CBC+HMAC-SHA256, PBKDF2.
	Chacha20Poly1305            // Chacha20Poly1305, Argon2.
	AES256WithTPM               // Like AES256, with masterkey on TPM.

	DefaultAlgo = AES256
	PickFastest = -1
)

var (
	// Indicates that the ciphertext could not be decrypted.
	ErrDecryptFailed = errors.New("decryption failed")
	// Indicates that the plaintext could not be encrypted.
	ErrEncryptFailed = errors.New("encryption failed")
	// Indicates an invalid alg value.
	ErrUnexpectedAlgo = errors.New("unexpected algorithm")
)

// Logger is the interface for writing debug logs.
type Logger interface {
	Debug(...any)
	Debugf(string, ...any)
	Info(...any)
	Infof(string, ...any)
	Error(...any)
	Errorf(string, ...any)
	Fatal(...any)
	Fatalf(string, ...any)
}

// MasterKey is an encryption key that is normally stored on disk encrypted with
// a passphrase. It is used to create file keys used to encrypt the content of
// files.
type MasterKey interface {
	EncryptionKey

	// Save encrypts the MasterKey with passphrase and saves it to file.
	Save(passphrase []byte, file string) error
}

// Option is used to specify the parameters of MasterKey.
type Option struct {
	alg        *int
	logger     Logger
	strictWipe *bool
	tpm        *tpm.TPM
	passphrase []byte
}

// WithAlgo specifies the cryptographic algorithm to use.
func WithAlgo(alg int) Option {
	return Option{alg: &alg}
}

// WithLogger specifies the logger to use.
func WithLogger(l Logger) Option {
	return Option{logger: l}
}

// WithStrictWipe specifies whether strict wipe is required. When enabled, keys
// must be wiped by calling Wipe() when they are no longer needed. Otherwise,
// program execution will be stopped with a fatal error.
func WithStrictWipe(v bool) Option {
	return Option{strictWipe: &v}
}

// WithTPM specifies that the master key should be in the Trusted Platform
// Module (TPM).
// When this option is used, the data encrypted with the master key can only
// ever be decrypted with the same TPM.
func WithTPM(tpm *tpm.TPM) Option {
	return Option{tpm: tpm}
}

// CreateMasterKey creates a new master key.
func CreateMasterKey(opts ...Option) (MasterKey, error) {
	alg := DefaultAlgo
	for _, opt := range opts {
		if opt.alg != nil {
			alg = *opt.alg
		}
	}
	if alg == PickFastest {
		var err error
		if alg, err = Fastest(opts...); err != nil {
			alg = DefaultAlgo
		}
	}
	switch alg {
	case AES256, AES256WithTPM:
		return CreateAESMasterKey(opts...)
	case Chacha20Poly1305:
		return CreateChacha20Poly1305MasterKey(opts...)
	default:
		return nil, ErrUnexpectedAlgo
	}
}

// ReadMasterKey reads an encrypted master key from file and decrypts it.
func ReadMasterKey(passphrase []byte, file string, opts ...Option) (MasterKey, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	if len(b) == 0 {
		return nil, ErrUnexpectedAlgo
	}
	switch b[0] {
	case 1, 3: // AES256 or AES256WithTPM
		return ReadAESMasterKey(passphrase, file, opts...)
	case 2: // Chacha20Poly1305
		return ReadChacha20Poly1305MasterKey(passphrase, file, opts...)
	default:
		return nil, ErrUnexpectedAlgo
	}
}

// EncryptionKey is an encryption key that can be used to encrypt and decrypt
// data and streams.
type EncryptionKey interface {
	Logger() Logger

	// Encrypt encrypts data using the key.
	Encrypt(data []byte) ([]byte, error)
	// Decrypt decrypts data that was encrypted with Encrypt and the same key.
	Decrypt(data []byte) ([]byte, error)
	// Hash returns a cryptographially secure hash of b.
	Hash(b []byte) []byte
	// StartReader opens a reader to decrypt a stream of data.
	StartReader(ctx []byte, r io.Reader) (StreamReader, error)
	// StartWriter opens a writer to encrypt a stream of data.
	StartWriter(ctx []byte, w io.Writer) (StreamWriter, error)
	// NewKey creates a new encryption key.
	NewKey() (EncryptionKey, error)
	// DecryptKey decrypts an encrypted key.
	DecryptKey(encryptedKey []byte) (EncryptionKey, error)
	// ReadEncryptedKey reads an encrypted key and decrypts it.
	ReadEncryptedKey(r io.Reader) (EncryptionKey, error)
	// WriteEncryptedKey writes the encrypted key to the writer.
	WriteEncryptedKey(w io.Writer) error
	// Wipe zeros the key material.
	Wipe()
}

// StreamReader decrypts a stream.
type StreamReader interface {
	io.Reader
	io.Seeker
	io.Closer
}

// StreamWriter encrypts a stream.
type StreamWriter interface {
	io.Writer
	io.Closer
}

func stack() string {
	buf := make([]byte, 4096)
	n := runtime.Stack(buf, false)
	return string(buf[:n])
}

func StdLogger() Logger {
	return defaultLogger{}
}

type defaultLogger struct{}

func (defaultLogger) Debug(args ...any) {
	args = append([]any{"DEBUG: "}, args...)
	log.Print(args...)
}

func (defaultLogger) Debugf(f string, args ...any) {
	log.Printf("DEBUG: "+f, args...)
}

func (defaultLogger) Info(args ...any) {
	args = append([]any{"INFO: "}, args...)
	log.Print(args...)
}

func (defaultLogger) Infof(f string, args ...any) {
	log.Printf("INFO: "+f, args...)
}

func (defaultLogger) Error(args ...any) {
	args = append([]any{"ERROR: "}, args...)
	log.Print(args...)
}

func (defaultLogger) Errorf(f string, args ...any) {
	log.Printf("ERROR: "+f, args...)
}

func (defaultLogger) Fatal(args ...any) {
	args = append([]any{"FATAL: "}, args...)
	log.Fatal(args...)
}

func (defaultLogger) Fatalf(f string, args ...any) {
	log.Fatalf("FATAL: "+f, args...)
}
