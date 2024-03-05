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
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"

	"github.com/c2FmZQ/tpm"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/pbkdf2"
)

const (
	// The size of an encrypted key.
	aesEncryptedKeySize = 129 // 1 (version) + 16 (iv) + 64 (key) + 16 (pad) + 32 (mac)

	// The size of encrypted chunks in streams.
	aesFileChunkSize = 1 << 20
)

// AESKey is an encryption key that can be used to encrypt and decrypt
// data and streams.
type AESKey struct {
	maskedKey    []byte
	encryptedKey []byte
	xor          func([]byte) []byte

	logger     Logger
	strictWipe bool
	tpmKey     *tpm.Key
	tpmCtx     []byte
}

func (k *AESKey) Logger() Logger {
	return k.logger
}

// Wipe zeros the key material.
func (k *AESKey) Wipe() {
	for i := range k.maskedKey {
		k.maskedKey[i] = 0
	}
	runtime.SetFinalizer(k, nil)
}

func (k *AESKey) setFinalizer() {
	buf := make([]byte, 4096)
	n := runtime.Stack(buf, false)
	stack := string(buf[:n])

	runtime.SetFinalizer(k, func(obj interface{}) {
		key := obj.(*AESKey)
		for i := range key.maskedKey {
			if key.maskedKey[i] != 0 {
				if key.strictWipe {
					key.Logger().Fatalf("WIPEME: AESKey not wiped. Call stack: %s", stack)
				}
				key.Logger().Errorf("WIPEME: AESKey not wiped. Call stack: %s", stack)
				key.Wipe()
				return
			}
		}
	})
}

type AESMasterKey struct {
	*AESKey
}

// CreateAESMasterKey creates a new master key.
func CreateAESMasterKey(opts ...Option) (MasterKey, error) {
	var logger Logger = defaultLogger{}
	var strictWipe bool
	var useTPM *tpm.TPM
	for _, opt := range opts {
		if opt.logger != nil {
			logger = opt.logger
		}
		if opt.strictWipe != nil {
			strictWipe = *opt.strictWipe
		}
		if opt.tpm != nil {
			useTPM = opt.tpm
		}
	}
	b := make([]byte, 64)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	key := aesKeyFromBytes(b)
	key.logger = logger
	key.strictWipe = strictWipe
	mk := &AESMasterKey{key}
	if useTPM != nil {
		tpmctx, err := useTPM.CreateKey()
		if err != nil {
			return nil, err
		}
		tpmkey, err := useTPM.Key(tpmctx)
		if err != nil {
			return nil, err
		}
		mk.tpmKey = tpmkey
		mk.tpmCtx = tpmctx
	}
	return mk, nil
}

// CreateAESMasterKeyForTest creates a new master key to tests.
func CreateAESMasterKeyForTest() (MasterKey, error) {
	b := make([]byte, 64)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	mk := &AESMasterKey{aesKeyFromBytes(b)}
	mk.strictWipe = true
	mk.logger = defaultLogger{}
	runtime.SetFinalizer(mk.AESKey, nil)
	return mk, nil
}

// ReadAESMasterKey reads an encrypted master key from file and decrypts it.
func ReadAESMasterKey(passphrase []byte, file string, opts ...Option) (MasterKey, error) {
	var logger Logger = defaultLogger{}
	var strictWipe bool
	var useTPM *tpm.TPM
	for _, opt := range opts {
		if opt.logger != nil {
			logger = opt.logger
		}
		if opt.strictWipe != nil {
			strictWipe = *opt.strictWipe
		}
		if opt.tpm != nil {
			useTPM = opt.tpm
		}
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	if len(b) < 64 {
		return nil, ErrDecryptFailed
	}
	str := cryptobyte.String(b)
	var version uint8
	if !str.ReadUint8(&version) {
		return nil, ErrDecryptFailed
	}
	if version != 1 && version != 3 {
		logger.Debugf("ReadMasterKey: unexpected version: %d", version)
		return nil, ErrDecryptFailed
	}
	if version == 3 && useTPM == nil {
		logger.Debug("ReadMasterKey: missing WithTPM option")
		return nil, ErrDecryptFailed
	}
	salt := make([]byte, 16)
	if !str.ReadBytes(&salt, 16) {
		return nil, ErrDecryptFailed
	}
	var numIter uint32
	if !str.ReadUint32(&numIter) {
		return nil, ErrDecryptFailed
	}
	dk := pbkdf2.Key(passphrase, salt, int(numIter), 32, sha256.New)
	block, err := aes.NewCipher(dk)
	if err != nil {
		logger.Debug(err)
		return nil, ErrDecryptFailed
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		logger.Debug(err)
		return nil, ErrDecryptFailed
	}
	nonce := make([]byte, gcm.NonceSize())
	if !str.ReadBytes(&nonce, len(nonce)) {
		return nil, ErrDecryptFailed
	}
	mkBytes, err := gcm.Open(nil, nonce, []byte(str), nil)
	if err != nil {
		logger.Debug(err)
		return nil, ErrDecryptFailed
	}
	var key *AESKey
	if version == 1 {
		key = aesKeyFromBytes(mkBytes)
	} else { // version == 3
		str := cryptobyte.String(mkBytes)
		var length uint16
		if !str.ReadUint16(&length) {
			return nil, ErrDecryptFailed
		}
		encKey := make([]byte, length)
		if !str.ReadBytes(&encKey, len(encKey)) {
			return nil, ErrDecryptFailed
		}
		if !str.ReadUint16(&length) {
			return nil, ErrDecryptFailed
		}
		tpmCtx := make([]byte, length)
		if !str.ReadBytes(&tpmCtx, len(tpmCtx)) {
			return nil, ErrDecryptFailed
		}
		tpmKey, err := useTPM.Key(tpmCtx)
		if err != nil {
			return nil, err
		}
		decKey, err := tpmKey.Decrypt(nil, encKey, nil)
		if err != nil {
			logger.Debug(err)
			return nil, ErrDecryptFailed
		}
		key = aesKeyFromBytes(decKey)
		key.tpmKey = tpmKey
		key.tpmCtx = tpmCtx
	}
	key.logger = logger
	key.strictWipe = strictWipe
	return &AESMasterKey{key}, nil
}

// Save encrypts the key with passphrase and saves it to file.
func (mk AESMasterKey) Save(passphrase []byte, file string) error {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	numIter := 200000
	if len(passphrase) == 0 {
		numIter = 10
	}
	dk := pbkdf2.Key(passphrase, salt, numIter, 32, sha256.New)
	block, err := aes.NewCipher(dk)
	if err != nil {
		mk.Logger().Debug(err)
		return ErrEncryptFailed
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		mk.Logger().Debug(err)
		return ErrEncryptFailed
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		mk.Logger().Debug(err)
		return ErrEncryptFailed
	}
	var version uint8
	var payload []byte
	if mk.tpmKey == nil {
		version = 1
		payload = mk.key()
	} else {
		version = 3
		buf := cryptobyte.NewBuilder(nil)
		encKey, err := mk.tpmKey.Encrypt(mk.key())
		if err != nil {
			mk.Logger().Debug(err)
			return ErrEncryptFailed
		}
		buf.AddUint16(uint16(len(encKey)))
		buf.AddBytes(encKey)
		buf.AddUint16(uint16(len(mk.tpmCtx)))
		buf.AddBytes(mk.tpmCtx)
		if payload, err = buf.Bytes(); err != nil {
			mk.Logger().Debug(err)
			return ErrEncryptFailed
		}
	}
	encMasterKey := gcm.Seal(nonce, nonce, payload, nil)
	buf := cryptobyte.NewBuilder([]byte{version})
	buf.AddBytes(salt)
	buf.AddUint32(uint32(numIter))
	buf.AddBytes(encMasterKey)
	data, err := buf.Bytes()
	if err != nil {
		mk.Logger().Debug(err)
		return ErrEncryptFailed
	}
	dir, _ := filepath.Split(file)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if err := os.WriteFile(file, data, 0600); err != nil {
		return err
	}
	return nil
}

func (k AESKey) key() []byte {
	return k.xor(k.maskedKey)
}

// Hash returns the HMAC-SHA256 hash of b.
func (k AESKey) Hash(b []byte) []byte {
	mac := hmac.New(sha256.New, k.key()[32:])
	mac.Write(b)
	return mac.Sum(nil)
}

// Decrypt decrypts data that was encrypted with Encrypt and the same key.
func (k AESKey) Decrypt(data []byte) ([]byte, error) {
	if k.tpmKey != nil {
		sigSize := k.tpmKey.Bits() / 8
		if len(data) < 1+sigSize {
			return nil, ErrDecryptFailed
		}
		version, data := data[0], data[1:]
		if version != 3 {
			return nil, ErrDecryptFailed
		}
		encData, data := data[:len(data)-sigSize], data[len(data)-sigSize:]
		sig := data[:sigSize]
		hashed := sha256.Sum256(encData)
		if err := rsa.VerifyPKCS1v15(k.tpmKey.Public().(*rsa.PublicKey), crypto.SHA256, hashed[:], sig); err != nil {
			return nil, ErrDecryptFailed
		}
		return k.tpmKey.Decrypt(nil, encData, nil)
	}
	if len(k.maskedKey) == 0 {
		k.Logger().Fatal("key is not set")
	}
	if (len(data)-1)%aes.BlockSize != 0 || len(data)-1 < aes.BlockSize+32 {
		return nil, ErrDecryptFailed
	}
	version, data := data[0], data[1:]
	if version != 1 {
		return nil, ErrDecryptFailed
	}
	iv, data := data[:aes.BlockSize], data[aes.BlockSize:]
	encData, data := data[:len(data)-32], data[len(data)-32:]
	hm := data[:32]
	if !hmac.Equal(hm, k.Hash(encData)) {
		return nil, ErrDecryptFailed
	}
	block, err := aes.NewCipher(k.key()[:32])
	if err != nil {
		return nil, ErrDecryptFailed
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	dec := make([]byte, len(encData))
	mode.CryptBlocks(dec, encData)
	padSize := int(dec[len(dec)-1])
	if padSize > len(encData) || padSize > aes.BlockSize {
		return nil, ErrDecryptFailed
	}
	for i := 0; i < padSize; i++ {
		if dec[len(dec)-i-1] != byte(padSize) {
			return nil, ErrDecryptFailed
		}
	}
	return dec[:len(dec)-padSize], nil
}

// Encrypt encrypts data using the key.
func (k AESKey) Encrypt(data []byte) ([]byte, error) {
	if k.tpmKey != nil {
		encData, err := k.tpmKey.Encrypt(data)
		if err != nil {
			return nil, ErrEncryptFailed
		}
		hashed := sha256.Sum256(encData)
		sig, err := k.tpmKey.Sign(nil, hashed[:], crypto.SHA256)
		if err != nil {
			return nil, ErrEncryptFailed
		}
		out := make([]byte, 1+len(encData)+len(sig))
		out[0] = 3 // version
		copy(out[1:], encData)
		copy(out[1+len(encData):], sig)
		return out, nil
	}
	if len(k.maskedKey) == 0 {
		k.Logger().Fatal("key is not set")
	}
	block, err := aes.NewCipher(k.key()[:32])
	if err != nil {
		return nil, ErrEncryptFailed
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, ErrEncryptFailed
	}
	padSize := aes.BlockSize - len(data)%aes.BlockSize
	pData := make([]byte, len(data)+padSize)
	copy(pData, data)
	for i := 0; i < padSize; i++ {
		pData[len(data)+i] = byte(padSize)
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	encData := make([]byte, len(pData))
	mode.CryptBlocks(encData, pData)
	for i := range pData {
		pData[i] = 0
	}
	hmac := k.Hash(encData)

	out := make([]byte, 1+len(iv)+len(encData)+len(hmac))
	out[0] = 1 // version
	copy(out[1:], iv)
	copy(out[1+len(iv):], encData)
	copy(out[1+len(iv)+len(encData):], hmac)
	return out, nil
}

// aesKeyFromBytes returns an AESKey with the raw bytes provided.
// Internally, the key is masked with a ephemeral key in memory.
func aesKeyFromBytes(b []byte) *AESKey {
	mask := make([]byte, len(b))
	if _, err := rand.Read(mask); err != nil {
		panic(err)
	}
	xor := func(in []byte) []byte {
		out := make([]byte, len(mask))
		for i := range mask {
			out[i] = in[i] ^ mask[i]
		}
		return out
	}
	ek := &AESKey{maskedKey: xor(b), xor: xor}
	for i := range b {
		b[i] = 0
	}
	ek.setFinalizer()
	return ek
}

// NewKey creates a new encryption key.
func (k AESKey) NewKey() (EncryptionKey, error) {
	b := make([]byte, 64)
	if _, err := rand.Read(b); err != nil {
		k.Logger().Debug(err)
		return nil, ErrEncryptFailed
	}
	enc, err := k.Encrypt(b)
	if err != nil {
		return nil, err
	}
	ek := aesKeyFromBytes(b)
	ek.encryptedKey = enc
	ek.logger = k.logger
	return ek, nil
}

func (k AESKey) keysize() int {
	if k.tpmKey != nil {
		return 2*k.tpmKey.Bits()/8 + 1
	}
	return aesEncryptedKeySize
}

// DecryptKey decrypts an encrypted key.
func (k AESKey) DecryptKey(encryptedKey []byte) (EncryptionKey, error) {
	if len(encryptedKey) != k.keysize() {
		k.Logger().Debugf("DecryptKey: unexpected encrypted key size %d != %d", len(encryptedKey), k.keysize())
		return nil, ErrDecryptFailed
	}
	b, err := k.Decrypt(encryptedKey)
	if err != nil {
		return nil, err
	}
	if len(b) != 64 {
		k.Logger().Debugf("DecryptKey: unexpected decrypted key size %d != %d", len(b), 64)
		return nil, ErrDecryptFailed
	}
	ek := aesKeyFromBytes(b)
	ek.encryptedKey = make([]byte, len(encryptedKey))
	copy(ek.encryptedKey, encryptedKey)
	ek.logger = k.logger
	return ek, nil
}

// AESStreamReader decrypts an input stream.
type AESStreamReader struct {
	logger Logger

	gcm   cipher.AEAD
	r     io.Reader
	ctx   []byte
	start int64
	off   int64
	buf   []byte
}

func gcmNonce(ctx []byte, counter int64) []byte {
	var n [12]byte
	copy(n[:4], ctx)
	binary.BigEndian.PutUint64(n[4:], uint64(counter))
	return n[:]
}

// Seek moves the next read to a new offset. The offset is in the decrypted
// stream.
func (r *AESStreamReader) Seek(offset int64, whence int) (int64, error) {
	var newOffset int64
	switch whence {
	case io.SeekStart:
		newOffset = offset
	case io.SeekCurrent:
		newOffset = r.off + offset
	case io.SeekEnd:
		seeker, ok := r.r.(io.Seeker)
		if !ok {
			return 0, errors.New("input is not seekable")
		}
		size, err := seeker.Seek(0, io.SeekEnd)
		if err != nil {
			return 0, err
		}
		nChunks := (size - r.start) / int64(aesFileChunkSize+r.gcm.Overhead())
		lastChunkSize := (size - r.start) % int64(aesFileChunkSize+r.gcm.Overhead())
		if lastChunkSize > 0 {
			lastChunkSize -= int64(r.gcm.Overhead())
		}
		if lastChunkSize < 0 {
			return 0, errors.New("invalid last chunk")
		}
		decSize := nChunks*int64(aesFileChunkSize) + lastChunkSize
		newOffset = decSize + offset
	default:
		return 0, fmt.Errorf("invalid whence: %d", whence)
	}
	if newOffset < 0 {
		return 0, fs.ErrInvalid
	}
	if newOffset == r.off {
		return r.off, nil
	}
	// Move to new offset. Fast path if we already have enough data in the
	// buffer.
	if d := newOffset - r.off; d > 0 && d < int64(len(r.buf)) {
		r.buf = r.buf[int(d):]
		r.off = newOffset
		return r.off, nil
	}

	// Move to new offset. Slow path. Seek to new position and read a new
	// chunk.
	seeker, ok := r.r.(io.Seeker)
	if !ok {
		return 0, errors.New("input is not seekable")
	}
	r.off = newOffset
	chunkOffset := r.off % int64(aesFileChunkSize)
	seekTo := r.start + r.off/int64(aesFileChunkSize)*int64(aesFileChunkSize+r.gcm.Overhead())
	if _, err := seeker.Seek(seekTo, io.SeekStart); err != nil {
		return 0, err
	}
	r.buf = nil
	if err := r.readChunk(); err != nil && err != io.EOF {
		return 0, err
	}
	if chunkOffset < int64(len(r.buf)) {
		r.buf = r.buf[chunkOffset:]
	} else {
		r.buf = nil
	}
	return r.off, nil
}

func (r *AESStreamReader) readChunk() error {
	in := make([]byte, aesFileChunkSize+r.gcm.Overhead())
	n, err := io.ReadFull(r.r, in)
	if n > 0 {
		nonce := gcmNonce(r.ctx, r.off/int64(aesFileChunkSize)+1)
		if n <= r.gcm.Overhead() {
			r.logger.Debugf("StreamReader.Read: short chunk %d", n)
			return ErrDecryptFailed
		}
		dec, err := r.gcm.Open(nil, nonce, in[:n], nil)
		if err != nil {
			r.logger.Debug(err)
			return ErrDecryptFailed
		}
		r.buf = append(r.buf, dec...)
	}
	if err == io.ErrUnexpectedEOF {
		err = io.EOF
	}
	if len(r.buf) > 0 && err == io.EOF {
		err = nil
	}
	return err
}

func (r *AESStreamReader) Read(b []byte) (n int, err error) {
	for err == nil {
		nn := copy(b[n:], r.buf)
		r.buf = r.buf[nn:]
		r.off += int64(nn)
		n += nn
		if n == len(b) {
			break
		}
		err = r.readChunk()
	}
	if n > 0 {
		return n, nil
	}
	return n, err
}

func (r *AESStreamReader) Close() error {
	if c, ok := r.r.(io.Closer); ok {
		if err := c.Close(); err != nil {
			return err
		}
	}
	return nil
}

// StartReader opens a reader to decrypt a stream of data.
func (k AESKey) StartReader(ctx []byte, r io.Reader) (StreamReader, error) {
	if k.tpmKey != nil {
		return nil, errors.New("operation not supported with TPM key")
	}
	var start int64
	if seeker, ok := r.(io.Seeker); ok {
		off, err := seeker.Seek(0, io.SeekCurrent)
		if err != nil {
			panic(err)
		}
		start = off
	}

	block, err := aes.NewCipher(k.key()[:32])
	if err != nil {
		k.Logger().Debug(err)
		return nil, ErrDecryptFailed
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		k.Logger().Debug(err)
		return nil, ErrDecryptFailed
	}
	return &AESStreamReader{logger: k.logger, gcm: gcm, r: r, ctx: ctx, start: start}, nil
}

// AESStreamWriter encrypts a stream of data.
type AESStreamWriter struct {
	gcm cipher.AEAD
	w   io.Writer
	ctx []byte
	c   int64
	buf []byte
}

func (w *AESStreamWriter) writeChunk(b []byte) (int, error) {
	w.c++
	nonce := gcmNonce(w.ctx, w.c)
	out := w.gcm.Seal(nil, nonce, b, nil)
	for i := range b {
		b[i] = 0
	}
	return w.w.Write(out)
}

func (w *AESStreamWriter) Write(b []byte) (n int, err error) {
	w.buf = append(w.buf, b...)
	n = len(b)
	for len(w.buf) >= aesFileChunkSize {
		_, err = w.writeChunk(w.buf[:aesFileChunkSize])
		w.buf = w.buf[aesFileChunkSize:]
		if err != nil {
			break
		}
	}
	return
}

func (w *AESStreamWriter) Close() (err error) {
	if len(w.buf) > 0 {
		_, err = w.writeChunk(w.buf)
	}
	if c, ok := w.w.(io.Closer); ok {
		if e := c.Close(); err == nil {
			err = e
		}
	}
	return
}

// StartWriter opens a writer to encrypt a stream of data.
func (k AESKey) StartWriter(ctx []byte, w io.Writer) (StreamWriter, error) {
	if k.tpmKey != nil {
		return nil, errors.New("operation not supported with TPM key")
	}
	block, err := aes.NewCipher(k.key()[:32])
	if err != nil {
		k.Logger().Debug(err)
		return nil, ErrEncryptFailed
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		k.Logger().Debug(err)
		return nil, ErrEncryptFailed
	}
	return &AESStreamWriter{gcm: gcm, w: w, ctx: ctx}, nil
}

// ReadEncryptedKey reads an encrypted key and decrypts it.
func (k AESKey) ReadEncryptedKey(r io.Reader) (EncryptionKey, error) {
	buf := make([]byte, k.keysize())
	if _, err := io.ReadFull(r, buf); err != nil {
		k.Logger().Debug(err)
		return nil, ErrDecryptFailed
	}
	return k.DecryptKey(buf)
}

// WriteEncryptedKey writes the encrypted key to the writer.
func (k AESKey) WriteEncryptedKey(w io.Writer) error {
	n, err := w.Write(k.encryptedKey)
	if n == 0 {
		k.Logger().Debugf("WriteEncryptedKey: unexpected key size: %d", n)
		return ErrEncryptFailed
	}
	return err
}
