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
	"io"
	"time"
)

// Fastest runs an in-memory speedtest and returns the fastest encryption
// algorithm on the local computer.
func Fastest(opts ...Option) (int, error) {
	var opt option
	opt.apply(opts)
	algos := []struct {
		name string
		alg  int
		mk   func(...Option) (MasterKey, error)
	}{
		{"AES256", AES256, CreateAESMasterKey},
		{"Chacha20Poly1305", Chacha20Poly1305, CreateChacha20Poly1305MasterKey},
	}
	var fastest int = -1
	var fastestName string
	var fastestTime time.Duration
	mb := 20
	for _, a := range algos {
		mk, err := a.mk()
		if err != nil {
			return 0, err
		}
		t, err := speedTest(mk, mb<<20)
		mk.Wipe()
		if err != nil {
			return 0, err
		}
		opt.logger.Debugf("speedtest: %s(%d) encrypted %d MiB in %s", a.name, a.alg, mb, t)
		if fastest == -1 || t < fastestTime {
			fastest = a.alg
			fastestName = a.name
			fastestTime = t
		}
	}
	opt.logger.Infof("Using %s encryption.", fastestName)
	return fastest, nil
}

func speedTest(mk MasterKey, size int) (d time.Duration, err error) {
	start := time.Now()
	w, err := mk.StartWriter(nil, io.Discard)
	if err != nil {
		return d, err
	}
	var buf [4096]byte
	for size > 0 {
		n := size
		if n > len(buf) {
			n = len(buf)
		}
		if _, err := w.Write(buf[:n]); err != nil {
			return d, err
		}
		size -= n
	}
	if err := w.Close(); err != nil {
		return d, err
	}
	return time.Since(start), nil
}
