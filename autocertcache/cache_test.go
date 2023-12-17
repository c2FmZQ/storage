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

package autocertcache_test

import (
	"context"
	"testing"

	"github.com/c2FmZQ/storage"
	"github.com/c2FmZQ/storage/autocertcache"
	"github.com/c2FmZQ/storage/crypto"
	"golang.org/x/crypto/acme/autocert"
)

func TestCache(t *testing.T) {
	ctx := context.Background()
	mk, err := crypto.CreateMasterKey()
	if err != nil {
		t.Fatalf("crypto.CreateMasterKey: %v", err)
	}
	defer mk.Wipe()
	cache := autocertcache.New("autocert", storage.New(t.TempDir(), mk))

	if v, err := cache.Keys(ctx); err != nil || len(v) != 0 {
		t.Errorf("cache.Keys() = %q, %v, want [], nil", v, err)
	}
	if v, err := cache.Get(ctx, "foo"); err != autocert.ErrCacheMiss || v != nil {
		t.Errorf("cache.Get(foo) = %v, %v, want nil, ErrCacheMiss", v, err)
	}
	if err := cache.Put(ctx, "foo", []byte("bar")); err != nil {
		t.Errorf("cache.Put(foo, bar) = %v", err)
	}
	if err := cache.Put(ctx, "bar", []byte("baz")); err != nil {
		t.Errorf("cache.Put(bar, baz) = %v", err)
	}
	if v, err := cache.Get(ctx, "foo"); err != nil || string(v) != "bar" {
		t.Errorf("cache.Get(foo) = %q, %v, want bar, nil", v, err)
	}
	if v, err := cache.Keys(ctx); err != nil || len(v) != 2 || v[0] != "bar" || v[1] != "foo" {
		t.Errorf("cache.Keys() = %q, %v, want [bar foo], nil", v, err)
	}
	if err := cache.Delete(ctx, "foo"); err != nil {
		t.Errorf("cache.Delete(foo) = %v", err)
	}
	if v, err := cache.Get(ctx, "foo"); err != autocert.ErrCacheMiss || v != nil {
		t.Errorf("cache.Get(foo) = %v, %v, want nil, ErrCacheMiss", v, err)
	}
	if err := cache.DeleteKeys(ctx, []string{"bar"}); err != nil {
		t.Errorf("cache.DeleteKeys([bar]) = %v", err)
	}
	if v, err := cache.Get(ctx, "bar"); err != autocert.ErrCacheMiss || v != nil {
		t.Errorf("cache.Get(bar) = %v, %v, want nil, ErrCacheMiss", v, err)
	}
}
