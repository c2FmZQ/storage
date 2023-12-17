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

package autocertcache

import (
	"context"
	"encoding/base64"
	"sort"

	"github.com/c2FmZQ/storage"
	"golang.org/x/crypto/acme/autocert"
)

type cacheContent struct {
	Entries map[string]string `json:"entries"`
}

var _ autocert.Cache = (*Cache)(nil)

// New returns a new Autocert Cache stored in fileName and encrypted with storage.
func New(fileName string, storage *storage.Storage) *Cache {
	storage.CreateEmptyFile(fileName, cacheContent{})
	return &Cache{fileName, storage}
}

// Cache implements autocert.Cache
type Cache struct {
	fileName string
	storage  *storage.Storage
}

// Get returns a cached entry.
func (c *Cache) Get(_ context.Context, key string) ([]byte, error) {
	c.storage.Logger().Debugf("Cache.Get(%q)", key)
	var cc cacheContent
	if err := c.storage.ReadDataFile(c.fileName, &cc); err != nil {
		return nil, err
	}
	if cc.Entries == nil {
		cc.Entries = make(map[string]string)
	}
	e, ok := cc.Entries[key]
	if !ok {
		c.storage.Logger().Debugf("Cache.Get(%q) NOT found.", key)
		return nil, autocert.ErrCacheMiss
	}
	c.storage.Logger().Debugf("Cache.Get(%q) found.", key)
	return base64.StdEncoding.DecodeString(e)
}

// Put stores a cache entry.
func (c *Cache) Put(_ context.Context, key string, data []byte) error {
	c.storage.Logger().Debugf("Cache.Put(%q, ...)", key)
	var cc cacheContent
	commit, err := c.storage.OpenForUpdate(c.fileName, &cc)
	if err != nil {
		return err
	}
	if cc.Entries == nil {
		cc.Entries = make(map[string]string)
	}
	cc.Entries[key] = base64.StdEncoding.EncodeToString(data)
	return commit(true, nil)
}

// Delete deletes a cached entry.
func (c *Cache) Delete(_ context.Context, key string) error {
	c.storage.Logger().Debugf("Cache.Delete(%q)", key)
	var cc cacheContent
	commit, err := c.storage.OpenForUpdate(c.fileName, &cc)
	if err != nil {
		return err
	}
	if cc.Entries == nil {
		cc.Entries = make(map[string]string)
	}
	delete(cc.Entries, key)
	return commit(true, nil)
}

// DeleteKeys deletes a list of cached entries.
func (c *Cache) DeleteKeys(_ context.Context, keys []string) error {
	c.storage.Logger().Debugf("Cache.DeleteKeys(%q)", keys)
	var cc cacheContent
	commit, err := c.storage.OpenForUpdate(c.fileName, &cc)
	if err != nil {
		return err
	}
	if cc.Entries == nil {
		cc.Entries = make(map[string]string)
	}
	for _, key := range keys {
		delete(cc.Entries, key)
	}
	return commit(true, nil)
}

// Keys returns all the cache keys.
func (c *Cache) Keys(_ context.Context) ([]string, error) {
	c.storage.Logger().Debug("Cache.Keys()")
	var cc cacheContent
	if err := c.storage.ReadDataFile(c.fileName, &cc); err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(cc.Entries))
	for k := range cc.Entries {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys, nil
}
