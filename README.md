# Storage

This go package is used to store data in encrypted files. It is designed for convenience and correctness, and may not be suitable for high volume or high throughput applications. It was refactored from internal [c2fmzq-server](https://github.com/c2FmZQ/c2FmZQ) code, and re-licenced, so that other projects can use it.

GO objects can be saved, loaded, and atomically updated.

```go
mk, err := crypto.CreateMasterKey([]byte("<passphrase>"))
if err != nil {
    panic(err)
}
store := storage.New("<data dir>", mk)

var obj1 Object
// Populate obj1
if err := store.SaveDataFile("<relative filename>", &obj1); err != nil {
    panic(err)
}

var obj2 Object
if err := store.ReadDataFile("<relative filename>", &obj2); err != nil {
    panic(err)
}
// obj1 and obj2 have the same value
```

To update objects atomically:
```go
func foo() (retErr error) {
    var obj Object
    commit, err := store.OpenForUpdate("<relative filename>", &obj)
    if err != nil {
        panic(err)
    }
    defer commit(false, &retErr) // rollback unless first committed.
    // modify obj
    obj.Bar = X
    return commit(true, nil) // commit
}
```

Multiple objects can be updated atomically with `OpenManyForUpdate()`.

Developers can also use `OpenBlobRead()` and `OpenBlobWrite()` to read and write encrypted BLOBs with a streaming API.

