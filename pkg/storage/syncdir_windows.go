package storage

// syncDir is a no-op on Windows, where directories cannot be opened for
// syncing and rename durability is provided by the filesystem itself.
func syncDir(string) error { return nil }
