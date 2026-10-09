// Package configfile reads small, regular configuration files without
// blocking on a substituted FIFO or allocating beyond the configured bound.
package configfile

import (
	"errors"
	"fmt"
	"io"
)

func Read(path string, limit int64) ([]byte, error) {
	if limit < 0 {
		return nil, errors.New("config file size limit must be nonnegative")
	}
	f, err := open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("configuration must be a regular file")
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("configuration file is larger than %d bytes", limit)
	}
	// f.Stat and Read use the same descriptor. A replacement path does not
	// change what is read; concurrent file growth is bounded by LimitReader.
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("configuration file is larger than %d bytes", limit)
	}
	return b, nil
}
