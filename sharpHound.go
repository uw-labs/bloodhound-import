// +build !windows

package main

import (
	"context"
	"fmt"

	"github.com/urfave/cli/v2"
)

func execSharpHound(ctx context.Context, c *cli.Context) error {
	return fmt.Errorf("executing sharphound is only supported on Windows Host. use `--bhi-upload-only` flag to run upload only mode")
}
