// SPDX-License-Identifier: 0BSD

package mem

import (
	"testing"

	"github.com/Sudo-Ivan/saves/internal/blob"
	"github.com/Sudo-Ivan/saves/internal/blob/blobtest"
)

func TestConformance(t *testing.T) {
	blobtest.Run(t, func(t *testing.T) blob.Store { return New() })
}
