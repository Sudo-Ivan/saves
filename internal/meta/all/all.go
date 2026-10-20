// SPDX-License-Identifier: 0BSD

// Package all links every meta driver into the binary via its init
// registration. Import it for side effects where meta.Open is used.
package all

import (
	_ "github.com/Sudo-Ivan/saves/internal/meta/postgres"
	_ "github.com/Sudo-Ivan/saves/internal/meta/sqlite"
)
