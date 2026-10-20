// SPDX-License-Identifier: 0BSD
//go:build windows

package detect

import "golang.org/x/sys/windows/registry"

// winReg reads the Windows registry.
type winReg struct{}

// NewRegistry returns the real registry reader on Windows.
func NewRegistry() RegistryReader { return winReg{} }

func hive(root string) registry.Key {
	switch root {
	case "HKCU", "HKEY_CURRENT_USER":
		return registry.CURRENT_USER
	case "HKLM", "HKEY_LOCAL_MACHINE":
		return registry.LOCAL_MACHINE
	}
	return registry.CURRENT_USER
}

// Get reads a string value.
func (winReg) Get(root, path, name string) (string, error) {
	k, err := registry.OpenKey(hive(root), path, registry.READ)
	if err != nil {
		return "", err
	}
	defer k.Close()
	s, _, err := k.GetStringValue(name)
	return s, err
}

// ListKeys lists subkeys.
func (winReg) ListKeys(root, path string) ([]string, error) {
	k, err := registry.OpenKey(hive(root), path, registry.READ)
	if err != nil {
		return nil, err
	}
	defer k.Close()
	return k.ReadSubKeyNames(-1)
}
