package core

import (
	"testing"
)

func TestGetNativeSystemInfo(t *testing.T) {
	info := &systemInfo{}
	err := GetNativeSystemInfo(info)
	if err != nil {
		t.Fatalf("GetNativeSystemInfo failed: %v", err)
	}
	t.Logf("ProcessorArchitecture: %+v", info)
}
