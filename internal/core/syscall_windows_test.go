package core

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/windows"
)

func TestGetBits(t *testing.T) {
	processID, err := GetProcessID("WeChat.exe")
	if err != nil {
		t.Fatalf("GetProcessID failed: %v", err)
	}

	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, processID)
	if err != nil {
		t.Fatalf("OpenProcess failed: %+v", err)
	}
	defer windows.CloseHandle(handle) //nolint

	bits, err := GetBits(handle)
	if err != nil {
		t.Fatalf("GetBits failed: %v", err)
	}
	t.Log(bits)
}

func TestScanMemory(t *testing.T) {
	processID, err := GetProcessID("WeChat.exe")
	if err != nil {
		t.Fatalf("GetProcessID failed: %+v", err)
	}

	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, processID)
	if err != nil {
		t.Fatalf("OpenProcess failed: %+v", err)
	}
	defer windows.CloseHandle(handle) //nolint

	addrs, err := ScanMemoryWithOptions(handle, "saltfishpr", ScanMemoryOptions{
		ModuleName: "WeChatWin.dll",
		Limit:      100,
	})
	if err != nil {
		t.Fatalf("ScanMemory failed: %+v", err)
	}
	t.Logf("Found %d addresses", len(addrs))
}

func Test_find(t *testing.T) {
	type args struct {
		bits  int
		buf   []byte
		value any
	}
	tests := []struct {
		name      string
		args      args
		want      []uintptr
		assertion assert.ErrorAssertionFunc
	}{
		{
			name: "Success: Find int(int32) (Little Endian) at offset 0 and 8",
			args: args{
				bits:  32,
				buf:   []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x09, 0x0A},
				value: 0x04030201, // 对应字节序列 01 02 03 04
			},
			want:      []uintptr{0, 8},
			assertion: assert.NoError,
		},
		{
			name: "Success: Find int32 (Little Endian) at offset 0 and 8",
			args: args{
				bits:  0,
				buf:   []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x01, 0x02, 0x03, 0x04, 0x09, 0x0A},
				value: int32(0x04030201),
			},
			want:      []uintptr{0, 8},
			assertion: assert.NoError,
		},
		{
			name: "Success: Find int(int64) (Little Endian) at offset 0",
			args: args{
				bits:  64,
				buf:   []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A},
				value: 0x0807060504030201, // 对应字节序列 01 02 03 04 05 06 07 08
			},
			want:      []uintptr{0},
			assertion: assert.NoError,
		},
		{
			name: "Success: Find string at offset 0 and 8",
			args: args{
				bits:  0, // bits 对于 string 类型不生效，可以设为0或任意值
				buf:   []byte("hello world hello"),
				value: "hello",
			},
			want:      []uintptr{0, 12},
			assertion: assert.NoError,
		},
		{
			name: "Success: Find []byte at offset 6",
			args: args{
				bits:  0,
				buf:   []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
				value: []byte{0x07, 0x08},
			},
			want:      []uintptr{6},
			assertion: assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := find(tt.args.bits, tt.args.buf, tt.args.value)
			tt.assertion(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
