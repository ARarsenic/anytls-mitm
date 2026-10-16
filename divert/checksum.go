package divert

import (
	"sync"
	"unsafe"

	divert "github.com/imgk/divert-go"
	"golang.org/x/sys/windows"
)

var (
	checksumOnce sync.Once
	winDivertDLL *windows.DLL
	procCalc     *windows.Proc
)

func initChecksumProc() {
	dll, err := windows.LoadDLL("WinDivert.dll")
	if err == nil {
		winDivertDLL = dll
		procCalc, _ = dll.FindProc("WinDivertHelperCalcChecksums")
	}
}

// calcChecksums wraps WinDivertHelperCalcChecksums with correct return-value checking.
// Note: github.com/imgk/divert-go has a known bug where it checks `if err != nil` on
// syscall.Proc.Call, which is always non-nil (windows.Errno(0)) on Windows, incorrectly
// returning false every time.
func calcChecksums(buffer []byte, address *divert.Address, flags uint64) bool {
	if len(buffer) == 0 {
		return false
	}
	checksumOnce.Do(initChecksumProc)
	if procCalc == nil {
		// Fallback to library function if manual proc lookup failed
		return divert.CalcChecksums(buffer, address, flags)
	}

	r1, _, _ := procCalc.Call(
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(len(buffer)),
		uintptr(unsafe.Pointer(address)),
		uintptr(flags),
	)
	return r1 != 0
}
