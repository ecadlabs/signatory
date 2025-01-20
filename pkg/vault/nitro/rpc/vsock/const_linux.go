package vsock

import "golang.org/x/sys/unix"

const (
	ContextAny        = unix.VMADDR_CID_ANY
	ContextHost       = unix.VMADDR_CID_HOST
	ContextHypervisor = unix.VMADDR_CID_HYPERVISOR
	ContextLocal      = unix.VMADDR_CID_LOCAL
)
