//go:build linux || darwin || freebsd

package main

import "syscall"

func setSockBuf(fd uintptr, size int) {
        syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, size)
        syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, size)
}




