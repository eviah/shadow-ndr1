// AVX-512 squared-residual kernel.
//
// func squaredResidualAVX512(out, a, b *float32, n uintptr)
//
// Computes out[i] = (a[i] - b[i]) * (a[i] - b[i]) for n elements, 16 lanes
// per iteration using ZMM registers. n MUST be a multiple of 16 and pointers
// 4-byte aligned (Go's allocator guarantees this for float32 slices).
//
// Plan 9 syntax. Assembled with the standard Go assembler (no external tools).

//go:build amd64

#include "textflag.h"

// func squaredResidualAVX512(out, a, b *float32, n uintptr)
// Stack frame:
//   out+0(FP), a+8(FP), b+16(FP), n+24(FP)
TEXT ·squaredResidualAVX512(SB), NOSPLIT, $0-32
	MOVQ out+0(FP), DI
	MOVQ a+8(FP),   SI
	MOVQ b+16(FP),  DX
	MOVQ n+24(FP),  CX
	SHRQ $4, CX                 // CX = n/16 (16 lanes per iteration)
	TESTQ CX, CX
	JZ done

loop:
	VMOVUPS (SI), Z0            // Z0 = a[i..i+16]
	VMOVUPS (DX), Z1            // Z1 = b[i..i+16]
	VSUBPS  Z1, Z0, Z2          // Z2 = a - b
	VMULPS  Z2, Z2, Z3          // Z3 = (a-b) * (a-b)
	VMOVUPS Z3, (DI)            // out[i..i+16] = Z3

	ADDQ $64, SI                // 16 floats * 4 bytes
	ADDQ $64, DX
	ADDQ $64, DI
	DECQ CX
	JNZ loop

done:
	VZEROUPPER
	RET
