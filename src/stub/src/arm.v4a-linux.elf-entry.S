/*  arm-linux.elf-entry.S -- Linux program entry point & decompressor (Elf binary)
*
*  This file is part of the UPX executable compressor.
*
*  Copyright (C) 1996-2024 Markus Franz Xaver Johannes Oberhumer
*  Copyright (C) 1996-2024 Laszlo Molnar
*  Copyright (C) 2000-2024 John F. Reiser
*  All Rights Reserved.
*
*  UPX and the UCL library are free software; you can redistribute them
*  and/or modify them under the terms of the GNU General Public License as
*  published by the Free Software Foundation; either version 2 of
*  the License, or (at your option) any later version.
*
*  This program is distributed in the hope that it will be useful,
*  but WITHOUT ANY WARRANTY; without even the implied warranty of
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*  GNU General Public License for more details.
*
*  You should have received a copy of the GNU General Public License
*  along with this program; see the file COPYING.
*  If not, write to the Free Software Foundation, Inc.,
*  59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*
*  Markus F.X.J. Oberhumer              Laszlo Molnar
*  <markus@oberhumer.com>               <ezerotven+github@gmail.com>
*
*  John F. Reiser
*  <jreiser@users.sourceforge.net>
*/

NBPW= 4
#define ARM_OLDABI 1
#include "arch/arm/v4a/macros.S"

#define bkpt .long 0xe7f001f0  /* reserved instr; Linux GNU eabi breakpoint */
sz_Elf32_Phdr =  8*4
  p_vaddr = 2*4
sz_Elf32_Ehdr = 13*4
  e_type= 16
    ET_DYN= 3
  e_phnum= 16 + 2*2 + 5*4 + 2*2

sz_b_info= 12
  sz_unc= 0
  sz_cpr= 4
  b_method= 8
sz_l_info= 12
sz_p_info= 12

PROT_READ=  1
PROT_WRITE= 2
PROT_EXEC=  4

is_ptinterp=     (1<<0)
unmap_all_pages= (1<<1)

MAP_ANONYMOUS= 0x20
MAP_FIXED=     0x10
MAP_PRIVATE=   0x02

FD_stderr=      2
O_RDONLY=       0

PAGE_SHIFT= 12
PAGE_SIZE = -(~0<<PAGE_SHIFT)

AT_NULL= 0
AT_PAGESZ= 6

__NR_exit =      1 + __NR_SYSCALL_BASE
__NR_open =      5 + __NR_SYSCALL_BASE

__NR_write =     4 + __NR_SYSCALL_BASE
__NR_mmap64 = 0xc0 + __NR_SYSCALL_BASE
__NR_mprotect= 125 + __NR_SYSCALL_BASE

__ARM_NR_BASE  = 0xf0000 + __NR_SYSCALL_BASE
__ARM_NR_cacheflush =  2 + __ARM_NR_BASE

#ifndef DEBUG  /*{*/
#define DEBUG 0
#endif  /*}*/

#if DEBUG  //{
#define TRACE_REGS r0-r12,r14,r15
// sp (r13) is not included because the write-back might cause UNDEFINED behavior
// if the write-back register is not first or last.  The actual value of sp
// usually does not matter.  Just remember that lr (r14) and pc (r15) are stored
// one word closer to the stack pointer because r13 has been omitted.
#endif  //}

        //.long sz_pack2  // placed there by ::pack3()
  section ELFMAINX
start_params:
sz_pack2= . - 4
mflg:
        .long MFLG  // MAP_{PRIVATE|ANONYMOUS}  // QNX vs linux
_start: .globl _start
////  nop; bkpt
        stmdb sp!, {r0,r1}  // ABI crt0 -static may have data here

F_elfaddr= 0*NBPW
F_fd=      1*NBPW
  F_szpage= F_fd
F_ADRU=    2*NBPW
F_LENU=    3*NBPW
F_f_exp=   4*NBPW
F_entry=   5*NBPW
  F_mflg=    F_entry
F_r0=      6*NBPW
F_r1=      7*NBPW
F_FRAME=   8*NBPW

        sub sp,sp,#F_FRAME - 2*NBPW

        bl main  // lr= &f_exp
f_exp:
#define LINUX_ARM_CACHEFLUSH 1

  section NRV_HEAD
        // empty
  section NRV_TAIL
        // empty

  section NRV2E
#include "arch/arm/v4a/nrv2e_d8.S"

  section NRV2D
#include "arch/arm/v4a/nrv2d_d8.S"

  section NRV2B
#include "arch/arm/v4a/nrv2b_d8.S"

#include "arch/arm/v4a/lzma_d.S"

  section ELFMAINY
end_decompress: .globl end_decompress
        /* IDENTSTR goes here */

section ELFMAINZ
unfold:  // in: r3= mflg; r6= elfaddr; lr= &O_BINFO
        add r6,lr,#4  @ &b_info of folded stub

// Reserve space for unfolded stub
        mov r5,#0  @ offset
        mov r4,#-1  @ fd
        @r3= mflg  @ MAP_PRIVATE|MAP_ANONYMOUS or MAP_PRIVANON
        mov r2,#PROT_READ|PROT_WRITE|PROT_EXEC
        ldr r1,[r6,#sz_unc]
        mov r0,#0  @ kernel chooses addr
        str r1,[sp,#F_LENU]  @ length to munmap
        do_sys7t __NR_mmap64
        str r0,[sp,#F_ADRU]  @ addr to munmap
#if DEBUG  /*{*/
        stmdb sp!,{TRACE_REGS}; mov r0,#1; bl trace
#endif  /*}*/

// Unfold
        ldr r3,[r6,#sz_unc]; str r3,[sp,#-NBPW]!  @ P_01
        mov r3,sp  @ &sz_unc = &dstlen
        mov r2,r0  @ dst
        ldrb r0,[r6,#b_method]; str r0,[sp,#-NBPW]!  @ P_02  5th param to f_exp
        ldr r1,[r6,#sz_cpr]  @ srclen
        add r0,r6,#sz_b_info  @ src
        mov r10,r2  @ copy of dst
#if DEBUG  /*{*/
        stmdb sp!,{TRACE_REGS}; mov r0,#2; bl trace
#endif  /*}*/
        mov lr,pc; ldr pc,[sp,#2*NBPW+ F_f_exp]  @ call f_exp  [ARMv4 lacks blx]
        add sp,sp,#NBPW  @ P_02  remove 5th param
        ldr r3,[sp],#4  @ P_01  sz_unc

// pass run-time constants into unfolded code
        ldr r1,[sp,#F_mflg]  @ mflg
        str r1,[r10],#NBPW  @ pass mflg to folded code
        ldr r1,[sp,#F_szpage]
        str r1,[r10],#NBPW

// PROT_EXEC
        mov r2,#PROT_EXEC|PROT_READ
        ldr r1,[sp,#F_LENU]
        ldr r0,[sp,#F_ADRU]
        do_sys7t __NR_mprotect

// jmp unfolded_code
        ldr r0,[sp,#F_elfaddr]
        ldr r3,[r6,#-4]  @ O_BINFO | is_ptinterp | unmap_all_pages
        bic r4,r3,#is_ptinterp | unmap_all_pages
        add r5,r0,r4  @ ADRX= &b_info
        sub r4,r9,r4  @ LENX= sz_pack2 - O_BINFO
#if DEBUG  /*{*/
        stmdb sp!,{TRACE_REGS}; mov r0,#3; bl trace
#endif  /*}*/
        add pc,r10, #2*NBPW  @ goto unfold

#if DEBUG  /*{*/
TRACE_BUFLEN=512
trace:
        str lr,[sp,#(-1+ 15)*NBPW]  @ return pc; [remember: sp is not stored]
        mov r4,sp  @ &saved_r0
        sub sp,sp,#TRACE_BUFLEN
        mov r2,sp  @ output string

        mov r1,#'\n'; bl trace_hex  @ In: r0 as label
        mov r1,#'>';  strb r1,[r2],#1

        mov r5,#3  @ rows to print
L600:  @ each row
        sub r0,r4,#TRACE_BUFLEN
        sub r0,r0,sp
        mov r0,r0,lsr #2; mov r1,#'\n'; bl trace_hex  @ which block of 8

        mov r6,#8  @ words per row
L610:  @ each word
        ldr r0,[r4],#NBPW; mov r1,#' '; bl trace_hex  @ next word
        subs r6,r6,#1; bgt L610

        subs r5,r5,#1; bgt L600

        mov r0,#'\n'; strb r0,[r2],#1
        sub r2,r2,sp  @ count
        mov r1,sp  @ buf
        mov r0,#2  @ FD_STDERR
#if defined(ARMEL_EABI4)  /*{*/
        mov r7,#__NR_write
        swi 0
#else  /*}{*/
        swi __NR_write
#endif  /*}*/
        add sp,sp,#TRACE_BUFLEN
        ldmia sp!,{TRACE_REGS}

trace_hex:  // In: r0=val, r1=punctuation before, r2=ptr; Uses: r3, ip
        strb r1,[r2],#1  @ punctuation
        mov r3,#NBPW*(8 -1)  @ shift count
        adr ip,hex
L620:
        mov r1,r0,lsr r3
        and r1,r1,#0xf
        ldrb r1,[ip, r1]
        strb r1,[r2],#1
        subs r3,r3,#NBPW; bge L620
        ret
hex:
        .ascii "0123456789abcdef"
        .balign 4
#endif  /*}*/

zfind:
        ldr r1,[r0],#NBPW; cmp r1,#0; bne zfind  // cbnz r1,zfind
        ret

main:  // IN: lr= &f_exp
        str lr,[sp,#F_f_exp]
        ldr r0,[lr,#sz_pack2 - f_exp]  @ sz_pack2
        add r6, lr,#sz_pack2 - f_exp  @ &sz_pack2
        str lr,[sp,#F_f_exp]
        sub r6,r6,r0  @ elfaddr= &Elf_Ehdr of this program
        str r6,[sp,#F_elfaddr]
        mov r9,r0  @ save sz_pack2
        ldr r3,[lr,#mflg - f_exp]
        str r3,[sp,#F_mflg]

        add r0,sp,#NBPW + F_FRAME  // skip argc
        call zfind  // in: r0= &argv;  out: r0= &envp
        call zfind  // in: r0= &envp;  out: r0- &auxv

// find actual page size in Elf32_auxv
1:
        ldr r1,[r0],#NBPW; ldr r2,[r0],#NBPW
        cmp r1,#AT_PAGESZ; beq 2f
        cmp r1,#AT_NULL; bne 1b  // cbnz r1,1b
        mov r2,#PAGE_SIZE  // default
2:
        mov r1,#0; sub r1,r1,r2; str r1,[sp,#F_szpage]

        call unfold
o_binfo:
        .long O_BINFO  // .int4 offset of b_info for text
cpr0: .globl cpr0
        /* { b_info={sz_unc, sz_cpr, {4 char}}, folded_loader...} */
eof:

/* vim:set ts=8 sw=8 et: */
