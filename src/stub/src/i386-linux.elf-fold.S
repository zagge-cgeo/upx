/*
;  i386-linux.elf-fold.S -- linkage to C code to process Elf binary
;
;  This file is part of the UPX executable compressor.
;
;  Copyright (C) 2000-2024 John F. Reiser
;  All Rights Reserved.
;
;  UPX and the UCL library are free software; you can redistribute them
;  and/or modify them under the terms of the GNU General Public License as
;  published by the Free Software Foundation; either version 2 of
;  the License, or (at your option) any later version.
;
;  This program is distributed in the hope that it will be useful,
;  but WITHOUT ANY WARRANTY; without even the implied warranty of
;  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;  GNU General Public License for more details.
;
;  You should have received a copy of the GNU General Public License
;  along with this program; see the file COPYING.
;  If not, write to the Free Software Foundation, Inc.,
;  59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
;
;  Markus F.X.J. Oberhumer              Laszlo Molnar
;  <markus@oberhumer.com>               <ezerotven+github@gmail.com>
;
;  John F. Reiser
;  <jreiser@users.sourceforge.net>
;
*/

#include "arch/i386/macros.S"
NBPW= 4

PAGE_SIZE= ( 1<<12)
PATH_MAX= 4096

ET_DYN= 3
ET_EXEC= 2
sz_Elf32_Ehdr= 0x34
  e_type=   16
  e_entry=  (16 + 2*2 + 4)
  e_phnum=  44
sz_Elf32_Phdr= 8*NBPW
  p_memsz=  5*NBPW

#define szb_info 12
#define szl_info 12
#define szp_info 12
#define a_type 0
#define a_val NBPW

is_ptinterp=     (1<<0)
unmap_all_pages= (1<<1)

__NR_readlink= 85
__NR_munmap=   91
__NR_open= 5
__NR_close= 6
__NR_mmap= 0xc0
__NR_mprotect= 0x7d
__NR_brk= 45

MAP_PRIVATE=   0x02
MAP_FIXED=     0x10

PROT_READ=     0x1

O_RDONLY=       0

// control just falls through, after this part and compiled C code
// are uncompressed.

// enter:
// eax:ADRX; ebx:free; ecx:LENX
// ebp:f_exp; esi:&b_info; edi:elfaddr
// esp/ ADRU,LENU,%fd,%entry,argc,argv,0,envp,0,auxv,0,strings
//      (ADRU,LENU) = params for final munmap()
//      (ADRX,LENX) = extent of compressed program (after moving)

fold_begin:
////    int3  // DEBUG
        push edi  // elfaddr
        push ecx  // LENX
        push eax  // ADRX
        mov ebx,[-NBPW + esi]  // O_BINFO | is_ptinterp | unmap_all_pages

        mov esi,esp; testb bl,unmap_all_pages; jnz 0f; sub esp,PATH_MAX; 0:
        mov edi,esp; push 8; pop ecx; rep movsd  // copy ADRX,LENX,elfaddr,ADRU,LENU,%fd,entry,argc

        push ebp  // f_exp
        mov ebp,esp  // frame: f_exp,ADRX,LENX,elfaddr,ADRU,LENU,%fd,entry,argc
0:
        lodsd; test %eax,%eax; stosd; jne 0b  // argv
        push edi  // P_05           &new_env[0]; f_exp,ADRX,LENX,elfaddr,ADRU,LENU,%fd,entry,argc
        testb bl,unmap_all_pages; jnz 0f; stosd; 0:  // space for new_env[0]
0:
        lodsd; test %eax,%eax; stosd; jne 0b  // env
        push edi  // P_06 &old_auxv,&new_env[0]; f_exp,ADRX,LENX,elfaddr,ADRU,LENU,%fd,entry,argc
0:
        lodsd; test %eax,%eax; stosd; movsd; jne 0b  // auxv
        testb bl,unmap_all_pages; jz env_pse
        pop %edi  // P_06 &old_auxv
        pop ecx  // toss P_05
        jmp no_env_pse
env_pse:
        inc eax  // 1, AT_IGNORE
        sub edi,2*NBPW  // back to {AT_NULL}
        push 5*2; pop ecx; rep stosd  // 5 extra slots of AT_IGNORE
        dec eax; stosd; stosd  // 0, AT_NULL
        sub [-2*NBPW + ebp],edi  // -len_aux
        push edi  // P_07          &new_aux[N],-len_aux,&new_env[0]; f_exp,ADRX,LENX,elfaddr,ADRU,LENU,%fd,entry,argc
        push esi  // P_08 &strings,&new_aux[N],-len_aux,&new_env[0]; f_exp,ADRX,LENX,elfaddr,ADRU,LENU,%fd,entry,argc

        call 1f
0:
        .asciz "/proc/self/exe"
1:
        pop ebx; push ebx  // path; copy of path
        mov ecx,O_RDONLY
        push __NR_open; pop eax; int 0x80; mov [6*NBPW + ebp],eax  // fd
        pop ebx  // copy of path
        mov edx,-5*2*NBPW -1+ PATH_MAX  // buflen
        mov ecx,edi  // buffer
        push __NR_readlink; pop eax; int 0x80; test eax,eax; jns 0f
        mov ecx,ebx  // point at name
        mov eax,-1+ (1b - 0b)  // len
0:
        lea esi,[-1+ ecx + eax]  // src last byte
        xchg ecx,eax  // ecx= byte count

   std
        pop edi; dec edi  // abuts old strings; &new_aux[N],-len_aux,&new_env[0]; f_exp,ADRX,LENX,elfaddr,ADRU,LENU,fd,entry,argc
        mov al,0; stosb  // terminate
        rep movsb  // slide up
        mov eax, 0+ ('='<<24)|(' '<<16)|(' '<<8)|(' '<<0)  # env var name
        sub edi,3; mov [edi],eax
        mov eax,[-1*NBPW + ebp]; mov [eax],edi  // new_env[0]
        and edi,-NBPW  // word align

        pop esi  // P_07  &new_aux[N]; -len_aux,&new_env[0]; f_exp,ADRX,LENX,elfaddr,ADRU,LENU,fd,entry,argc
// Final sp must be 0 mod 8.  There are now 10 words below argc.
        mov ecx,esi  // last
        sub ecx,esp  // length of moved block
        mov eax,ecx
        xor eax,edi  // check parity of purported destination
        and eax,4
        sub edi,eax  // align &new_aux[last]

        pop edx  // -len_aux; &new_env[0]; f_exp,ADRX,LENX,elfaddr,ADRU,LENU,fd,entry,argc
          add edx,edi  // edx= &final_aux[0]

        scasd  // edi -= 4
        lodsd  // esi -= 4
        shr ecx,2; dec ecx; rep movsd  // dec: compensate for P_07
   cld
// Clear the vacated stack, for buggy programs that assume it is 0
        lea ecx,[1*NBPW+ edi]  // correct for 'std'
        xor eax,eax  // 0
        sub ecx,esp
        mov edi,esp
        shr ecx,2; rep stosd
        mov esp,edi
          mov edi,edx  // &final_aux[0]

        pop eax  // toss &new_env[0]
no_env_pse:
        pop ebp  // f_exp
// stack is back to original state: ADRX,LENX,elfaddr,ADRU,LENU,fd,entry,argc

        pop eax  // ADRX: &b_info
        pop esi  // LENX: total_size
        pop ecx  // elfaddr
#define OVERHEAD 2048
#include "MAX_ELF_HDR.S"
        sub esp, MAX_ELF_HDR_32 + OVERHEAD  // alloca
        mov edx, esp  // &tmp
        push ecx  // elfaddr (9th arg)
        mov ebx, [       eax]  // length of uncompressed ELF headers
        mov ecx, [NBPW + eax]  // length of   compressed ELF headers
        add ecx, szb_info
               //   edi,    esi,      ebp,       esp,     ebx,  edx,      ecx,        eax
        pusha  // (auxv, sz_cpr, f_expand, &tmp_ehdr, {sz_unc, &tmp}, {sz_cpr, &b1st_info} )
        inc edi  // swap with above 'pusha' to inhibit auxv_up for PT_INTERP
.extern upx_main
        call upx_main  // returns entry address
        dec edi
        mov esi,eax  // entry
        mov ebp,[8*NBPW+ esp]  // elfaddr

// Discard C_TEXT (includes [ADRC,+LENC) )
        mov ecx,[ebp+ p_memsz+sz_Elf32_Phdr+sz_Elf32_Ehdr]  // Phdr[C_TEXT= 1].p_memsz
        mov ebx,ebp  // hi &Elf32_Ehdr
        cmpw [e_type + ebp],ET_EXEC; jne 1f
          push __NR_brk; pop %eax; int 0x80  // static __end_bss
1:
        push __NR_munmap; pop %eax; int 0x80  // discard C_TEXT compressed data

// Buggy programs may depend on uninit stack being 0, so clear what we used.
        mov edx,edi  // save auxv
        mov edi,esp
        mov ecx,((8 +1)*NBPW + MAX_ELF_HDR_32 + OVERHEAD) >>2  // 8 params, elfaddr, un-alloca
        xor eax,eax  // 0
        rep stosd  // clear frame on exit
        mov esp,edi  // end of frame

        pop eax  // ADRU
        pop ecx  // LENU
        pop edi  // fd
        pop ebx  // %entry
        push esi  // entry
        push ecx  // LENU
        push eax  // ADRU
        push edx  // auxv
        push edi  // fd, auxv, ADRU, LENU, entry, argc

// Map one page of /proc/self/exe so that symlink does not disappear
        pop ebx  // toss fd in case no_pse_map
        test edi,edi; js no_pse_map
        push ebx  // restore fd
        sub ebp,ebp  // 0 block in file
        // edi has fd
        push MAP_PRIVATE; pop esi
        push PROT_READ; pop edx
        mov ecx,PAGE_SIZE
        sub ebx,ebx  // 0 ==> Linux chooses page frame
        push __NR_mmap; pop eax; int 0x80

        pop ebx  // fd;  auxv, LENU, ADRU, entry, argc
        push __NR_close; pop eax; int 0x80
no_pse_map:
        pop edi  // auxv table
        sub eax,eax  // 0, also AT_NULL
        .byte 0x3c  // "cmpb al, byte ..." like "jmp 1+L60" but 1 byte shorter
L60:
        scasd  // a_un.a_val etc.
        scasd  // a_type
        jne L60  // not AT_NULL
// edi now points at [AT_NULL]a_un.a_ptr which contains result of make_hatch()

        pop ebx  // ADRU  parameters for final munmap
        pop ecx  // LENU

        push eax
        push eax
        push eax
        push eax
        push eax
        push eax
        push eax
        push eax  // 32 bytes of zeroes now on stack, ready for 'popa'

        mov al, __NR_munmap  // eax was 0 from L60
        jmp [edi]  // unmap ourselves via escape hatch, then goto entry

// Sometimes linux enforces page-aligned address
Pprotect: .globl Pprotect
    xchg ebx,[1*NBPW + esp]  // save reg, %ebx= address
    mov ecx,ebx  // copy address
    and ebx, ~0<<12  // page align
    sub ecx,%ebx  // extra length
    add ecx,[2*NBPW + esp]  // length
    mov edx,[3*NBPW + esp]  // bits
    push __NR_mprotect; pop %eax; int 0x80
    cmp eax, -0x1000; jna 0f; hlt; 0:
    mov ebx,[1*NBPW + esp]  // restore reg
    ret

mmap: .globl mmap  // what happened to the ebx->args_on_stack method?
        push ebp
        push ebx
        push esi
        push edi
        mov ebx,[ 5*NBPW + esp]
        mov ecx,[ 6*NBPW + esp]
        mov edx,[ 7*NBPW + esp]
        mov esi,[ 8*NBPW+ esp]
        mov edi,[ 9*NBPW + esp]
        mov ebp,[10*NBPW + esp]
        shr ebp,12
        push __NR_mmap; pop eax; int 0x80

        pop edi
        pop esi
        pop ebx
        pop ebp
        ret

.balign 4,0

/* vim:set ts=8 sw=8 et: */
