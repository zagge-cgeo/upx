OUTPUT_FORMAT("elf32-i386", "elf32-i386", "elf32-i386")
OUTPUT_ARCH(i386)

SECTIONS
{
  SO_HEAD : {
    *(SO_HEAD)
    *(.text)
  }
}
