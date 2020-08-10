#ifndef _ASM_EFI_H
#define _ASM_EFI_H

#include <asm/io.h>

#ifdef CONFIG_EFI
extern void efi_init(void);
extern void efi_idmap_init(void);
extern unsigned long arm64_efi_facility;
#else
#define efi_init()
#define efi_idmap_init()
#endif

#endif /* _ASM_EFI_H */
