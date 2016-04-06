#include <linux/moduleloader.h>
#include <linux/elf.h>

int apply_relocate_add(Elf64_Shdr *sechdrs,
		       const char *strtab,
		       unsigned int symindex,
		       unsigned int relsec,
		       struct module *me)
{
    printk("han - in apply_relocate_add, not implemented!!\n");

    /*uint64_t i;
    Elf64_Rela *rel = (void *)sechdrs[relsec].sh_addr;
    Elf64_Sym *sym;
    u64 *loc;
    u64 val;

    printk("Applying relocate section %u to %u\n", relsec,
	     sechdrs[relsec].sh_info);

    for (i = 0; i < sechdrs[relsec].sh_size / sizeof(*rel); i++) {
	loc = (void *)sechdrs[sechdrs[relsec].sh_info].sh_addr
	    + rel[i].r_offset;

	sym = (Elf64_Sym *)sechdrs[symindex].sh_addr
	    + ELF64_R_SYM(rel[i].r_info);

	printk("type %d st_value %Lx r_addend %Lx loc %Lx\n",
	       (int)ELF64_R_TYPE(rel[i].r_info),
	       sym->st_value, rel[i].r_addend, (u64)loc);

	val = sym->st_value + rel[i].r_addend;

	switch((int)ELF64_R_TYPE(rel[i].r_info))
	{
	case R_RISCV_HI20:
	    *loc = ((val+0x800) & ~0xfff) & (*loc & 0xfff);
	    printk("switch: loc = 0x%x\n", loc);
	    break;
	case R_RISCV_LO12_I:
	    *loc = ((val & 0xfff) << 20) | (*loc & 0xfffff);
	    printk("switch: loc = 0x%x\n", loc);
	    break;
	case R_RISCV_CALL:
	    loc[0] = ((val+0x800) & ~0xfff) | (loc[0] & 0xfff);
	    loc[1] = (val << 20) | (loc[1] & 0x000fffff);
	    printk("switch: loc = 0x%x\n", loc);
	    break;
	case R_RISCV_64:
	    *loc = val;
	    printk("switch: loc = 0x%x\n", loc);
	    break;
	default:
	    printk("module %s: Unknown relocation: %u\n",
		   me->name, ELF64_R_TYPE(rel[i].r_info));
	    break;
	}
	printk("\n");
    }
    */
    
    return 0;
}
