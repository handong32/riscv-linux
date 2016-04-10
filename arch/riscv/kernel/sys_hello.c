#include <linux/syscalls.h>
#include <asm/unistd.h>

SYSCALL_DEFINE0(syshello)
{
    printk("SYSCALL HELLO\n");
    printk("pid = %d\n", current->pid);
    printk("xdasid = %d\n", current->xdasid);
}
