#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/signal.h>
#include <linux/kdebug.h>
#include <linux/uaccess.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/slab.h>

#include <asm/processor.h>
#include <asm/ptrace.h>
#include <asm/csr.h>

int show_unhandled_signals = 1;

extern asmlinkage void handle_exception(void);

static DEFINE_SPINLOCK(die_lock);

void die(struct pt_regs *regs, const char *str)
{
    printk("die in traps.c %s \n", str);
	static int die_counter;
	int ret;

	oops_enter();

	spin_lock_irq(&die_lock);
	console_verbose();
	bust_spinlocks(1);

	pr_emerg("%s [#%d]\n", str, ++die_counter);
	print_modules();
	show_regs(regs);

	ret = notify_die(DIE_OOPS, str, regs, 0, regs->scause, SIGSEGV);

	bust_spinlocks(0);
	add_taint(TAINT_DIE, LOCKDEP_NOW_UNRELIABLE);
	spin_unlock_irq(&die_lock);
	oops_exit();

	if (in_interrupt())
		panic("Fatal exception in interrupt");
	if (panic_on_oops)
		panic("Fatal exception");
	if (ret != NOTIFY_STOP)
		do_exit(SIGSEGV);
}

/* void construct_queue(queue ** new_queue, int size) { */
/*     (*new_queue)->data = (uint64_t *) kmalloc(size * sizeof(uint64_t), GFP_KERNEL); */
/*     (*new_queue)->size = size; */
/*     (*new_queue)->head = (*new_queue)->data; */
/*     (*new_queue)->tail = (*new_queue)->data; */
/* } */

/* void destroy_queue(queue ** old_queue) { */
/*     kfree((*old_queue)->data); */
/*     kfree(*old_queue); */
/* } */

/* void asid_nnid_table_create(asid_nnid_table ** new_table, size_t table_size, */
/*                             size_t configs_per_entry) { */
/*   int i; */

/*   // Allocate space for the table */
/*   *new_table = (asid_nnid_table *) kmalloc(sizeof(asid_nnid_table), GFP_KERNEL); */
/*   (*new_table)->entry = */
/*       (asid_nnid_table_entry *) kmalloc(sizeof(asid_nnid_table_entry) * table_size, GFP_KERNEL); */
/*   (*new_table)->size = table_size; */

/*   for (i = 0; i < table_size; i++) { */
/*     // Create the configuration region */
/*     (*new_table)->entry[i].asid_nnid = */
/* 	(nn_configuration *) kmalloc(configs_per_entry * sizeof(nn_configuration), GFP_KERNEL); */
/*     (*new_table)->entry[i].asid_nnid->config = NULL; */
/*     (*new_table)->entry[i].num_configs = configs_per_entry; */
/*     (*new_table)->entry[i].num_valid = 0; */

/*     // Create the io region */
/*     (*new_table)->entry[i].transaction_io = (io *) kmalloc(sizeof(io), GFP_KERNEL); */
/*     (*new_table)->entry[i].transaction_io->header = 0; */
/*     (*new_table)->entry[i].transaction_io->input = (queue *) kmalloc(sizeof(queue), GFP_KERNEL); */
/*     (*new_table)->entry[i].transaction_io->output = (queue *) kmalloc(sizeof(queue), GFP_KERNEL); */
/*     construct_queue(&(*new_table)->entry[i].transaction_io->input, 16); */
/*     construct_queue(&(*new_table)->entry[i].transaction_io->output, 16); */
/*   } */

/* } */

/* void asid_nnid_table_info(asid_nnid_table * table) { */
/*   int i, j; */
/*   printk("[INFO] 0x%lx <- Table Head\n", (uint64_t) table); */
/*   printk("[INFO]   |-> 0x%lx: size:                     0x%lx\n", */
/*          (uint64_t) &table->size, */
/*          (uint64_t) table->size); */
/*   printk("[INFO]       0x%lx: * entry:                  0x%lx\n", */
/*          (uint64_t) &table->entry, */
/*          (uint64_t) table->entry); */
/*   for (i = 0; i < table->size; i++) { */
/*     printk("[INFO]         |-> [%0d] 0x%lx: num_configs:    0x%lx\n", i, */
/*            (uint64_t) &table->entry[i].num_configs, */
/*            (uint64_t) table->entry[i].num_configs); */
/*     printk("[INFO]         |       0x%lx: num_valid:      0x%lx\n", */
/*            (uint64_t) &table->entry[i].num_valid, */
/*            (uint64_t) table->entry[i].num_valid); */
/*     printk("[INFO]         |       0x%lx: asid_nnid:      0x%lx\n", */
/*            (uint64_t) &table->entry[i].asid_nnid, */
/*            (uint64_t) table->entry[i].asid_nnid); */
/*     // Dump the `nn_configuration` */
/*     for (j = 0; j < table->entry[i].num_valid; j++) { */
/*       printk("[INFO]         |         |-> [%0d] 0x%lx: size:             0x%lx\n", j, */
/*              (uint64_t) &table->entry[i].asid_nnid[j].size, */
/*              (uint64_t) table->entry[i].asid_nnid[j].size); */
/*       printk("[INFO]         |         |       0x%lx: elements_per_block: 0d%ld\n", */
/*              (uint64_t) &table->entry[i].asid_nnid[j].elements_per_block, */
/*              (uint64_t) table->entry[i].asid_nnid[j].elements_per_block); */
/*       printk("[INFO]         |         |       0x%lx: * config:           0x%lx\n", */
/*              (uint64_t) &table->entry[i].asid_nnid[j].config, */
/*              (uint64_t) table->entry[i].asid_nnid[j].config); */
/*     } */
/*     // Back to `asid_nnid_table_entry` */
/*     printk("[INFO]         |       0x%lx: transaction_io: 0x%lx\n", */
/*            (uint64_t) &table->entry[i].transaction_io, */
/*            (uint64_t) table->entry[i].transaction_io); */
/*     // Dump the `io` */
/*     printk("[INFO]         |         |-> 0x%lx: header:   0x%lx\n", */
/*            (uint64_t) &table->entry[i].transaction_io->header, */
/*            (uint64_t) table->entry[i].transaction_io->header); */
/*     printk("[INFO]         |         |   0x%lx: * input:  0x%lx\n", */
/*            (uint64_t) &table->entry[i].transaction_io->input, */
/*            (uint64_t) table->entry[i].transaction_io->input); */
/*     printk("[INFO]         |         |   0x%lx: * output: 0x%lx\n", */
/*            (uint64_t) &table->entry[i].transaction_io->output, */
/*            (uint64_t) table->entry[i].transaction_io->output); */
/*   } */
/* } */


static inline void do_trap_siginfo(int signo, int code,
	unsigned long addr, struct task_struct *tsk)
{
	siginfo_t info;

	info.si_signo = signo;
	info.si_errno = 0;
	info.si_code = code;
	info.si_addr = (void __user *)addr;
	force_sig_info(signo, &info, tsk);
}

void do_trap(struct pt_regs *regs, int signo, int code,
	unsigned long addr, struct task_struct *tsk)
{
	if (show_unhandled_signals && unhandled_signal(tsk, signo)
	    && printk_ratelimit()) {
		pr_info("%s[%d]: unhandled signal %d code 0x%x at 0x" REG_FMT,
			tsk->comm, task_pid_nr(tsk), signo, code, addr);
		print_vma_addr(KERN_CONT " in ", GET_IP(regs));
		pr_cont("\n");
		show_regs(regs);
	}

	do_trap_siginfo(signo, code, addr, tsk);
}

static void do_trap_error(struct pt_regs *regs, int signo, int code,
	unsigned long addr, const char *str)
{
	if (user_mode(regs)) {
		do_trap(regs, signo, code, addr, current);
	} else {
		if (!fixup_exception(regs))
			die(regs, str);
	}
}

#define DO_ERROR_INFO(name, signo, code, str)				\
asmlinkage void name(struct pt_regs *regs)				\
{									\
	do_trap_error(regs, signo, code, regs->sepc, "Oops - " str);	\
}

DO_ERROR_INFO(do_trap_unknown,
	SIGILL, ILL_ILLTRP, "unknown exception");
DO_ERROR_INFO(do_trap_insn_misaligned,
	SIGBUS, BUS_ADRALN, "instruction address misaligned");
DO_ERROR_INFO(do_trap_insn_illegal,
	SIGILL, ILL_ILLOPC, "illegal instruction");

asmlinkage void do_trap_break(struct pt_regs *regs)
{
    printk("do_trap_break\n");
#ifdef CONFIG_GENERIC_BUG
	if (!user_mode(regs)) {
		enum bug_trap_type type;

		type = report_bug(regs->sepc, regs);
		switch (type) {
		case BUG_TRAP_TYPE_NONE:
			break;
		case BUG_TRAP_TYPE_WARN:
			regs->sepc += sizeof(bug_insn_t);
			return;
		case BUG_TRAP_TYPE_BUG:
			die(regs, "Kernel BUG");
		}
	}
#endif /* CONFIG_GENERIC_BUG */

	do_trap_siginfo(SIGTRAP, TRAP_BRKPT, regs->sepc, current);
	regs->sepc += 0x4;
}

#ifdef CONFIG_GENERIC_BUG
int is_valid_bugaddr(unsigned long pc)
{
	bug_insn_t insn;

	if (pc < PAGE_OFFSET)
		return 0;
	if (probe_kernel_address((bug_insn_t __user *)pc, insn))
		return 0;
	return (insn == __BUG_INSN);
}
#endif /* CONFIG_GENERIC_BUG */

void __init trap_init(void)
{
	/* Clear the IPI exception that started the processor */
	csr_clear(sip, SIE_SSIE);
	/* Enable software interrupts */
	csr_set(sie, SIE_SSIE);
	/* Set sup0 scratch register to 0, indicating to exception vector
	   that we are presently executing in the kernel */
	csr_write(sscratch, 0);
	/* Set the exception vector address */
	csr_write(stvec, &handle_exception);
}
