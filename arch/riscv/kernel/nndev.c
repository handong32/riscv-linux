#include <linux/init.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <asm/io.h>

#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/types.h>

#include <asm/processor.h>
#include <asm/ptrace.h>
#include <asm/csr.h>
#include <asm/io.h>
#include <asm/pgalloc.h>

#define  DEVICE_NAME "nndev"
#define  CLASS_NAME  "nn"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("BU");
MODULE_DESCRIPTION("nndev");
MODULE_VERSION("1");

typedef int16_t asid_type;
typedef int32_t nnid_type;
typedef int16_t tid_type;
typedef int32_t element_type;
typedef uint64_t xlen_t;

typedef enum {
  xfiles_reg_batch_items = 0,
  xfiles_reg_learning_rate,
  xfiles_reg_weight_decay_lambda
} xfiles_reg;

typedef enum {
  t_USR_READ_DATA = 4,
  t_USR_WRITE_DATA = 5,
  t_USR_NEW_REQUEST = 6,
  t_USR_WRITE_DATA_LAST = 7,
  t_USR_WRITE_REGISTER = 8,
  t_USR_XFILES_DEBUG = 9,
  t_USR_XFILES_DANA_ID = 10
} request_t;

typedef enum {
  t_SUP_UPDATE_ASID = 0,
  t_SUP_WRITE_REG = 1,
  t_SUP_READ_CSR = 2
} request_super_t;

typedef enum {
  FEEDFORWARD = 0,
  TRAIN_INCREMENTAL = 1,
  TRAIN_BATCH = 2
} learning_type_t;

typedef enum {
  err_XFILES_UNKNOWN = 0,
  err_XFILES_NOASID,
  err_XFILES_TTABLEFULL,
  err_XFILES_INVALIDTID
} xfiles_err_t;

typedef enum {
  resp_OK = 0,
  resp_TID,
  resp_READ,
  resp_NOT_DONE,
  resp_QUEUE_ERR,
  resp_XFILES
} xfiles_resp_t;

typedef enum {
  err_UNKNOWN     = 0,
  err_DANA_NOANTP = 1,
  err_INVASID     = 2,
  err_INVNNID     = 3,
  err_ZEROSIZE    = 4,
  err_INVEPB      = 5
} dana_err_t;

// Enumerated type that defines the action taken by the Debug Unit
typedef enum {
  a_REG,          // Return a value written using the cmd interface
  a_MEM_READ,     // Read data from the L1 cache and return it
  a_MEM_WRITE,    // Write data to the L1 cache
  a_VIRT_TO_PHYS, // Do address translation via the PTW port
  a_UTL_READ,     // Read data from the L2 cache and return it
  a_UTL_WRITE     // Write data to the L2 cache
} xfiles_debug_action_t;

typedef enum {
  csr_CAUSE = 0
} xfiles_csr_t;

typedef struct {                 // |------------|     <---- queue size ----->
  uint64_t * data;               // | * data     |---> [ | |0|1|2|3|4| | ... ]
  size_t size;                   // | queue size |          ^       ^
  uint64_t * head;               // | * head     |----------|       |
  uint64_t * tail;               // | * tail     |------------------|
} queue;                         // |------------| <-----| <--|
                                 //                      |    |
typedef struct {                 // |----------------|   |    |
  uint64_t header;               // | status bits    |   |    |
  queue * input;                 // | * input queue  |---|    |
  queue * output;                // | * output queue |--------|
} io;                            // |----------------| <-----------------|
                                 //                                      |
typedef struct {                 // |--------------------|               |
  size_t size;                   // | size of config     |               |
  size_t elements_per_block;     // | elements per block |               |
  xlen_t * config;                // | * config           |-> [NN Config] |
} nn_configuration;              // |--------------------| <---|         |
                                 //                            |         |
typedef struct {                 // |-------------------|      |         |
  int num_configs;               // | num configs       |      |         |
  int num_valid;                 // | num valid configs |      |         |
  nn_configuration * asid_nnid;  // | * ASID--NNID      |------|         |
  io * transaction_io;           // | * IO              |----------------|
} asid_nnid_table_entry;         // |-------------------| <-| <--[Hardware ANTP]
                                 //                         |
typedef struct {                 // |-----------|           |
  size_t size;                   // | num ASIDs |           |
  asid_nnid_table_entry * entry; // | * entry   |-----------|
} asid_nnid_table;               // |-----------| <--------------------[OS ANTP]

static asid_nnid_table * asid_nnid_ktable = NULL;

static int    majorNumber;                  ///< Stores the device number -- determined automatically
static char   message[256] = {0};           ///< Memory for the string that is passed from userspace
static short  size_of_message;              ///< Used to remember the size of the string stored
static int    numberOpens = 0;              ///< Counts the number of times the device is opened
static struct class*  nnClass  = NULL; ///< The device-driver class struct pointer
static struct device* nnDevice = NULL; ///< The device-driver device struct pointer


static asid_type asid;
static nnid_type nnid;
static int file_bytes;
static int file_size;
static uint64_t connections_per_epoch;
static xlen_t * vconfig;
/*static phys_addr_t nqd;
static phys_addr_t pnew_table;
static phys_addr_t pentry;
static phys_addr_t pasid_nnid;
static phys_addr_t ptransaction_io; 
static phys_addr_t pinput;
static phys_addr_t poutput;
static int    ioNum = 100;*/

#define MAJOR_NUM 101
#define IOCTL_SET_FILESIZE _IOR(MAJOR_NUM, 0, xlen_t *)
#define IOCTL_SET_NN _IOR(MAJOR_NUM, 1, xlen_t *)
#define IOCTL_SHOW_ANT _IO(MAJOR_NUM, 2)
#define IOCTL_PHYS_ADDR _IO(MAJOR_NUM, 3)
#define IOCTL_TRANS_PHYS_ADDR _IOR(MAJOR_NUM, 4, xlen_t*)

#define RESP_CODE_WIDTH 3

// Macros for using XCustom instructions. Four different macros are
// provided depending on whether or not the passed arguments should be
// communicated as registers or immediates.
#define XCUSTOM "custom0"

// Standard macro that passes rd_, rs1_, and rs2_ via registers
#define XFILES_INSTRUCTION(rd_, rs1_, rs2_, funct_)     \
  XFILES_INSTRUCTION_R_R_R(rd_, rs1_, rs2_, funct_)
#define XFILES_INSTRUCTION_R_R_R(rd_, rs1_, rs2_, funct_)               \
  asm volatile (XCUSTOM" %[rd], %[rs1], %[rs2], %[funct]"               \
                : [rd] "=r" (rd_)                                       \
                : [rs1] "r" (rs1_), [rs2] "r" (rs2_), [funct] "i" (funct_))

// Macro to pass rs2_ as an immediate
#define XFILES_INSTRUCTION_R_R_I(rd_, rs1_, rs2_, funct_)               \
  asm volatile (XCUSTOM" %[rd], %[rs1], %[rs2], %[funct]"               \
                : [rd] "=r" (rd_)                                       \
                : [rs1] "r" (rs1_), [rs2] "i" (rs2_), [funct] "i" (funct_))

    // Macro to pass rs1_ and rs2_ as immediates
#define XFILES_INSTRUCTION_R_I_I(rd_, rs1_, rs2_, funct_)               \
  asm volatile (XCUSTOM" %[rd], %[rs1], %[rs2], %[funct]"               \
                : [rd] "=r" (rd_)                                       \
                : [rs1] "i" (rs1_), [rs2] "i" (rs2_), [funct] "i" (funct_))

xlen_t debug_test(xfiles_debug_action_t action, uint32_t data, void * addr) {
  xlen_t out, action_and_data = ((uint64_t)action << 32) | (uint32_t)data;
  XFILES_INSTRUCTION(out, action_and_data, addr, t_USR_XFILES_DEBUG);
  return out;
}

xlen_t debug_echo_via_reg(uint32_t data) {
  return debug_test(a_REG, data, 0);
}

xlen_t debug_read_mem(void * addr) {
  return debug_test(a_MEM_READ, 0, addr);
}

xlen_t debug_write_mem(uint32_t data, void * addr) {
  return debug_test(a_MEM_WRITE, data, addr);
}

xlen_t debug_virt_to_phys(void * addr_v) {
  return debug_test(a_VIRT_TO_PHYS, 0, addr_v);
}

xlen_t debug_read_utl(void * addr) {
  return debug_test(a_UTL_READ, 0, addr);
}

xlen_t debug_write_utl(uint32_t data, void * addr) {
  return debug_test(a_UTL_WRITE, data, addr);
}

xlen_t set_asid(asid_type asid) {
  int old_asid;
  XFILES_INSTRUCTION_R_R_I(old_asid, asid, 0, t_SUP_UPDATE_ASID);
  return old_asid;
}

xlen_t set_antp(asid_nnid_table_entry * antp, size_t size) {
  int old_antp;
  XFILES_INSTRUCTION(old_antp, antp, size, t_SUP_WRITE_REG);
  return old_antp;
}

xlen_t xf_read_csr(xfiles_csr_t csr) {
  xlen_t csr_value;
  XFILES_INSTRUCTION_R_R_I(csr_value, csr, 0, t_SUP_READ_CSR);
  return csr_value;
}


void
dumpNNBytes(xlen_t *addr, xlen_t size)
{
    xlen_t i;
    printk("dumpNNBytes in kernel:\n");
    printk("NN: 0x%llx size: %llu\n", (xlen_t)addr, size);
    for (i=0; i<size; i++) {
	if (i%8 == 0) printk("\n%03llu: ", i);
	printk("%016llx ", addr[i]);
    }
    printk("\n\n");
}

uint64_t binary_config_num_connections(void) {
  int i;

  uint64_t connections = 0;
  uint16_t total_layers, layer_offset, ptr;
  uint32_t tmp;
  uint16_t layer_0, layer_1;
  
  //fseek(fp, 6, SEEK_SET);
  //fread(&total_layers, sizeof(uint16_t), 1, fp);
  copy_from_user(&total_layers, (void*)vconfig+6, sizeof(uint16_t));
  
  //fread(&layer_offset, sizeof(uint16_t), 1, fp);
  copy_from_user(&layer_offset, (void*)vconfig+6+sizeof(uint16_t), sizeof(uint16_t));

  //fseek(fp, layer_offset, SEEK_SET);
  //fread(&ptr, sizeof(uint16_t), 1, fp);
  copy_from_user(&ptr, (void*)vconfig+layer_offset, sizeof(uint16_t));
  ptr &= ~((~0)<<12);
  
  //fseek(fp, ptr + 2, SEEK_SET);
  //fread(&layer_0, sizeof(uint16_t), 1, fp);
  copy_from_user(&layer_0, (void*)vconfig+ptr+2, sizeof(uint16_t));
  layer_0 &= ~((~0)<<8);

  //fseek(fp, layer_offset, SEEK_SET);
  //fread(&tmp, sizeof(uint32_t), 1, fp);
  copy_from_user(&tmp, (void*)vconfig+layer_offset, sizeof(uint32_t));
  layer_1 = (tmp & (~((~0)<<10))<<12)>>12;

  connections += (layer_0 + 1) * layer_1;

  for (i = 1; i < total_layers; i++) {
    layer_0 = layer_1;
    
    //fseek(fp, layer_offset + 4 * i, SEEK_SET);
    //fread(&tmp, sizeof(uint32_t), 1, fp);
    copy_from_user(&tmp, (void*)vconfig+layer_offset + 4 * i, sizeof(uint32_t));

    layer_1 = (tmp & (~((~0)<<10))<<12)>>12;
    connections += (layer_0 + 1) * layer_1;
  }

  return connections;
}


void construct_queue(queue ** new_queue, int size) {
    (*new_queue)->data = (uint64_t *) kmalloc(size * sizeof(uint64_t), GFP_KERNEL);
    (*new_queue)->size = size;
    (*new_queue)->head = (*new_queue)->data;
    (*new_queue)->tail = (*new_queue)->data;

    //
    //(*new_queue)->data = (uint64_t *) nqd;
}

void destroy_queue(queue ** old_queue) {
    kfree((*old_queue)->data);
    kfree(*old_queue);
}

void asid_nnid_table_create(asid_nnid_table ** new_table, size_t table_size,
                            size_t configs_per_entry) {
  int i;

  // Allocate space for the table
  *new_table = (asid_nnid_table *) kmalloc(sizeof(asid_nnid_table), GFP_KERNEL);
  //pnew_table = virt_to_phys((void*) (*new_table));

  (*new_table)->entry =
      (asid_nnid_table_entry *) kmalloc(sizeof(asid_nnid_table_entry) * table_size, GFP_KERNEL);
  //pentry = virt_to_phys((void*) ((*new_table)->entry));

  (*new_table)->size = table_size;

  for (i = 0; i < table_size; i++) {
    // Create the configuration region
    (*new_table)->entry[i].asid_nnid =
	(nn_configuration *) kmalloc(configs_per_entry * sizeof(nn_configuration), GFP_KERNEL);
    //pasid_nnid = virt_to_phys((void*) ((*new_table)->entry[i].asid_nnid));
    
    (*new_table)->entry[i].asid_nnid->config = NULL;
    (*new_table)->entry[i].num_configs = configs_per_entry;
    (*new_table)->entry[i].num_valid = 0;


#if 0
    /* THE FOLLOWING IS FOR MEMORY BASED I/O -- NOT CURRENT SUPPORTED BY HW YET */
    // Create the io region
    (*new_table)->entry[i].transaction_io = (io *) kmalloc(sizeof(io), GFP_KERNEL);
    //ptransaction_io = virt_to_phys((void*) ((*new_table)->entry[i].transaction_io));
    
    (*new_table)->entry[i].transaction_io->header = 0;
    (*new_table)->entry[i].transaction_io->input = (queue *) kmalloc(sizeof(queue), GFP_KERNEL);
    //pinput = virt_to_phys((void*) ((*new_table)->entry[i].transaction_io->input));
    
    (*new_table)->entry[i].transaction_io->output = (queue *) kmalloc(sizeof(queue), GFP_KERNEL);
    //poutput = virt_to_phys((void*) ((*new_table)->entry[i].transaction_io->output));

    construct_queue(&(*new_table)->entry[i].transaction_io->input, 16);
    construct_queue(&(*new_table)->entry[i].transaction_io->output, 16);
#endif
  }

}

/*void update_phys(asid_nnid_table * table)
{
    table->entry[0].transaction_io->input = (queue*) pinput;
    table->entry[0].transaction_io->output = (queue*) poutput;
    table->entry[0].transaction_io = (io *) ptransaction_io;
    table->entry[0].asid_nnid = (nn_configuration *) pasid_nnid;
    table->entry = (asid_nnid_table_entry *) pentry;
    //table = (asid_nnid_table *)pnew_table;
    }*/

void asid_nnid_table_info(asid_nnid_table * table) {
  int i, j;
  printk("[INFO] 0x%llx <- Table Head\n", (uint64_t) table);
  printk("[INFO]   |-> 0x%llx: size:                     0x%llx\n",
         (uint64_t) &table->size,
         (uint64_t) table->size);
  printk("[INFO]       0x%llx: * entry:                  0x%llx\n",
         (uint64_t) &table->entry,
         (uint64_t) table->entry);
  for (i = 0; i < table->size; i++) {
    printk("[INFO]         |-> [%0d] 0x%llx: num_configs:    0x%llx\n", i,
           (uint64_t) &table->entry[i].num_configs,
           (uint64_t) table->entry[i].num_configs);
    printk("[INFO]         |       0x%llx: num_valid:      0x%llx\n",
           (uint64_t) &table->entry[i].num_valid,
           (uint64_t) table->entry[i].num_valid);
    printk("[INFO]         |       0x%llx: asid_nnid:      0x%llx\n",
           (uint64_t) &table->entry[i].asid_nnid,
           (uint64_t) table->entry[i].asid_nnid);
    // Dump the `nn_configuration`
    for (j = 0; j < table->entry[i].num_valid; j++) {
      printk("[INFO]         |         |-> [%0d] 0x%llx: size:             0x%llx\n", j,
             (uint64_t) &table->entry[i].asid_nnid[j].size,
             (uint64_t) table->entry[i].asid_nnid[j].size);
      printk("[INFO]         |         |       0x%llx: elements_per_block: 0d%lld\n",
             (uint64_t) &table->entry[i].asid_nnid[j].elements_per_block,
             (uint64_t) table->entry[i].asid_nnid[j].elements_per_block);
      printk("[INFO]         |         |       0x%llx: * config:           0x%llx\n",
             (uint64_t) &table->entry[i].asid_nnid[j].config,
             (uint64_t) table->entry[i].asid_nnid[j].config);
    }
    // Back to `asid_nnid_table_entry`
    printk("[INFO]         |       0x%llx: transaction_io: 0x%llx\n",
           (uint64_t) &table->entry[i].transaction_io,
           (uint64_t) table->entry[i].transaction_io);
    // Dump the `io`
    printk("[INFO]         |         |-> 0x%llx: header:   0x%llx\n",
           (uint64_t) &table->entry[i].transaction_io->header,
           (uint64_t) table->entry[i].transaction_io->header);
    printk("[INFO]         |         |   0x%llx: * input:  0x%llx\n",
           (uint64_t) &table->entry[i].transaction_io->input,
           (uint64_t) table->entry[i].transaction_io->input);
    printk("[INFO]         |         |   0x%llx: * output: 0x%llx\n",
           (uint64_t) &table->entry[i].transaction_io->output,
           (uint64_t) table->entry[i].transaction_io->output);
  }
}

xlen_t user_virt_to_phys(xlen_t addr)
{
    xlen_t paddr, mask, offsetMask, sanity;
    struct page *page;
    struct mm_struct *mm;
    pgd_t *pgd;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    
    offsetMask = 0xfff;
    page = NULL;
    mm = current->mm;

    /* sanity check va bits 38 to 63 must be equal */
    sanity = addr >> 38;
    if(sanity != 0 && sanity != 0x3ffffff)
    {
	printk("Invalid virtual address: 0x%llx, 0x%llx\n", sanity, addr);
	return -1;
    }
    
    //mask out bits 39-63
    mask = (1UL << 39)-1;
    addr &= mask;
    offsetMask &= addr;
    //printk("\tvirt_addr = 0x%llx, offsetMask = 0x%llx\n", addr, offsetMask);
    
    pgd = pgd_offset(mm, addr);
    if (pgd_present(*pgd)) 
    {
        pud = pud_offset(pgd, addr);
	if(pud_present(*pud))
	{
	    pmd = pmd_offset(pud, addr);
	    if (pmd_present(*pmd)) 
	    {
	        pte = pte_offset_map(pmd, addr);
		if (pte_present(*pte)) 
		{
		    paddr = page_address(pte_page(*pte));
		    printk("va 0x%llx -> pa 0x%llx\n", addr, paddr);
		    printk("virt_to_phys: 0x%llx\n", virt_to_phys(paddr) | offsetMask);
		    return virt_to_phys(paddr) | offsetMask;
		}
	    }
	}
    }
}

// The prototype functions for the nn driver -- must come before the struct definition
static int     dev_open(struct inode *, struct file *);
static int     dev_release(struct inode *, struct file *);
static ssize_t dev_read(struct file *, char *, size_t, loff_t *);
static ssize_t dev_write(struct file *, const char *, size_t, loff_t *);

long device_ioctl(struct file* file,
		  unsigned int ioctl_num,
		  unsigned long ioctl_param)
{
    int res;
    xlen_t temp, oldasid, block_64, ret;
    
    switch(ioctl_num){
    case IOCTL_SET_FILESIZE:
	res = get_user(temp, (xlen_t*)ioctl_param);
	if(res != 0)
	{
	    printk("IOCTL_SET_FILESIZE error\n");
	    break;
	}
	
	nnid = asid_nnid_ktable->entry[asid].num_valid;
	file_bytes = temp;
	
	file_size = file_bytes / sizeof(xlen_t);
	file_size += (file_bytes % sizeof(xlen_t)) ? 1 : 0;
	
	asid_nnid_ktable->entry[asid].asid_nnid[nnid].size = file_size;
	printk("file size = %ld, file bytes = %d\n", asid_nnid_ktable->entry[asid].asid_nnid[nnid].size, file_bytes);
	break;
    case IOCTL_SET_NN:
	res = get_user(temp, (xlen_t*)ioctl_param);
	if(res != 0)
	{
	    printk("IOCTL_SET_NN error\n");
	    break;
	}

	vconfig = (xlen_t *)temp;
	printk("IOCTL_SET_NN: virt addr 0x%p\n", (void*) temp);
		
	
        // FIXME: !!!!! KLUDGE !!!!!
	// validate address correct user address and pinned 
	if (!access_ok(VERIFY_READ, 
		      temp, 
		      asid_nnid_ktable->entry[asid].asid_nnid[nnid].size 
		       * sizeof(xlen_t))) {
		BUG_ON(1);
	    }
	
	
	/*xlen_t * kaddr;
	kaddr = (xlen_t *) kmalloc(file_bytes, GFP_KERNEL);
	copy_from_user(kaddr, temp, file_bytes);
	void *kphys = virt_to_phys((void*) kaddr);
	printk("kernel phys: 0x%p\n", kphys);
	asid_nnid_ktable->entry[asid].asid_nnid[nnid].config = (xlen_t*)kphys;*/
	
	
	asid_nnid_ktable->entry[asid].asid_nnid[nnid].config = (xlen_t *)temp;
	
        copy_from_user(&block_64, vconfig, sizeof(block_64));
	if(res != 0)
	{
	    printk("IOCTL_SET_NN copy_from_user error\n");
	    break;
	}
	
	block_64 = (block_64 >> 4) & 3;
	asid_nnid_ktable->entry[asid].asid_nnid[nnid].elements_per_block = 1 << (block_64+2);
	asid_nnid_ktable->entry[asid].num_valid ++;
	oldasid = set_asid(asid);
	printk("set_asid: oldasid = %llu\n", oldasid);	
	connections_per_epoch = binary_config_num_connections();
	
	/*csr_clear(sstatus, SR_PUM);
	  dumpNNBytes(asid_nnid_ktable->entry[asid].asid_nnid[nnid].config, asid_nnid_ktable->entry[asid].asid_nnid[nnid].size);
	  csr_set(sstatus, SR_PUM);*/
	break;
    case IOCTL_SHOW_ANT:
	asid_nnid_table_info(asid_nnid_ktable);
	break;

    case IOCTL_PHYS_ADDR:
	//printk("0x%p\n, 0x%p\n, 0x%p\n, 0x%p\n, 0x%p\n, 0x%p\n, 0x%p\n", nqd, pnew_table, pentry, pasid_nnid, ptransaction_io, pinput, poutput);
	//update_phys(asid_nnid_ktable);
	//asid_nnid_ktable = (asid_nnid_table *) pnew_table;
	//printk("0x%p\n", asid_nnid_ktable);
	asid_nnid_table_info(asid_nnid_ktable);
	
	break;

    case IOCTL_TRANS_PHYS_ADDR:
	printk("\tIOCTL_TRANS_PHYS_ADDR for PID %d\n", current->pid);	
	res = get_user(temp, (xlen_t*)ioctl_param);
	if(res != 0) {
       	    printk("IOCTL_TRANS_PHYS_ADDR error\n");
	    break;
	}
	ret = user_virt_to_phys(temp);
        ret = debug_read_utl((void*)ret);
	printk("\t debug_read_utl = 0x%llx\n", ret);

	break;
    default:
	printk("default ioctl\n");
	break;
    }

    return 0;
}

/** @brief Devices are represented as file structure in the kernel. The file_operations structure from
 *  /linux/fs.h lists the callback functions that you wish to associated with your file operations
 *  using a C99 syntax structure. char devices usually implement open, read, write and release calls
 */
static struct file_operations fops =
{
   .open = dev_open,
   .read = dev_read,
   .write = dev_write,
   .release = dev_release,
   .unlocked_ioctl = device_ioctl,
};

/** @brief The LKM initialization function
 *  The static keyword restricts the visibility of the function to within this C file. The __init
 *  macro means that for a built-in driver (not a LKM) the function is only used at initialization
 *  time and that it can be discarded and its memory freed up after that point.
 *  @return returns 0 if successful
 */
static int __init nn_init(void){
   printk(KERN_INFO "NNDEV: Initializing the NNDEV\n");
   majorNumber = register_chrdev(0, DEVICE_NAME, &fops);
   if (majorNumber<0){
      printk(KERN_ALERT "NNDEV failed to register a major number\n");
      return majorNumber;
   }
   printk(KERN_INFO "NNDEV: registered correctly with major number %d\n", majorNumber);

   // Register the device class
   nnClass = class_create(THIS_MODULE, CLASS_NAME);
   if (IS_ERR(nnClass)){
      unregister_chrdev(majorNumber, DEVICE_NAME);
      printk(KERN_ALERT "Failed to register NNDEV class\n");
      return PTR_ERR(nnClass);
   }
   printk(KERN_INFO "NNDEV: device class registered correctly\n");

   // Register the device driver
   nnDevice = device_create(nnClass, NULL, MKDEV(majorNumber, 0), NULL, DEVICE_NAME);
   if (IS_ERR(nnDevice)){               // Clean up if there is an error
      class_destroy(nnClass);           // Repeated code but the alternative is goto statements
      unregister_chrdev(majorNumber, DEVICE_NAME);
      printk(KERN_ALERT "Failed to create the device\n");
      return PTR_ERR(nnDevice);
   }
   printk(KERN_INFO "NNDEV: device class created correctly\n"); // Made it! device was initialized
   return 0;
}

static void __exit nn_exit(void){
   device_destroy(nnClass, MKDEV(majorNumber, 0));     // remove the device
   class_unregister(nnClass);                          // unregister the device class
   class_destroy(nnClass);                             // remove the device class
   unregister_chrdev(majorNumber, DEVICE_NAME);             // unregister the major number
   printk(KERN_INFO "NNDEV: Goodbye from the LKM!\n");
}

static int dev_open(struct inode *inodep, struct file *filep){
   numberOpens++;
   printk(KERN_INFO "NNDEV: Device has been opened %d time(s)\n", numberOpens);
   return 0;
}

static ssize_t dev_read(struct file *filep, char *buffer, size_t len, loff_t *offset){
   int error_count = 0;
   error_count = copy_to_user(buffer, message, size_of_message);

   if (error_count==0) {
      printk(KERN_INFO "NNDEV: Sent %d characters to the user\n", size_of_message);
      return (size_of_message=0);
   }
   else {
      printk(KERN_INFO "NNDEV: Failed to send %d characters to the user\n", error_count);
      return -EFAULT;
   }
}


static ssize_t dev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset) {
    uintptr_t old_antp;

    printk("NNDEV: Received %d characters from the user\n", (int)len);
    
    if(strcmp(buffer, "createant") == 0)
    {
	if(asid_nnid_ktable == NULL) 
	{
	    printk("Creating asid_nnid_ktable\n");
	    asid = 0; 
	    nnid = 0;
	    asid_nnid_table_create(&asid_nnid_ktable, asid * 2 + 1, nnid * 2 + 1);

	    printk("entry = 0x%p\n", asid_nnid_ktable->entry);
	    
	    old_antp = set_antp(asid_nnid_ktable->entry, asid_nnid_ktable->size);
	    printk("createant: old_antp = 0x%lx\n", old_antp);
	    BUG_ON(old_antp != (uintptr_t)-1);

	    old_antp = set_antp(asid_nnid_ktable->entry, asid_nnid_ktable->size);
	    printk("createant: old_antp = 0x%lx\n", old_antp);
	    BUG_ON(old_antp != (uintptr_t)asid_nnid_ktable->entry);
	}
	else
	{
	    printk("Already created asid_nnid_ktable\n");
	}
    }
    else if (strcmp(buffer, "showant") == 0)
    {
	asid_nnid_table_info(asid_nnid_ktable);
    }
    else
    {
	int res, temp;
	res = get_user(temp, (int*)buffer);
	if(res != 0){
	    printk("Unknown command\n");
	}
	else
	{
	    printk("temp = %d\n", temp);
	}
    }
    
    return len;
}

static int dev_release(struct inode *inodep, struct file *filep){
   printk(KERN_INFO "NNDEV: Device successfully closed\n");
   return 0;
}

module_init(nn_init);
module_exit(nn_exit);
