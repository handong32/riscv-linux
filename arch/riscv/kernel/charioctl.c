#include <linux/init.h>           // Macros used to mark up functions e.g. __init __exit
#include <linux/module.h>         // Core header for loading LKMs into the kernel
#include <linux/device.h>         // Header to support the kernel Driver Model
#include <linux/kernel.h>         // Contains types, macros, functions for the kernel
#include <linux/fs.h>             // Header for the Linux file system support
#include <asm/uaccess.h>          // Required for the copy to user function

#include <linux/mm.h>
#include <linux/slab.h>

#include <asm/processor.h>
#include <asm/ptrace.h>
#include <asm/csr.h>

#define  DEVICE_NAME "ebbchar"    ///< The device will appear at /dev/ebbchar using this value
#define  CLASS_NAME  "ebb"        ///< The device class -- this is a character device driver

MODULE_LICENSE("GPL");            ///< The license type -- this affects available functionality
MODULE_AUTHOR("BU");    ///< The author -- visible when you use modinfo
MODULE_DESCRIPTION("riscv xfiles-dana mod");  ///< The description -- see modinfo
MODULE_VERSION("0.000000000001");            ///< A version number to inform users

typedef uint32_t nnid_type;
typedef uint16_t asid_type;
typedef uint16_t tid_type;
typedef int32_t element_type;
typedef uint64_t x_len;
typedef uint64_t xlen_t;

typedef enum {
  xfiles_reg_batch_items = 0,
  xfiles_reg_learning_rate,
  xfiles_reg_weight_decay_lambda
} xfiles_reg;

typedef enum {
  READ_DATA = 0,
  WRITE_DATA = 1,
  NEW_REQUEST = 3,
  WRITE_DATA_LAST = 5,
  WRITE_REGISTER = 7,
  XFILES_DANA_ID = 16
} request_t;

typedef enum {
  UPDATE_ASID = 0,
  UPDATE_ANTP = 1
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
  x_len * config;                // | * config           |-> [NN Config] |
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
static struct class*  ebbcharClass  = NULL; ///< The device-driver class struct pointer
static struct device* ebbcharDevice = NULL; ///< The device-driver device struct pointer
static int    ioNum = 100;

xlen_t set_asid(asid_type asid) {
  int old_asid;
  asm volatile ("custom0 %[old_asid], %[rs1], 0, 0"
                : [old_asid] "=r" (old_asid)
                : [rs1] "r" (asid));
  return old_asid;
}

xlen_t set_antp(asid_nnid_table_entry * antp, size_t size) {
  int old_antp;
  asm volatile ("custom0 %[old_antp], %[rs1], %[rs2], 1"
                : [old_antp] "=r" (old_antp)
                : [rs1] "r" (antp), [rs2] "r" (size));
  return old_antp;
}

xlen_t xf_read_csr(xfiles_csr_t csr) {
  xlen_t csr_value;
  asm volatile ("custom0 %[csr_value], %[rs1], 0, 2"
                : [csr_value] "=r" (csr_value)
                : [rs1] "r" (csr));
  return csr_value;
}

void construct_queue(queue ** new_queue, int size) {
    (*new_queue)->data = (uint64_t *) kmalloc(size * sizeof(uint64_t), GFP_KERNEL);
    (*new_queue)->size = size;
    (*new_queue)->head = (*new_queue)->data;
    (*new_queue)->tail = (*new_queue)->data;
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
  (*new_table)->entry =
      (asid_nnid_table_entry *) kmalloc(sizeof(asid_nnid_table_entry) * table_size, GFP_KERNEL);
  (*new_table)->size = table_size;

  for (i = 0; i < table_size; i++) {
    // Create the configuration region
    (*new_table)->entry[i].asid_nnid =
	(nn_configuration *) kmalloc(configs_per_entry * sizeof(nn_configuration), GFP_KERNEL);
    (*new_table)->entry[i].asid_nnid->config = NULL;
    (*new_table)->entry[i].num_configs = configs_per_entry;
    (*new_table)->entry[i].num_valid = 0;

    // Create the io region
    (*new_table)->entry[i].transaction_io = (io *) kmalloc(sizeof(io), GFP_KERNEL);
    (*new_table)->entry[i].transaction_io->header = 0;
    (*new_table)->entry[i].transaction_io->input = (queue *) kmalloc(sizeof(queue), GFP_KERNEL);
    (*new_table)->entry[i].transaction_io->output = (queue *) kmalloc(sizeof(queue), GFP_KERNEL);
    construct_queue(&(*new_table)->entry[i].transaction_io->input, 16);
    construct_queue(&(*new_table)->entry[i].transaction_io->output, 16);
  }

}

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



// The prototype functions for the character driver -- must come before the struct definition
static int     dev_open(struct inode *, struct file *);
static int     dev_release(struct inode *, struct file *);
static ssize_t dev_read(struct file *, char *, size_t, loff_t *);
static ssize_t dev_write(struct file *, const char *, size_t, loff_t *);

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
};

/** @brief The LKM initialization function
 *  The static keyword restricts the visibility of the function to within this C file. The __init
 *  macro means that for a built-in driver (not a LKM) the function is only used at initialization
 *  time and that it can be discarded and its memory freed up after that point.
 *  @return returns 0 if successful
 */
static int __init ebbchar_init(void){
   printk(KERN_INFO "EBBChar: Initializing the EBBChar LKM\n");

   // Try to dynamically allocate a major number for the device -- more difficult but worth it
   majorNumber = register_chrdev(0, DEVICE_NAME, &fops);
   if (majorNumber<0){
      printk(KERN_ALERT "EBBChar failed to register a major number\n");
      return majorNumber;
   }
   printk(KERN_INFO "EBBChar: registered correctly with major number %d\n", majorNumber);

   // Register the device class
   ebbcharClass = class_create(THIS_MODULE, CLASS_NAME);
   if (IS_ERR(ebbcharClass)){                // Check for error and clean up if there is
      unregister_chrdev(majorNumber, DEVICE_NAME);
      printk(KERN_ALERT "Failed to register device class\n");
      return PTR_ERR(ebbcharClass);          // Correct way to return an error on a pointer
   }
   printk(KERN_INFO "EBBChar: device class registered correctly\n");

   // Register the device driver
   ebbcharDevice = device_create(ebbcharClass, NULL, MKDEV(majorNumber, 0), NULL, DEVICE_NAME);
   if (IS_ERR(ebbcharDevice)){               // Clean up if there is an error
      class_destroy(ebbcharClass);           // Repeated code but the alternative is goto statements
      unregister_chrdev(majorNumber, DEVICE_NAME);
      printk(KERN_ALERT "Failed to create the device\n");
      return PTR_ERR(ebbcharDevice);
   }
   printk(KERN_INFO "EBBChar: device class created correctly\n"); // Made it! device was initialized
   return 0;
}

/** @brief The LKM cleanup function
 *  Similar to the initialization function, it is static. The __exit macro notifies that if this
 *  code is used for a built-in driver (not a LKM) that this function is not required.
 */
static void __exit ebbchar_exit(void){
   device_destroy(ebbcharClass, MKDEV(majorNumber, 0));     // remove the device
   class_unregister(ebbcharClass);                          // unregister the device class
   class_destroy(ebbcharClass);                             // remove the device class
   unregister_chrdev(majorNumber, DEVICE_NAME);             // unregister the major number
   printk(KERN_INFO "EBBChar: Goodbye from the LKM!\n");
}

/** @brief The device open function that is called each time the device is opened
 *  This will only increment the numberOpens counter in this case.
 *  @param inodep A pointer to an inode object (defined in linux/fs.h)
 *  @param filep A pointer to a file object (defined in linux/fs.h)
 */
static int dev_open(struct inode *inodep, struct file *filep){
   numberOpens++;
   printk(KERN_INFO "EBBChar: Device has been opened %d time(s)\n", numberOpens);
   return 0;
}

/** @brief This function is called whenever device is being read from user space i.e. data is
 *  being sent from the device to the user. In this case is uses the copy_to_user() function to
 *  send the buffer string to the user and captures any errors.
 *  @param filep A pointer to a file object (defined in linux/fs.h)
 *  @param buffer The pointer to the buffer to which this function writes the data
 *  @param len The length of the b
 *  @param offset The offset if required
 */
static ssize_t dev_read(struct file *filep, char *buffer, size_t len, loff_t *offset){
   int error_count = 0;
   // copy_to_user has the format ( * to, *from, size) and returns 0 on success
   error_count = copy_to_user(buffer, message, size_of_message);

   if (error_count==0){            // if true then have success
      printk(KERN_INFO "EBBChar: Sent %d characters to the user\n", size_of_message);
      return (size_of_message=0);  // clear the position to the start and return 0
   }
   else {
      printk(KERN_INFO "EBBChar: Failed to send %d characters to the user\n", error_count);
      return -EFAULT;              // Failed -- return a bad address message (i.e. -14)
   }
}

/** @brief This function is called whenever the device is being written to from user space i.e.
 *  data is sent to the device from the user. The data is copied to the message[] array in this
 *  LKM using the sprintf() function along with the length of the string.
 *  @param filep A pointer to a file object
 *  @param buffer The buffer to that contains the string to write to the device
 *  @param len The length of the array of data that is being passed in the const char buffer
 *  @param offset The offset if required
 */
static ssize_t dev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset){
    printk("EBBChar: Received %d characters from the user\n", (int)len);
    
    if(strcmp(buffer, "createant") == 0)
    {
	if(asid_nnid_ktable == NULL) 
	{
	    printk("Creating asid_nnid_ktable\n");
	    asid_type asid;
	    int old_antp;
	    nnid_type nnid;

	    asid = 0; 
	    nnid = 0;
	    asid_nnid_table_create(&asid_nnid_ktable, asid * 2 + 1, nnid * 2 + 1);

	    old_antp = set_antp(asid_nnid_ktable->entry, asid_nnid_ktable->size);
	    printk("old_antp = %d\n", old_antp);
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

/** @brief The device release function that is called whenever the device is closed/released by
 *  the userspace program
 *  @param inodep A pointer to an inode object (defined in linux/fs.h)
 *  @param filep A pointer to a file object (defined in linux/fs.h)
 */
static int dev_release(struct inode *inodep, struct file *filep){
   printk(KERN_INFO "EBBChar: Device successfully closed\n");
   return 0;
}

/** @brief A module must use the module_init() module_exit() macros from linux/init.h, which
 *  identify the initialization function at insertion time and the cleanup function (as
 *  listed above)
 */
module_init(ebbchar_init);
module_exit(ebbchar_exit);
