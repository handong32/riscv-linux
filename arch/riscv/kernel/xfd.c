#include <asm/io.h>
#include <asm/uaccess.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>

#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/types.h>

#include <asm/csr.h>
#include <asm/io.h>
#include <asm/pgalloc.h>
#include <asm/processor.h>
#include <asm/ptrace.h>

#define DEVICE_NAME "xfd"
#define CLASS_NAME "fpga nn accelerator"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("BU");
MODULE_DESCRIPTION("XFiles/Dana device");
MODULE_VERSION("1");

static int    majorNumber;                  ///< Stores the device number -- determined automatically
static int    numberOpens = 0;              ///< Counts the number of times the device is opened
static struct class*  nnClass  = NULL; ///< The device-driver class struct pointer
static struct device* nnDevice = NULL; ///< The device-driver device struct pointer

// IOCTL calls
#define MAJOR_NUM 101
#define IOCTL_SET_FILESIZE _IOR(MAJOR_NUM, 0, xlen_t *)
#define IOCTL_SET_NN _IOR(MAJOR_NUM, 1, xlen_t *)
#define IOCTL_SHOW_ANT _IO(MAJOR_NUM, 2)
#define IOCTL_PHYS_ADDR _IO(MAJOR_NUM, 3)
#define IOCTL_TRANS_PHYS_ADDR _IOR(MAJOR_NUM, 4, xlen_t*)
#define IOCTL_TEST _IO(MAJOR_NUM, 5)

long xfd_ioctl(struct file* file,
		  unsigned int ioctl_num,
		  unsigned long ioctl_param)
{
    switch(ioctl_num) 
    {
    case IOCTL_TEST:
	printk("IOCTL_TEST\n");
	break;
    default:
	printk("UNKNOWN IOCTL\n");
	break;
    }
    
    return 0;

}

// The prototype functions for xfd driver
static int dev_open(struct inode *, struct file *);
static int dev_release(struct inode *, struct file *);
static ssize_t dev_read(struct file *, char *, size_t, loff_t *);
static ssize_t dev_write(struct file *, const char *, size_t, loff_t *);

static struct file_operations fops = {
    .open = dev_open,
    .read = dev_read,
    .write = dev_write,
    .release = dev_release,
    .unlocked_ioctl = xfd_ioctl,
};

/* INIT FUNCTION */
static int __init xfd_init(void) {
  printk(KERN_INFO "XFD: Initializing device\n");
  majorNumber = register_chrdev(0, DEVICE_NAME, &fops);
  if (majorNumber < 0) {
    printk(KERN_ALERT "XFD failed to register a major number\n");
    return majorNumber;
  }
  printk(KERN_INFO "XFD: registered correctly with major number %d\n",
         majorNumber);

  // Register the device class
  nnClass = class_create(THIS_MODULE, CLASS_NAME);
  if (IS_ERR(nnClass)) {
    unregister_chrdev(majorNumber, DEVICE_NAME);
    printk(KERN_ALERT "Failed to register XFD class\n");
    return PTR_ERR(nnClass);
  }
  printk(KERN_INFO "XFD: device class registered correctly\n");

  // Register the device driver
  nnDevice =
      device_create(nnClass, NULL, MKDEV(majorNumber, 0), NULL, DEVICE_NAME);
  if (IS_ERR(nnDevice)) { // Clean up if there is an error
    class_destroy(
        nnClass); // Repeated code but the alternative is goto statements
    unregister_chrdev(majorNumber, DEVICE_NAME);
    printk(KERN_ALERT "Failed to create the device\n");
    return PTR_ERR(nnDevice);
  }
  printk(KERN_INFO "XFD: device class created correctly\n"); // Made it! device
                                                             // was initialized
  return 0;
}

static void __exit xfd_exit(void) {
  device_destroy(nnClass, MKDEV(majorNumber, 0)); // remove the device
  class_unregister(nnClass);                      // unregister the device class
  class_destroy(nnClass);                         // remove the device class
  unregister_chrdev(majorNumber, DEVICE_NAME);    // unregister the major number
  printk(KERN_INFO "XFD EXITED\n");
}

static int dev_open(struct inode *inodep, struct file *filep) {
  numberOpens++;
  printk(KERN_INFO "XFD: Device has been opened %d time(s)\n", numberOpens);
  return 0;
}

static ssize_t dev_read(struct file *filep, char *buffer, size_t len,
                        loff_t *offset) {
    return 0;
}

static ssize_t dev_write(struct file *filep, const char *buffer, size_t len,
                         loff_t *offset) {
    return 0;
}

static int dev_release(struct inode *inodep, struct file *filep) {
  printk(KERN_INFO "XFD: Device successfully closed\n");
  return 0;
}

module_init(xfd_init);
module_exit(xfd_exit);
