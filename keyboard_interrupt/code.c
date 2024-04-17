#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/interrupt.h>

#define KEYBOARD_IRQ 1
int count=0;

irqreturn_t keyboard_interrupt_handler(int irq, void *dev_id)
{
    printk(KERN_INFO "Keyboard interrupt occurred!,%d\n",++count);
    return IRQ_HANDLED;
}

static int __init keyboard_interrupt_init(void)
{
    printk(KERN_INFO "Initializing keyboard interrupt module\n");

    // 注册键盘中断处理函数
    int result = request_irq(KEYBOARD_IRQ, keyboard_interrupt_handler, IRQF_SHARED, "keyboard_interrupt_handler", (void *)keyboard_interrupt_handler);
    if (result) {
        printk(KERN_ERR "Failed to register keyboard interrupt handler\n");
        return result;
    }

    return 0;
}

static void __exit keyboard_interrupt_exit()
{
    printk(KERN_INFO "Exiting keyboard interrupt module\n");
    free_irq(KEYBOARD_IRQ ,(void *)keyboard_interrupt_handler);
}

module_init(keyboard_interrupt_init);
module_exit(keyboard_interrupt_exit);

