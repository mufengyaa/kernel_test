#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kthread.h> // 包含创建内核线程所需的头文件

static struct task_struct *my_thread1, *my_thread2; // 内核线程结构体指针

int thread_func(void *data)
{
    printk(KERN_ERR "Kernel thread is running!");
    return 0;
}

static int __init my_module_init(void)
{
    printk(KERN_INFO "Initializing my_module\n");

    // 创建内核线程
    my_thread1 = kthread_create(thread_func, NULL, "mythread_1");
    if (IS_ERR(my_thread1))
    {
        printk(KERN_ERR "Failed to create kernel thread\n");
        return PTR_ERR(my_thread1);
    }
    my_thread2 = kthread_create(thread_func, NULL, "mythread_2");
    if (IS_ERR(my_thread2))
    {
        printk(KERN_ERR "Failed to create kernel thread\n");
        return PTR_ERR(my_thread2);
    }
    wake_up_process(my_thread1); // 启动内核线程
    wake_up_process(my_thread2);

    printk(KERN_ERR "Kernel thread created successfully,name:%s,pid:%d\n", my_thread1->comm, my_thread1->pid);
    printk(KERN_ERR "Kernel thread created successfully,name:%s,pid:%d\n", my_thread2->comm, my_thread2->pid);

    return 0;
}

static void __exit my_module_exit(void)
{
    printk(KERN_INFO "Exiting my_module\n");

    if (my_thread1)
    {
        kthread_stop(my_thread1); // 停止内核线程
    }
    if (my_thread2)
    {
        kthread_stop(my_thread2); // 停止内核线程
    }
}

module_init(my_module_init);
module_exit(my_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("A simple kernel module to create a kernel thread");
MODULE_VERSION("1.0");
