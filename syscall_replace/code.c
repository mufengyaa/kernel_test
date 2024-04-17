#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/unistd.h>
#include <linux/time.h>
#include <asm/uaccess.h>
#include <linux/sched.h>
#include <linux/kprobes.h>

#define __NR_perf_event_open 298

unsigned int clear_and_return_cr0(void);
void setback_cr0(unsigned int val);
static int sys_hackcall(void);

unsigned long *sys_call_table = 0;

/* 定义一个函数指针，用来保存原来的系统调用*/
static int (*orig_syscall_saved)(void);

/*
 * 设置cr0寄存器的第16位为0
 */
unsigned int clear_and_return_cr0(void)
{
    unsigned int cr0 = 0;
    unsigned int ret;

    /* 将cr0寄存器的值移动到rax寄存器中，同时输出到cr0变量中 */
    asm volatile ("movq %%cr0, %%rax" : "=a"(cr0));

    ret = cr0;
    cr0 &= 0xfffeffff;  /* 将cr0变量值中的第16位清0，将修改后的值写入cr0寄存器 */

    /* 读取cr0的值到rax寄存器，再将rax寄存器的值放入cr0中 */
    asm volatile ("movq %%rax, %%cr0" :: "a"(cr0));

    return ret;
}

/*
 * 还原cr0寄存器的值为val
 */
void setback_cr0(unsigned int val)
{
    asm volatile ("movq %%rax, %%cr0" :: "a"(val));
}

/*
 * 自己编写的系统调用函数
 */
static int sys_hackcall(void)
{
    printk("It is my perf_event_open\n");
    return 0;
}

/*
 * 模块的初始化函数，模块的入口函数，加载模块时调用
 */
static int __init init_hack_module(void)
{
    int orig_cr0;

    printk("Hack syscall is starting...\n");

   /*  cat kallsyms |grep sys_call_table获取 sys_call_table 虚拟内存地址 */
    sys_call_table = 0xffffffff9d402dc0;
    if(sys_call_table == NULL)
        return -1;

    /* 保存原始系统调用 */
    orig_syscall_saved = (int(*)(void))(sys_call_table[__NR_perf_event_open]);

    orig_cr0 = clear_and_return_cr0(); /* 设置cr0寄存器的第16位为0 */
    sys_call_table[__NR_perf_event_open] = (unsigned long)&sys_hackcall; /* 替换成我们编写的函数 */
    setback_cr0(orig_cr0); /* 还原cr0寄存器的值 */

    return 0;
}

/*
 * 模块退出函数，卸载模块时调用
 */
static void __exit exit_hack_module(void)
{
    int orig_cr0;

    orig_cr0 = clear_and_return_cr0();
    sys_call_table[__NR_perf_event_open] = (unsigned long)orig_syscall_saved; /* 设置为原来的系统调用 */
    setback_cr0(orig_cr0);

    printk("Hack syscall is exited....\n");
}

module_init(init_hack_module);
module_exit(exit_hack_module);
MODULE_LICENSE("GPL");
