// Comprueba que Linux intercepta una syscall con número de macOS (clase en el byte alto) y que se puede
// emular desde un manejador de SIGSYS, usando PR_SET_SYSCALL_USER_DISPATCH (kernel >= 5.11).
//
//   clang -O1 -o sud_syscall_dispatch sud_syscall_dispatch.c && ./sud_syscall_dispatch
//
// Detalle importante: rt_sigreturn debe ejecutarse desde la región permitida, así que se usa un
// restaurador propio (my_restorer) y solo esa función se declara como región exenta. Con el de libc, el
// propio retorno del manejador se intercepta y el proceso muere por recursión.
// Prueba: ¿intercepta Linux una syscall con número de macOS (0x2000000|N) mediante SUD?
#define _GNU_SOURCE
#include <linux/prctl.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ucontext.h>
#include <unistd.h>

#ifndef SYS_USER_DISPATCH
#define SYS_USER_DISPATCH 2
#endif
static volatile char selector = SYSCALL_DISPATCH_FILTER_ALLOW;
static volatile int hits = 0;
static volatile long last_nr = 0;

static void handler(int sig, siginfo_t* info, void* ucv) {
	ucontext_t* uc = ucv;
	selector = SYSCALL_DISPATCH_FILTER_ALLOW;              // dentro del manejador, syscalls normales
	hits++;
	last_nr = info->si_syscall;
	long nr = uc->uc_mcontext.gregs[REG_RAX];               // en x86_64 el nº va en rax
	if (info->si_code != SYS_USER_DISPATCH) { _exit(90); }
	// emulación de juguete: BSD getpid (clase 2, nº 20) -> devolver 4242; el resto -> ENOSYS
	uc->uc_mcontext.gregs[REG_RAX] = (nr == (0x2000000 | 20)) ? 4242 : -38;
	selector = SYSCALL_DISPATCH_FILTER_BLOCK;               // volver a interceptar antes de retornar
}

// retorno de señal en una función propia: rt_sigreturn debe ejecutarse desde la región permitida
__asm__(".text\n.global my_restorer\n.type my_restorer,@function\nmy_restorer:\n\tmovq $15, %rax\n\tsyscall\n\t.size my_restorer, .-my_restorer\n");
extern void my_restorer(void);

struct ksigaction { void* handler; unsigned long flags; void* restorer; unsigned long mask; };

static long raw(long nr, long a0) {
	long ret;
	register long r10 __asm__("r10") = 0;
	__asm__ volatile("syscall" : "=a"(ret) : "a"(nr), "D"(a0), "r"(r10) : "rcx", "r11", "memory");
	return ret;
}

int main(void) {
	struct ksigaction ks = { .handler = handler, .flags = SA_SIGINFO | SA_NODEFER | 0x04000000 /*SA_RESTORER*/,
		.restorer = my_restorer, .mask = 0 };
	if (syscall(SYS_rt_sigaction, SIGSYS, &ks, NULL, 8) != 0) { perror("rt_sigaction"); return 1; }
	// región permitida: solo my_restorer (16 bytes); todo lo demás se intercepta cuando selector == BLOCK
	if (prctl(PR_SET_SYSCALL_USER_DISPATCH, PR_SYS_DISPATCH_ON, (unsigned long)my_restorer, 16, &selector) != 0) {
		perror("prctl(PR_SET_SYSCALL_USER_DISPATCH)");
		return 1;
	}
	selector = SYSCALL_DISPATCH_FILTER_BLOCK;
	long a = raw(0x2000000 | 20, 0);          // getpid de BSD/macOS
	long b = raw(0x2000000 | 99999, 0);       // número inexistente
	selector = SYSCALL_DISPATCH_FILTER_ALLOW;
	printf("kernel: %s\n", "ok");
	printf("getpid BSD (0x2000014)  -> %ld   (esperado 4242)\n", a);
	printf("syscall inexistente      -> %ld   (esperado -38)\n", b);
	printf("intercepciones: %d, último si_syscall=0x%lx\n", hits, last_nr);
	return !(a == 4242 && b == -38 && hits == 2);
}
