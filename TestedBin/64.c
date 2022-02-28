#include<stdio.h>
#include<unistd.h>
#include <sys/syscall.h>

#include <sys/types.h>

int func1() {
	pid_t tid;
	syscall(SYS_tgkill, getpid(), tid);
	
}
int main()
{
func1();
asm( "syscall" :: "a" (60) );
asm( "syscall" :: "a" (60)  );
asm( "syscall" :: "a" (60) );


}
