#include <unistd.h>
#include <sys/syscall.h>

int func1(){

asm( "syscall" :: "a" (11));
func2();

}


int func2(){

printf("hi");


	asm( "syscall" :: "a" (1) );


}





int main () {
   char src[40];
   char dest[100];
  
   syscall(SYS_write, 1, "hello, world!\n", 14);

   printf("Final copied string : %s\n", dest);
   func1();
   return(0);
}
