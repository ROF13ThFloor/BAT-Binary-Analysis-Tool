#include <stdio.h>
#include <string.h>



int func1(){


func2();

}


int func2(){

printf("hi");




}





int main () {
   char src[40];
   char dest[100];
  
   memset(dest, '\0', sizeof(dest));
   strcpy(src, "This is tutorialspoint.com");
   strcpy(dest, src);

   printf("Final copied string : %s\n", dest);
   
   return(0);
}
