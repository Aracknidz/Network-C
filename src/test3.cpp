#include <stdio.h>
#include <stdlib.h>
int main(){
	char output, input1, input2;
	int foo = 10, bar = 15, dude = 19, thrid = 15;
	__asm__ __volatile__( "addl %0,%1;"
						  "addl %0,%1"
		                 :"=a"(dude)
		                 :"a"(foo), "b"(bar)
						);
	printf("foo+bar=%d\n", dude);
	return 0;
}

