#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <limits.h>
#include <vector>
#include <string.h>
using std::vector;

template<typename T> const wchar_t *GetTypeName();

#define DEFINE_TYPE_NAME(type, name) \
    template<>const wchar_t *GetTypeName<type>(){return name;}

namespace xld 
{
	struct pcontain
	{
		struct _private
		{
			void** ptr;
			long unsigned int size;
			bool buffing;
			unsigned int buff_size;
		} priv;

		bool initialise(){
			if(!priv.ptr){
				priv.ptr = (void**)malloc(1 * sizeof(void*));
				priv.size = 1;
				priv.buffing = false;
				priv.buff_size = 0;
				return true;
			}else{
				return false;
			}
		}

		void add(void* obj){
			++priv.size;
			priv.ptr = (void**)realloc(priv.ptr, priv.size * sizeof(void*));
			priv.ptr[priv.size - 1] = obj;
			if(priv.buffing){
				++priv.buff_size;
			}
		}
		
		void release(){
			int i;
			for(i = 0; i < priv.size; ++i){
				free(priv.ptr[i]);
			}
			free(priv.ptr);
			priv.size = 0;
		}

		void free_buff(){
			register int i;
			priv.buffing = false;
			for(i=priv.size-1; i>=(priv.size-priv.buff_size); i--){
				free(priv.ptr[i]);
				priv.size--;
				priv.buff_size--;
			}
			priv.ptr = (void**)realloc(priv.ptr, priv.size * sizeof(void*));
		}

		void start_buff(){ priv.buffing = true; }
		long unsigned int size(){ return priv.size; }

	} pcont;

	template<typename T>
	T xalloc(int size){
		pcont.initialise();
		long int len = sizeof(T);
		T obj = NULL;
		obj = (T)malloc(size);
		if(obj == NULL){
			perror("bad malloc");
			exit(1);	
		}
		pcont.add(obj);
		return obj;
	}

	void lock_xbuff(){ pcont.start_buff(); }
	void free_xbuff(){ pcont.free_buff(); }
	void free_xalloc(){ pcont.release(); }
}

using namespace xld;

unsigned char* rand_ip(){
	int i;
	unsigned char rnd;
	unsigned char* hex = xalloc<unsigned char*>(4);
	for(i=0; i<4; i++)
	{
		rnd = rand() % 256;
		sprintf((char*)hex+i, "%c", rnd);
	}
	return hex;
}

char* cchar(){
	char *c = xalloc<char*>(sizeof(char)*7);
	strcpy(c, "bonjour");
	return c;
}

int main(){
	int *x = xalloc<int*>(sizeof(int)*5);
	x[0] = 0x01;
	lock_xbuff();
	printf("%ld\n", pcont.priv.size);
	char *c = cchar();
	printf("%s\n", c);
	printf("%ld\n", pcont.priv.size);
	free_xbuff();
	printf("%ld\n", pcont.priv.size);
	free_xalloc();
	printf("%ld\n", pcont.priv.size);
	c[0] = 10;
	printf("%s", c);
	//printf("%d\n", ((int*)(z[0]))[0]);
	/*int i;
	srand(time(NULL));
	for(i=0; i<4; i++){
		unsigned char* hex;
		hex = rand_ip();
		printf("%d.%d.%d.%d\n", hex[0], hex[1], hex[2], hex[3]);
		free(hex);
	}*/
	return 0;
}

