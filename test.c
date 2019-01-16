#include<stdio.h>
#include<stdlib.h>
#include<errno.h>
#include<fcntl.h>
#include<string.h>
#include<unistd.h>
 
int main(){
	int ret, fd;   
	fd = open("/dev/ipfilter", O_RDWR);
	FILE * fp;
	char  line[50] ;
	fp = fopen("config", "r");
	if (fp == NULL)
		exit(EXIT_FAILURE);
	while (fgets(line, 50, fp) != NULL)
	{
		int j;
		for( j=0;j<50;j++){
			if(line[j]=='\n'){
				line[j]='\0';
				break;
			}
		}
		ret = write(fd, line, strlen(line));
   		if (ret < 0){
      			return errno;
   		}
	}
   return 0;
}
