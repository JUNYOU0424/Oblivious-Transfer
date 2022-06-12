#ifndef _AES_H    
#define _AES_H

unsigned char* str2hex(char *str);
char *padding_buf(char *buf,int size, int *final_size);
void printf_buff(char *buff,int size);
void encrpyt_buf(char *raw_buf, char **encrpy_buf, int len );
void decrpyt_buf(char *raw_buf, char **encrpy_buf, int len );

#endif