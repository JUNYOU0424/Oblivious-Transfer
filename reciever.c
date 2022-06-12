#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>
#include "./crypto/aes.h"


int sockfd = 0;
char *S,*T1,*T2 = NULL;
void Gen_Rand(int len){
    char *raw_buf = NULL;
    char *after_padding_buf = NULL;
    int padding_size = 0;
    srand(time(0));
    raw_buf = (char *)malloc(len);
    S = (char *)malloc(padding_size);
    T1 = (char *)malloc(len*2);
    T2 = (char *)malloc(len*2);
    memcpy(raw_buf,"s"+rand()%256,len);
    after_padding_buf = padding_buf(raw_buf,len,&padding_size);
    encrpyt_buf(after_padding_buf,&S, padding_size);
    for(int i=0;i<len*2;i++){
        T1[i] = rand()%256;
        T2[i] = S[i] ^ T1[i];
    }
}

void Send_Random_Matrix(){
    char receiveMessage[100] = {};
    char *T = malloc(64*sizeof(char));
    memcpy(T,T1, 32 * sizeof(char));
    memcpy(T+32,T2, 32 * sizeof(char));
    printf("Send T1 & T2:\n");
    printf_buff(T1,32);
    printf_buff(T2,32);
    send(sockfd,T,64,0);
    recv(sockfd,receiveMessage,sizeof(receiveMessage),0);

    printf("Sever %s\n",receiveMessage);
}

void InitOTReciever(){
    sockfd = socket(AF_INET , SOCK_STREAM , 0);
    if (sockfd == -1){
        printf("Fail to create a socket.");
    }

    struct sockaddr_in info;
    bzero(&info,sizeof(info));
    info.sin_family = PF_INET;

    info.sin_addr.s_addr = inet_addr("127.0.0.1");
    info.sin_port = htons(8700);


    int err = connect(sockfd,(struct sockaddr *)&info,sizeof(info));
    if(err==-1){
        printf("Connection error");
    }

}

int main(int argc , char *argv[])
{
    InitOTReciever();
    Gen_Rand(16);
    Send_Random_Matrix();
    return 0;
}