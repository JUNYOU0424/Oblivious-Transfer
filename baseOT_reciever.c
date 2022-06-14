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
char *S = NULL;
void Gen_Rand(int len)
{
    char *raw_buf = NULL;
    char *after_padding_buf = NULL;
    int padding_size = 0;
    srand(time(0));
    raw_buf = (char *)malloc(len);
    S = (char *)malloc(padding_size);
    memcpy(raw_buf, "s" + rand() % 256, len);
    after_padding_buf = padding_buf(raw_buf, len, &padding_size);
    encrpyt_buf(after_padding_buf, &S, padding_size);
}

void Send_Random_Matrix()
{
    char receiveMessage[100] = {};
    recv(sockfd, receiveMessage, sizeof(receiveMessage), 0);

    printf("Sever %x\n", receiveMessage);
}

void InitOTReciever()
{
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1)
    {
        printf("Fail to create a socket.");
    }

    struct sockaddr_in info;
    bzero(&info, sizeof(info));
    info.sin_family = PF_INET;

    info.sin_addr.s_addr = inet_addr("127.0.0.1");
    info.sin_port = htons(8700);

    int err = connect(sockfd, (struct sockaddr *)&info, sizeof(info));
    if (err == -1)
    {
        printf("Connection error");
    }
}

int main(int argc, char *argv[])
{
    InitOTReciever();
    Gen_Rand(16);
    Send_Random_Matrix();
    return 0;
}