#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>
#include "./crypto/aes.h"
//-lssl -lcrypto
int sockfd = 0, forClientSockfd = 0, flag = 0;
struct sockaddr_in serverInfo, clientInfo;
int addrlen = sizeof(clientInfo);

void InitOTSender()
{
    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd == -1)
    {
        printf("Fail to create a socket.");
    }
    bzero(&serverInfo, sizeof(serverInfo));

    serverInfo.sin_family = PF_INET;
    serverInfo.sin_addr.s_addr = INADDR_ANY;
    serverInfo.sin_port = htons(8700);
    bind(sockfd, (struct sockaddr *)&serverInfo, sizeof(serverInfo));
    listen(sockfd, 5);
}

void Recieve_Random_Matrix()
{
    char T1[256], T2[256] = {};
    recv(forClientSockfd, T1, 32, 0);
    recv(forClientSockfd, T2, 32, 0);
    send(forClientSockfd, "get T1 & T2", 128, 0);
    printf("Get T1:\n");
    printf_buff(T1, 32);
    printf("Get T2:\n");
    printf_buff(T2, 32);
}

int main(int argc, char *argv[])

{
    InitOTSender();
    forClientSockfd = accept(sockfd, (struct sockaddr *)&clientInfo, &addrlen);
    while (1)
    {
        Recieve_Random_Matrix();
    }

    return 0;
}