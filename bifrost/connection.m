//
//  connection.m
//  bifrost
//
//  Created by @its_a_feature_ on 10/14/19.
//  Copyright © 2019 Cody Thomas (@its_a_feature_). All rights reserved.
//

#import <Foundation/Foundation.h>
#include "connection.h"

@implementation kdc

int fd = 0;

-(int)connectDomain:(char*) domain{
    int sockfd;
    struct hostent *server;
    struct sockaddr_in servaddr;
    char ip[100];
    //create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd == -1){
        printf("[-] Failed to create socket\n");
        return -1;
    }
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    server = gethostbyname(domain);
    if(server == NULL){
        printf("[-] Failed to find computer\n");
        return -1;
    }
    servaddr.sin_port = htons(88);
    struct in_addr **addr_list;
    addr_list = (struct in_addr **) server->h_addr_list;
    
    for(int i = 0; addr_list[i] != NULL; i++)
    {
        //try to connect to them and if they don't work, try the next one
        strcpy(ip , inet_ntoa(*addr_list[i]) );
        printf("[*] %s resolved to : %s\n" , domain , ip);
        servaddr.sin_addr.s_addr = inet_addr(ip);
        if(connect(sockfd, &servaddr, sizeof(servaddr)) < 0){
            printf("[-] Failed to connect\n");
            continue;
        }
        printf("[+] Successfully connected to remote domain\n");
        fd = sockfd;
        return 0;
    }
    printf("[-] Failed to connect to any IP address on port 88\n");
    return -1;
}
-(int)connectLKDCByHostname:(char*) hostname{
    return [self connectDomain: hostname];
}
-(int)connectLKDCByIP:(char*) ip{
    // connect to the LKDC of a remote computer
    int sockfd;
    struct hostent *server;
    struct sockaddr_in servaddr;
    //create socket
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd == -1){
        printf("[-] Failed to create socket\n");
        return -1;
    }
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(88);
    servaddr.sin_addr.s_addr = inet_addr(ip);
    if(connect(sockfd, &servaddr, sizeof(servaddr)) < 0){
        printf("[-] Failed to connect\n");
        fd = 0;
        return -1;
    }
    printf("[+] Successfully connected to remote IP: %s\n", ip);
    fd = sockfd;
    return 0;
}
-(int)sendBytes:(NSData*) data{
    int res;
    Byte* i = malloc(4);
    uint32_t network = htonl(data.length);
    memcpy(i, &network, 4);
    send(fd, i, 4, 0);
    //printf("Sending %d bytes\n", data.length);
    res = send(fd, data.bytes, data.length, 0);
    if(res < 0){
        printf("[-] Send failed\n");
        return -1;
    }
    //printf("Sent %d bytes\n", res);
    return 0;
}
-(NSData*)recvBytes{
    //printf("Receiving data\n");
    Byte* response = malloc(65535);
    int sizeBytes;
    int received_size = recv(fd, &sizeBytes, 4, 0);
    int size = ntohl(sizeBytes);
    //printf("Total size to receive: %d\n", size);
    int received_bytes_total = 0;
    while(received_bytes_total < size){
        received_size = recv(fd, response + received_bytes_total, 65535, 0);
        if(received_size <= 0){
            printf("[-] Failed to receive bytes with error: %d\n", received_size);
            printf("[-] Error number: %d\n", errno);
            return NULL;
        }
        received_bytes_total += received_size;
        //printf("Total received: %d\n", received_bytes_total);
    }
    NSData* result = [[NSData alloc] initWithBytes:response length:received_bytes_total];
    return result;
}
-(void)closeConnection{
    close(fd);
}
@end
