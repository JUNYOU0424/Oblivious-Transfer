#ifndef _RSA_H    
#define _RSA_H

void Encrypt(char *encrypt,RSA *keypair,char *err,char *msg);
void Decrypt(char *decrypt,char *encrypt,char *err,RSA *keypair);
#endif