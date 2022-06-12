#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "rsa.h"

int main(){
    char   *pri_key;           // Private key
    char   *pub_key;  
    Gen_Key();
    printf("\n%s\n%s\n", pri_key, pub_key);
}