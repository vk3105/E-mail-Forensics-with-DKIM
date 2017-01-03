#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<string.h>
#include<sys/time.h>
#include<sys/types.h>
//signing the email with RSA and SHA
double signMessage(char **hashName, char **message, char *rsaKey, char *shaType){
    double time = 0;
    int i = 0;
    int pid;
    struct timeval start,end;
    gettimeofday(&start,NULL);
    while(i<10){
        pid = fork();
        if(!pid){
            execl("/usr/bin/openssl","openssl","dgst",shaType,"-sign",rsaKey,"-out",hashName[i],message[i],NULL);
        }else{
            waitpid(pid,NULL, 0);
        }
        i++;
    }
    gettimeofday(&end,NULL);
    time =(((double)end.tv_sec-(double)start.tv_sec)*1000)+(((double)end.tv_usec-(double)start.tv_usec)/((double)1000));
return time;
}

//Verify the signed email with RSA and SHA
double verifyMessage(char **hashName, char **message, char *rsaKey, char *shaType){
    double time = 0;
    int i = 0;
    int pid;
    struct timeval start,end;
    gettimeofday(&start,NULL);
    while(i<10){
        pid = fork();
        if(!pid){
            execl("/usr/bin/openssl","openssl","dgst",shaType,"-verify",rsaKey,"-signature",hashName[i],message[i],NULL);
        }else{
            waitpid(pid,NULL, 0);
        }
        i++;
    }
    gettimeofday(&end,NULL);
    time =(((double)end.tv_sec-(double)start.tv_sec)*1000)+(((double)end.tv_usec-(double)start.tv_usec)/((double)1000));
return time;
}

void main(){
    int i =0;
    double timeTaken = 0;
    char *inputMsg[10];
    char *hash1024SHA1[10];
    char *hash1024SHA256[10];
    char *hash2048SHA1[10];
    char *hash2048SHA256[10];

    for(i=0;i<10;i++){
        inputMsg[i]= (char*)malloc(30);
        hash1024SHA1[i]= (char*)malloc(30);
        hash1024SHA256[i]= (char*)malloc(30);
        hash2048SHA1[i]= (char*)malloc(30);
        hash2048SHA256[i]= (char*)malloc(30);
        sprintf(inputMsg[i],"mails/mail %d.msg",i+1);
        sprintf(hash1024SHA1[i],"encrypted/1024SHA1/cipher.%d",i+1);
        sprintf(hash1024SHA256[i],"encrypted/1024SHA256/cipher.%d",i+1);
        sprintf(hash2048SHA1[i],"encrypted/2048SHA1/cipher.%d",i+1);
        sprintf(hash2048SHA256[i],"encrypted/2048SHA256/cipher.%d",i+1);
    }


    for (i=1;i<=5;i++){

        // sha1 + RSA 1024 signing
            timeTaken = 0;
            timeTaken = signMessage(hash1024SHA1,inputMsg,"rsaprivatekey1024.pem","-sha1");
            printf("Time Taken for round %d of 1024+SHA1 signing is %lf \n",i,timeTaken);

            // sha1 + RSA 2048 signing
            timeTaken = 0;
            timeTaken = signMessage(hash2048SHA1,inputMsg,"rsaprivatekey2048.pem","-sha1");
            printf("Time Taken for round %d of 2048+SHA1 signing is %lf \n",i,timeTaken);

            // sha256 + RSA 1024 signing
            timeTaken = 0;
            timeTaken = signMessage(hash1024SHA256,inputMsg,"rsaprivatekey1024.pem","-sha256");
            printf("Time Taken for round %d of 1024+SHA256 signing is %lf \n",i,timeTaken);

            // sha256 + RSA 2048 signing
            timeTaken = 0;
            timeTaken = signMessage(hash2048SHA256,inputMsg,"rsaprivatekey2048.pem","-sha256");
            printf("Time Taken for round %d of 2048+SHA256 signing is %lf \n\n",i,timeTaken);
    }


    for(i=1;i<=5;i++){

            // sha1 + RSA 1024 verification
            timeTaken = 0;
            timeTaken = verifyMessage(hash1024SHA1,inputMsg,"rsapublickey1024.pem","-sha1");
            printf("Time Taken for round %d of 1024+SHA1 verification is %lf \n",i,timeTaken);

            // sha1 + RSA 2048 verification
            timeTaken = 0;
            timeTaken = verifyMessage(hash2048SHA1,inputMsg,"rsapublickey2048.pem","-sha1");
            printf("Time Taken for round %d of 2048+SHA1 verification is %lf \n",i,timeTaken);

            // sha256 + RSA 1024 verification
            timeTaken = 0;
            timeTaken = verifyMessage(hash1024SHA256,inputMsg,"rsapublickey1024.pem","-sha256");
            printf("Time Taken for round %d of 1024+SHA256 verification is %lf \n",i,timeTaken);

            // sha256 + RSA 2048 verification
            timeTaken = 0;
            timeTaken = verifyMessage(hash2048SHA256,inputMsg,"rsapublickey2048.pem","-sha256");
            printf("Time Taken for round %d of 2048+SHA256 verification is %lf \n",i,timeTaken);
    }

}
