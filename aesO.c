 /* aes.c
 * Code was written: June 7, 2017
 *
 * aes.c implements AES-128, AES-192, and AES-256 for RLCE
 * Copyright (C) 2017 Yongge Wang
 * 
 * Yongge Wang
 * Department of Software and Information Systems
 * UNC Charlotte
 * Charlotte, NC 28223
 * yonwang@uncc.edu
 *
 *
 * 91 - 97
 * 94 - 100
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

typedef struct AESkey {
  unsigned short Nk;
  unsigned short Nr;
  unsigned short Nb;
  unsigned short wLen;
  unsigned short keylen;
  unsigned char * key;
} * aeskey_t;

void aeskey_free(aeskey_t key) {
  free(key->key);
  free(key);
  return;
}

void AES_encrypt(unsigned char*, unsigned char*, aeskey_t);
void AES_decrypt(unsigned char*, unsigned char*, aeskey_t);
void testEncryption(unsigned char*, unsigned char*,aeskey_t, unsigned char*,int);
void testDecryption(unsigned char*, unsigned char*,aeskey_t, unsigned char*,int);
aeskey_t aeskey_init(unsigned short);

int main (int argc, char *argv[]) {
  
  unsigned char msg[]={0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
		       0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
  unsigned char decryptedmsg[16];
  unsigned char cipher[16];
   
  aeskey_t key=aeskey_init(128);  // Move code of function here
  unsigned char keystring[]={0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
			     0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f};
  memcpy(key->key, keystring, 16);
  unsigned char expectedcipher[]={0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,
				0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a};
				
	int numofT=500000; // Moved from line 44 to just before first used of variable. 
  testEncryption(msg, cipher,key,expectedcipher,numofT);
  testDecryption(msg, cipher,key,decryptedmsg,numofT);
  aeskey_free(key);

  key=aeskey_init(192); // and here
  char keystring192[]={0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,
		       0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17};
  memcpy(key->key,keystring192,24);
  unsigned char expectedcipher192[]={0xdd,0xa9,0x7c,0xa4,0x86,0x4c,0xdf,0xe0,
				     0x6e,0xaf,0x70,0xa0,0xec,0x0d,0x71,0x91};
  testEncryption(msg, cipher,key,expectedcipher192,numofT);
  testDecryption(msg, cipher,key,decryptedmsg,numofT);
  aeskey_free(key);
  
  key=aeskey_init(256); // and here
  unsigned char keystring256[]={0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
				0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
				0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
				0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f};
  memcpy(key->key, keystring256, 32);
  unsigned char expectedcipher256[]={0x8e,0xa2,0xb7,0xca,0x51,0x67,0x45,0xbf,
				     0xea,0xfc,0x49,0x90,0x4b,0x49,0x60,0x89};
  testEncryption(msg, cipher,key,expectedcipher256,numofT);
  testDecryption(msg, cipher,key,decryptedmsg,numofT);
  aeskey_free(key);
  exit(0);
}

void testEncryption(unsigned char msg[], unsigned char cipher[],aeskey_t key, unsigned char expectedcipher[],int numofT) {
  int i, failed=0;
  AES_encrypt(msg, cipher,key);
  for (i=0;i<16;i++) if (expectedcipher[i] != cipher[i]) failed =1;
  if (failed >0) {
    printf("AES-%d encryption failed\n", (key->keylen)*8);
  } else {
    /* Moved start and finish variables to new location to remove scope issues. */
    clock_t start, finish;
    
    start = clock();
    
    for (i=0;i<numofT;i++) {
      AES_encrypt(msg, cipher,key);
    }
  
    finish = clock();
    
    /* Moved seconds to new location to remove scope issues. */
    double seconds;
    
    seconds = ((double)(finish - start))/CLOCKS_PER_SEC;
    printf("%f seconds for %d times of AES-%d encryption\n",seconds,numofT,(key->keylen)*8);
  }
}

void testDecryption(unsigned char msg[], unsigned char cipher[],aeskey_t key, unsigned char decryptedmsg[],int numofT) {
  int i, failed=0;
  AES_decrypt(cipher,decryptedmsg, key);
  for (i=0;i<16;i++) if (decryptedmsg[i] != msg[i])  failed =1;

  if (failed >0) {
    printf("AES-%d decryption failed\n",(key->keylen)*8);
  } else {
    /* Moved start and finish to new location to remove scope issues. */
    clock_t start, finish;
    
    start = clock();
    for (i=0;i<numofT;i++) {
      AES_decrypt(cipher,decryptedmsg, key);
    }
  
    finish = clock();
    
    /* Moved seconds to new location to remove scope issues. */
    double seconds;
    
    seconds = ((double)(finish - start))/CLOCKS_PER_SEC;
    printf("%f seconds for %d times of AES-%d decryption\n",seconds,numofT,(key->keylen)*8);    
  }
}

// attempt to eliminate failed variable. 
// void testDecryption(unsigned char msg[], unsigned char cipher[],aeskey_t key, unsigned char decryptedmsg[],int numofT) {
//   int i, failed=0;
//   AES_decrypt(cipher,decryptedmsg, key);
//   for (i=0;i<16;i++) if (decryptedmsg[i] != msg[i])  
//     printf("AES-%d decryption failed\n",(key->keylen)*8);
//     failed =1;
  
//   if (failed==0) 
//   {
//     /* Moved start and finish to new location to remove scope issues. */
//     clock_t start, finish;
    
//     start = clock();
//   }
//     for (i=0;i<numofT;i++) {
//       AES_decrypt(cipher,decryptedmsg, key);
//     }
  
//     finish = clock();
    
//     /* Moved seconds to new location to remove scope issues. */
//     double seconds;
    
//     seconds = ((double)(finish - start))/CLOCKS_PER_SEC;
//     printf("%f seconds for %d times of AES-%d decryption\n",seconds,numofT,(key->keylen)*8);    
//   }
// }



static const unsigned char sbox[256] ={
  0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
  0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
  0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
  0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
  0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
  0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
  0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
  0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
  0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
  0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
  0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
  0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
  0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
  0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
  0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
  0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const unsigned char Invsbox[256] ={
  0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
  0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
  0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
  0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
  0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
  0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
  0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
  0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
  0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
  0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
  0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
  0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
  0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
  0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
  0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
  0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};


static const unsigned char Rcon[11] = {0x8d,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36};

aeskey_t aeskey_init(unsigned short kappa) {
  if ((kappa!=128)&&(kappa!=192)&&(kappa!=256)){
    return NULL;
  }
  aeskey_t out;
  out = (aeskey_t) malloc(sizeof(struct AESkey));
  out->keylen= kappa/8;
  out->Nk = kappa/32;
  switch(out->Nk) {
  case 4:
    out->Nr=10;
    out->wLen = 176; 
    break;
  case 6:
    out->Nr=12;
    out->wLen = 208;
    break;
  case 8:
    out->Nr=14;
    out->wLen = 240;
    break;
  default:
    /* Freed out to prevent memory leaks */
    free(out);
    return NULL;
  }
  out->key = (unsigned char *) calloc(kappa/8, sizeof(unsigned char));
  return out;
}


int KeyExpansion(aeskey_t key, unsigned char w[]){
  int i;
  unsigned char temp[4];
  unsigned char tmp;
  unsigned short Nk = key->Nk;
  unsigned short Nr= key->Nr;
  memcpy(w, key->key, 4*Nk*sizeof(unsigned char));
  for (i=Nk; i<4*(Nr+1); i++){
    memcpy(temp, &w[4*(i-1)], 4);
    if ((i % Nk) == 0) {
      tmp = temp[0];
      temp[0]=sbox[temp[1]];
      temp[1]=sbox[temp[2]];
      temp[2]=sbox[temp[3]];
      temp[3]=sbox[tmp];
      temp[0] ^= Rcon[i/Nk];
    } else if ((Nk==8) && ((i%Nk)==4)) {
      temp[0]= sbox[temp[0]];
      temp[1]= sbox[temp[1]];
      temp[2]= sbox[temp[2]];
      temp[3]= sbox[temp[3]];
    }
    w[4*i] = w[4*(i-Nk)] ^ temp[0];
    w[4*i+1] = w[4*(i-Nk)+1] ^ temp[1];
    w[4*i+2] = w[4*(i-Nk)+2] ^ temp[2];
    w[4*i+3] = w[4*(i-Nk)+3] ^ temp[3];
  }
  return 0;
}

// static void SubBytes(unsigned char cipher[]) {
//   int i;
//   for (i=0;i<16;i++) cipher[i]=sbox[cipher[i]];
// }


/* move the cipher[] movements to where the function is called. 
Then, at end, clear the temp variable with free(temp) and declare temp only 
once on first call with appropriate scope.*/ 
// static void ShiftRows(unsigned char cipher[]) {
//   unsigned char temp;
//   temp = cipher[1];
//   cipher[1]=cipher[5];
//   cipher[5]=cipher[9];
//   cipher[9]=cipher[13];
//   cipher[13]=temp;
//   temp=cipher[2];
//   cipher[2]=cipher[10];
//   cipher[10]=temp;
//   temp=cipher[6];
//   cipher[6]=cipher[14];
//   cipher[14]=temp;
//   temp=cipher[15];
//   cipher[15]=cipher[11];
//   cipher[11]=cipher[7];
//   cipher[7]=cipher[3];
//   cipher[3]=temp;  
// }

// static void MixColumns(unsigned char cipher[]) {
//   //int i,j;
//   //unsigned char a[4], b[4];
//   // for (i=0; i<4; i++) {
//   //   memcpy(a,&cipher[4*i], 4);
    
//   //   // for(j=0;j<4;j++) 
//   //   //   b[j]=((a[j]<<1)^(0x1B & (unsigned char)((signed char) a[j] >> 7)));
//   //   b[0]=((a[0]<<1)^(0x1B & (unsigned char)((signed char) a[0] >> 7)));
//   //   b[1]=((a[1]<<1)^(0x1B & (unsigned char)((signed char) a[1] >> 7)));
//   //   b[2]=((a[2]<<1)^(0x1B & (unsigned char)((signed char) a[2] >> 7)));
//   //   b[3]=((a[3]<<1)^(0x1B & (unsigned char)((signed char) a[3] >> 7)));
    
      
//   //   cipher[4*i] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1];
//   //   cipher[4*i+1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2];
//   //   cipher[4*i+2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3];
//   //   cipher[4*i+3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0];
//   // }
//   unsigned char a[4], b[4];
//   //first iteration
//   memcpy(a,&cipher[4*0], 4);
//   b[0]=((a[0]<<1)^(0x1B & (unsigned char)((signed char) a[0] >> 7)));
//   b[1]=((a[1]<<1)^(0x1B & (unsigned char)((signed char) a[1] >> 7)));
//   b[2]=((a[2]<<1)^(0x1B & (unsigned char)((signed char) a[2] >> 7)));
//   b[3]=((a[3]<<1)^(0x1B & (unsigned char)((signed char) a[3] >> 7)));
//   cipher[4*0] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1];
//   cipher[4*0+1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2];
//   cipher[4*0+2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3];
//   cipher[4*0+3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0];
  
//   // second iteration
//   memcpy(a,&cipher[4*1], 4);
//   b[0]=((a[0]<<1)^(0x1B & (unsigned char)((signed char) a[0] >> 7)));
//   b[1]=((a[1]<<1)^(0x1B & (unsigned char)((signed char) a[1] >> 7)));
//   b[2]=((a[2]<<1)^(0x1B & (unsigned char)((signed char) a[2] >> 7)));
//   b[3]=((a[3]<<1)^(0x1B & (unsigned char)((signed char) a[3] >> 7)));
//   cipher[4*1] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1];
//   cipher[4*1+1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2];
//   cipher[4*1+2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3];
//   cipher[4*1+3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0];
  
//   // third iteration 
//   memcpy(a,&cipher[4*2], 4);
//   b[0]=((a[0]<<1)^(0x1B & (unsigned char)((signed char) a[0] >> 7)));
//   b[1]=((a[1]<<1)^(0x1B & (unsigned char)((signed char) a[1] >> 7)));
//   b[2]=((a[2]<<1)^(0x1B & (unsigned char)((signed char) a[2] >> 7)));
//   b[3]=((a[3]<<1)^(0x1B & (unsigned char)((signed char) a[3] >> 7)));
//   cipher[4*2] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1];
//   cipher[4*2+1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2];
//   cipher[4*2+2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3];
//   cipher[4*2+3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0];
  
//   // fourth iteration
//   memcpy(a,&cipher[4*3], 4);
//   b[0]=((a[0]<<1)^(0x1B & (unsigned char)((signed char) a[0] >> 7)));
//   b[1]=((a[1]<<1)^(0x1B & (unsigned char)((signed char) a[1] >> 7)));
//   b[2]=((a[2]<<1)^(0x1B & (unsigned char)((signed char) a[2] >> 7)));
//   b[3]=((a[3]<<1)^(0x1B & (unsigned char)((signed char) a[3] >> 7)));
//   cipher[4*3] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1];
//   cipher[4*3+1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2];
//   cipher[4*3+2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3];
//   cipher[4*3+3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0];

// }

void AES_encrypt(unsigned char plain[], unsigned char cipher[], aeskey_t key) {
  int i,j,k;
  unsigned char w[key->wLen];
  KeyExpansion(key, w);
  memcpy(cipher, plain, 16*sizeof(unsigned char));
  
  // wrote out forloop iterations. 
  //for (i=0;i<16;i++) cipher[i] ^=w[i];
  cipher[0] ^=w[0];
  cipher[1] ^=w[1];
  cipher[2] ^=w[2];
  cipher[3] ^=w[3];
  cipher[4] ^=w[4];
  cipher[5] ^=w[5];
  cipher[6] ^=w[6];
  cipher[7] ^=w[7];
  cipher[8] ^=w[8];
  cipher[9] ^=w[9];
  cipher[10] ^=w[10];
  cipher[11] ^=w[11];
  cipher[12] ^=w[12];
  cipher[13] ^=w[13];
  cipher[14] ^=w[14];
  cipher[15] ^=w[15];
  
  unsigned char temp; // declared out of the for loop scope
  for (k=1; k<key->Nr; k++) {
    // Removed SubBytes fx call and insert manually
    //SubBytes(cipher);
    cipher[0]=sbox[cipher[0]];
    cipher[1]=sbox[cipher[1]];
    cipher[2]=sbox[cipher[2]];
    cipher[3]=sbox[cipher[3]];
    cipher[4]=sbox[cipher[4]];
    cipher[5]=sbox[cipher[5]];
    cipher[6]=sbox[cipher[6]];
    cipher[7]=sbox[cipher[7]];
    cipher[8]=sbox[cipher[8]];
    cipher[9]=sbox[cipher[9]];
    cipher[10]=sbox[cipher[10]];
    cipher[11]=sbox[cipher[11]];
    cipher[12]=sbox[cipher[12]];
    cipher[13]=sbox[cipher[13]];
    cipher[14]=sbox[cipher[14]];
    cipher[15]=sbox[cipher[15]];
    
    // Removed ShiftRows(cipher) fx call and inserted manually. 
    //ShiftRows(cipher);
    temp = cipher[1];
    cipher[1]=cipher[5];
    cipher[5]=cipher[9];
    cipher[9]=cipher[13];
    cipher[13]=temp;
    temp=cipher[2];
    cipher[2]=cipher[10];
    cipher[10]=temp;
    temp=cipher[6];
    cipher[6]=cipher[14];
    cipher[14]=temp;
    temp=cipher[15];
    cipher[15]=cipher[11];
    cipher[11]=cipher[7];
    cipher[7]=cipher[3];
    cipher[3]=temp;  
    
    // Neet to remove MixColumns fx call and insert manually
    //MixColumns(cipher);
    unsigned char a[4], b[4];
    //first iteration
    memcpy(a,&cipher[4*0], 4);
    b[0]=((a[0]<<1)^(0x1B & (unsigned char)((signed char) a[0] >> 7)));
    b[1]=((a[1]<<1)^(0x1B & (unsigned char)((signed char) a[1] >> 7)));
    b[2]=((a[2]<<1)^(0x1B & (unsigned char)((signed char) a[2] >> 7)));
    b[3]=((a[3]<<1)^(0x1B & (unsigned char)((signed char) a[3] >> 7)));
    cipher[4*0] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1];
    cipher[4*0+1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2];
    cipher[4*0+2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3];
    cipher[4*0+3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0];
    
    // second iteration
    memcpy(a,&cipher[4*1], 4);
    b[0]=((a[0]<<1)^(0x1B & (unsigned char)((signed char) a[0] >> 7)));
    b[1]=((a[1]<<1)^(0x1B & (unsigned char)((signed char) a[1] >> 7)));
    b[2]=((a[2]<<1)^(0x1B & (unsigned char)((signed char) a[2] >> 7)));
    b[3]=((a[3]<<1)^(0x1B & (unsigned char)((signed char) a[3] >> 7)));
    cipher[4*1] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1];
    cipher[4*1+1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2];
    cipher[4*1+2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3];
    cipher[4*1+3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0];
    
    // third iteration 
    memcpy(a,&cipher[4*2], 4);
    b[0]=((a[0]<<1)^(0x1B & (unsigned char)((signed char) a[0] >> 7)));
    b[1]=((a[1]<<1)^(0x1B & (unsigned char)((signed char) a[1] >> 7)));
    b[2]=((a[2]<<1)^(0x1B & (unsigned char)((signed char) a[2] >> 7)));
    b[3]=((a[3]<<1)^(0x1B & (unsigned char)((signed char) a[3] >> 7)));
    cipher[4*2] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1];
    cipher[4*2+1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2];
    cipher[4*2+2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3];
    cipher[4*2+3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0];
    
    // fourth iteration
    memcpy(a,&cipher[4*3], 4);
    b[0]=((a[0]<<1)^(0x1B & (unsigned char)((signed char) a[0] >> 7)));
    b[1]=((a[1]<<1)^(0x1B & (unsigned char)((signed char) a[1] >> 7)));
    b[2]=((a[2]<<1)^(0x1B & (unsigned char)((signed char) a[2] >> 7)));
    b[3]=((a[3]<<1)^(0x1B & (unsigned char)((signed char) a[3] >> 7)));
    cipher[4*3] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1];
    cipher[4*3+1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2];
    cipher[4*3+2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3];
    cipher[4*3+3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0];
    
    
    //for (j=0;j<16;j++) cipher[j]^= w[16*k+j];
    cipher[0]^= w[16*k+0];
    cipher[1]^= w[16*k+1];
    cipher[2]^= w[16*k+2];
    cipher[3]^= w[16*k+3];
    cipher[4]^= w[16*k+4];
    cipher[5]^= w[16*k+5];
    cipher[6]^= w[16*k+6];
    cipher[7]^= w[16*k+7];
    cipher[8]^= w[16*k+8];
    cipher[9]^= w[16*k+9];
    cipher[10]^= w[16*k+10];
    cipher[11]^= w[16*k+11];
    cipher[12]^= w[16*k+12];
    cipher[13]^= w[16*k+13];
    cipher[14]^= w[16*k+14];
    cipher[15]^= w[16*k+15];
    
    //free(temp); 
    /* we dont really need this free() since its reassigned every loop and right
    after the loop for its final iteration. If we could free it at the end before 
    that final for loop and/or if we eliminate this function to be all 
    part of main(), then we would need to care more. */ 
  }
  
  // Eliminated another SubBytes fx call. 
  //SubBytes(cipher);
  cipher[0]=sbox[cipher[0]];
  cipher[1]=sbox[cipher[1]];
  cipher[2]=sbox[cipher[2]];
  cipher[3]=sbox[cipher[3]];
  cipher[4]=sbox[cipher[4]];
  cipher[5]=sbox[cipher[5]];
  cipher[6]=sbox[cipher[6]];
  cipher[7]=sbox[cipher[7]];
  cipher[8]=sbox[cipher[8]];
  cipher[9]=sbox[cipher[9]];
  cipher[10]=sbox[cipher[10]];
  cipher[11]=sbox[cipher[11]];
  cipher[12]=sbox[cipher[12]];
  cipher[13]=sbox[cipher[13]];
  cipher[14]=sbox[cipher[14]];
  cipher[15]=sbox[cipher[15]];
  
  //ShiftRows(cipher);
  temp = cipher[1];
  cipher[1]=cipher[5];
  cipher[5]=cipher[9];
  cipher[9]=cipher[13];
  cipher[13]=temp;
  temp=cipher[2];
  cipher[2]=cipher[10];
  cipher[10]=temp;
  temp=cipher[6];
  cipher[6]=cipher[14];
  cipher[14]=temp;
  temp=cipher[15];
  cipher[15]=cipher[11];
  cipher[11]=cipher[7];
  cipher[7]=cipher[3];
  cipher[3]=temp;  
  
  //Turned forloop into not a for loop. 
  // for (i=0;i<16; i++) cipher[i] ^= w[16*(key->Nr)+i];
  cipher[0] ^= w[16*(key->Nr)+0];
  cipher[1] ^= w[16*(key->Nr)+1];
  cipher[2] ^= w[16*(key->Nr)+2];
  cipher[3] ^= w[16*(key->Nr)+3];
  cipher[4] ^= w[16*(key->Nr)+4];
  cipher[5] ^= w[16*(key->Nr)+5];
  cipher[6] ^= w[16*(key->Nr)+6];
  cipher[7] ^= w[16*(key->Nr)+7];
  cipher[8] ^= w[16*(key->Nr)+8];
  cipher[9] ^= w[16*(key->Nr)+9];
  cipher[10] ^= w[16*(key->Nr)+10];
  cipher[11] ^= w[16*(key->Nr)+11];
  cipher[12] ^= w[16*(key->Nr)+12];
  cipher[13] ^= w[16*(key->Nr)+13];
  cipher[14] ^= w[16*(key->Nr)+14];
  cipher[15] ^= w[16*(key->Nr)+15];
  
}

// static void InvShiftRows(unsigned char plain[]) {
//   unsigned char tmp;
//   plain[0]=Invsbox[plain[0]];
//   plain[4]=Invsbox[plain[4]];
//   plain[8]=Invsbox[plain[8]];
//   plain[12]=Invsbox[plain[12]];
//   /* row 1 */
//   tmp=plain[13];
//   plain[13]=Invsbox[plain[9]];
//   plain[9]=Invsbox[plain[5]];
//   plain[5]=Invsbox[plain[1]];
//   plain[1]=Invsbox[tmp];
//   /* row 2 */
//   tmp = plain[2];
//   plain[2]=Invsbox[plain[10]];
//   plain[10]=Invsbox[tmp];
//   tmp = plain[6];
//   plain[6]=Invsbox[plain[14]];
//   plain[14]=Invsbox[tmp];
//   /* row 3 */
//   tmp=plain[3];
//   plain[3]=Invsbox[plain[7]];
//   plain[7]=Invsbox[plain[11]];
//   plain[11]=Invsbox[plain[15]];
//   plain[15]=Invsbox[tmp];
// }

static unsigned char f256times2(unsigned char a) {
  return ((a<<1) ^ (0x1B & (unsigned char)((signed char) a >> 7)));
}

// static unsigned char f256mul(unsigned char b, unsigned char a) {
//   switch(b) {
//   case 0x09:
//     return f256times2(f256times2(f256times2(a))) ^ a;
//   case 0x0b:
//     return f256times2(a^f256times2(f256times2(a))) ^a;
//   case 0x0d:
//     return f256times2(f256times2(a^f256times2(a))) ^a;
//   case 0x0e:
//     return f256times2(a^f256times2(a^f256times2(a)));
//   }
//   return '\0';
// }

/* after eliminating the for loop in this, we should move it to the AES_decrypt fx*/
// static void InvMixColumns(unsigned char plain[]) {
//   //int i;
//   unsigned char a[4];
//   /* Eliminating for loops will probably be a big improvement */
//   // for (i=0; i<4; i++) {
//   //   memcpy(a, plain+4*i, 4*sizeof(unsigned char));
//   //   plain[4*i]   = f256mul(0x0e,a[0])^f256mul(0x0b,a[1])^f256mul(0x0d,a[2])^f256mul(0x09,a[3]);
//   //   plain[4*i+1] = f256mul(0x09,a[0])^f256mul(0x0e,a[1])^f256mul(0x0b,a[2])^f256mul(0x0d,a[3]); 
//   //   plain[4*i+2] = f256mul(0x0d,a[0])^f256mul(0x09,a[1])^f256mul(0x0e,a[2])^f256mul(0x0b,a[3]);
//   //   plain[4*i+3] = f256mul(0x0b,a[0])^f256mul(0x0d,a[1])^f256mul(0x09,a[2])^f256mul(0x0e,a[3]);
//   // }
  
//     memcpy(a, plain+4*0, 4*sizeof(unsigned char));
//     plain[4*0]   = f256mul(0x0e,a[0])^f256mul(0x0b,a[1])^f256mul(0x0d,a[2])^f256mul(0x09,a[3]);
//     plain[4*0+1] = f256mul(0x09,a[0])^f256mul(0x0e,a[1])^f256mul(0x0b,a[2])^f256mul(0x0d,a[3]); 
//     plain[4*0+2] = f256mul(0x0d,a[0])^f256mul(0x09,a[1])^f256mul(0x0e,a[2])^f256mul(0x0b,a[3]);
//     plain[4*0+3] = f256mul(0x0b,a[0])^f256mul(0x0d,a[1])^f256mul(0x09,a[2])^f256mul(0x0e,a[3]);
    
//     memcpy(a, plain+4*1, 4*sizeof(unsigned char));
//     plain[4*1]   = f256mul(0x0e,a[0])^f256mul(0x0b,a[1])^f256mul(0x0d,a[2])^f256mul(0x09,a[3]);
//     plain[4*1+1] = f256mul(0x09,a[0])^f256mul(0x0e,a[1])^f256mul(0x0b,a[2])^f256mul(0x0d,a[3]); 
//     plain[4*1+2] = f256mul(0x0d,a[0])^f256mul(0x09,a[1])^f256mul(0x0e,a[2])^f256mul(0x0b,a[3]);
//     plain[4*1+3] = f256mul(0x0b,a[0])^f256mul(0x0d,a[1])^f256mul(0x09,a[2])^f256mul(0x0e,a[3]);
    
//     memcpy(a, plain+4*2, 4*sizeof(unsigned char));
//     plain[4*2]   = f256mul(0x0e,a[0])^f256mul(0x0b,a[1])^f256mul(0x0d,a[2])^f256mul(0x09,a[3]);
//     plain[4*2+1] = f256mul(0x09,a[0])^f256mul(0x0e,a[1])^f256mul(0x0b,a[2])^f256mul(0x0d,a[3]); 
//     plain[4*2+2] = f256mul(0x0d,a[0])^f256mul(0x09,a[1])^f256mul(0x0e,a[2])^f256mul(0x0b,a[3]);
//     plain[4*2+3] = f256mul(0x0b,a[0])^f256mul(0x0d,a[1])^f256mul(0x09,a[2])^f256mul(0x0e,a[3]);
    
//     memcpy(a, plain+4*3, 4*sizeof(unsigned char));
//     plain[4*3]   = f256mul(0x0e,a[0])^f256mul(0x0b,a[1])^f256mul(0x0d,a[2])^f256mul(0x09,a[3]);
//     plain[4*3+1] = f256mul(0x09,a[0])^f256mul(0x0e,a[1])^f256mul(0x0b,a[2])^f256mul(0x0d,a[3]); 
//     plain[4*3+2] = f256mul(0x0d,a[0])^f256mul(0x09,a[1])^f256mul(0x0e,a[2])^f256mul(0x0b,a[3]);
//     plain[4*3+3] = f256mul(0x0b,a[0])^f256mul(0x0d,a[1])^f256mul(0x09,a[2])^f256mul(0x0e,a[3]);
// }


void AES_decrypt(unsigned char cipher[], unsigned char plain[], aeskey_t key) {
  int i,j;
  unsigned char *w;
  // changed calloc to malloc as malloc is more effecient. 
  w=malloc(key->wLen * sizeof(unsigned char));
  // KeyExpansion(key, w);
  
  unsigned char temp[4];
  unsigned char tmp;
  unsigned short Nk = key->Nk;
  unsigned short Nr= key->Nr;
  memcpy(w, key->key, 4*Nk*sizeof(unsigned char));
  for (i=Nk; i<4*(Nr+1); i++){
    memcpy(temp, &w[4*(i-1)], 4);
    if ((i % Nk) == 0) {
      tmp = temp[0];
      temp[0]=sbox[temp[1]];
      temp[1]=sbox[temp[2]];
      temp[2]=sbox[temp[3]];
      temp[3]=sbox[tmp];
      temp[0] ^= Rcon[i/Nk];
    } else if ((Nk==8) && ((i%Nk)==4)) {
      temp[0]= sbox[temp[0]];
      temp[1]= sbox[temp[1]];
      temp[2]= sbox[temp[2]];
      temp[3]= sbox[temp[3]];
    }
    
    w[4*i] = w[4*(i-Nk)] ^ temp[0];
    w[4*i+1] = w[4*(i-Nk)+1] ^ temp[1];
    w[4*i+2] = w[4*(i-Nk)+2] ^ temp[2];
    w[4*i+3] = w[4*(i-Nk)+3] ^ temp[3];
  }
  
  memcpy(plain, cipher, 16*sizeof(unsigned char));
  // for (i=0;i<16;i++) plain[i] ^=w[16*(key->Nr)+i];
  
  plain[0] ^=w[16*(key->Nr)+0];
  plain[1] ^=w[16*(key->Nr)+1];
  plain[2] ^=w[16*(key->Nr)+2];
  plain[3] ^=w[16*(key->Nr)+3];
  plain[4] ^=w[16*(key->Nr)+4];
  plain[5] ^=w[16*(key->Nr)+5];
  plain[6] ^=w[16*(key->Nr)+6];
  plain[7] ^=w[16*(key->Nr)+7];
  plain[8] ^=w[16*(key->Nr)+8];
  plain[9] ^=w[16*(key->Nr)+9];
  plain[10] ^=w[16*(key->Nr)+10];
  plain[11] ^=w[16*(key->Nr)+11];
  plain[12] ^=w[16*(key->Nr)+12];
  plain[13] ^=w[16*(key->Nr)+13];
  plain[14] ^=w[16*(key->Nr)+14];
  plain[15] ^=w[16*(key->Nr)+15];
  
  // InvShiftRows(plain);
  
  plain[0]=Invsbox[plain[0]];
  plain[4]=Invsbox[plain[4]];
  plain[8]=Invsbox[plain[8]];
  plain[12]=Invsbox[plain[12]];
  /* row 1 */
  tmp=plain[13];
  plain[13]=Invsbox[plain[9]];
  plain[9]=Invsbox[plain[5]];
  plain[5]=Invsbox[plain[1]];
  plain[1]=Invsbox[tmp];
   /* row 2 */
  tmp = plain[2];
  plain[2]=Invsbox[plain[10]];
  plain[10]=Invsbox[tmp];
  tmp = plain[6];
  plain[6]=Invsbox[plain[14]];
  plain[14]=Invsbox[tmp];
  /* row 3 */
  tmp=plain[3];
  plain[3]=Invsbox[plain[7]];
  plain[7]=Invsbox[plain[11]];
  plain[11]=Invsbox[plain[15]];
  plain[15]=Invsbox[tmp];
  
  unsigned char a[4];
  
  // TODO: eliminate nested forloop. or all the for loops.  
  for(i=key->Nr-1;i>0;i--)  {
    // for (j=0;j<16;j++) plain[j] ^=w[16*i+j];
    // InvMixColumns(plain);
    
    plain[0] ^=w[16*i+0];
    plain[1] ^=w[16*i+1];
    plain[2] ^=w[16*i+2];
    plain[3] ^=w[16*i+3];
    plain[4] ^=w[16*i+4];
    plain[5] ^=w[16*i+5];
    plain[6] ^=w[16*i+6];
    plain[7] ^=w[16*i+7];
    plain[8] ^=w[16*i+8];
    plain[9] ^=w[16*i+9];
    plain[10] ^=w[16*i+10];
    plain[11] ^=w[16*i+11];
    plain[12] ^=w[16*i+12];
    plain[13] ^=w[16*i+13];
    plain[14] ^=w[16*i+14];
    plain[15] ^=w[16*i+15];
    
    memcpy(a, plain+4*0, 4*sizeof(unsigned char));
    plain[4*0]   = f256times2(a[0]^f256times2(a[0]^f256times2(a[0])))^f256times2(a[1]^f256times2(f256times2(a[1]))) ^a[1]^f256times2(f256times2(a[2]^f256times2(a[2]))) ^a[2]^f256times2(f256times2(f256times2(a[3]))) ^ a[3];
    plain[4*0+1] = f256times2(f256times2(f256times2(a[0]))) ^ a[0]^f256times2(a[1]^f256times2(a[1]^f256times2(a[1])))^f256times2(a[2]^f256times2(f256times2(a[2]))) ^a[2]^f256times2(f256times2(a[3]^f256times2(a[3]))) ^a[3];
    plain[4*0+2] = f256times2(f256times2(a[0]^f256times2(a[0]))) ^a[0]^f256times2(f256times2(f256times2(a[1]))) ^ a[1]^f256times2(a[2]^f256times2(a[2]^f256times2(a[2])))^f256times2(a[3]^f256times2(f256times2(a[3]))) ^a[3];
    plain[4*0+3] = f256times2(a[0]^f256times2(f256times2(a[0]))) ^a[0]^f256times2(f256times2(a[1]^f256times2(a[1]))) ^a[1]^f256times2(f256times2(f256times2(a[2]))) ^ a[2]^f256times2(a[3]^f256times2(a[3]^f256times2(a[3])));
    
    memcpy(a, plain+4*1, 4*sizeof(unsigned char));
    plain[4*1]   = f256times2(a[0]^f256times2(a[0]^f256times2(a[0])))^f256times2(a[1]^f256times2(f256times2(a[1]))) ^a[1]^f256times2(f256times2(a[2]^f256times2(a[2]))) ^a[2]^f256times2(f256times2(f256times2(a[3]))) ^ a[3];
    plain[4*1+1] = f256times2(f256times2(f256times2(a[0]))) ^ a[0]^f256times2(a[1]^f256times2(a[1]^f256times2(a[1])))^f256times2(a[2]^f256times2(f256times2(a[2]))) ^a[2]^f256times2(f256times2(a[3]^f256times2(a[3]))) ^a[3];
    plain[4*1+2] = f256times2(f256times2(a[0]^f256times2(a[0]))) ^a[0]^f256times2(f256times2(f256times2(a[1]))) ^ a[1]^f256times2(a[2]^f256times2(a[2]^f256times2(a[2])))^f256times2(a[3]^f256times2(f256times2(a[3]))) ^a[3];
    plain[4*1+3] = f256times2(a[0]^f256times2(f256times2(a[0]))) ^a[0]^f256times2(f256times2(a[1]^f256times2(a[1]))) ^a[1]^f256times2(f256times2(f256times2(a[2]))) ^ a[2]^f256times2(a[3]^f256times2(a[3]^f256times2(a[3])));
    
    memcpy(a, plain+4*2, 4*sizeof(unsigned char));
    plain[4*2]   = f256times2(a[0]^f256times2(a[0]^f256times2(a[0])))^f256times2(a[1]^f256times2(f256times2(a[1]))) ^a[1]^f256times2(f256times2(a[2]^f256times2(a[2]))) ^a[2]^f256times2(f256times2(f256times2(a[3]))) ^ a[3];
    plain[4*2+1] = f256times2(f256times2(f256times2(a[0]))) ^ a[0]^f256times2(a[1]^f256times2(a[1]^f256times2(a[1])))^f256times2(a[2]^f256times2(f256times2(a[2]))) ^a[2]^f256times2(f256times2(a[3]^f256times2(a[3]))) ^a[3];
    plain[4*2+2] = f256times2(f256times2(a[0]^f256times2(a[0]))) ^a[0]^f256times2(f256times2(f256times2(a[1]))) ^ a[1]^f256times2(a[2]^f256times2(a[2]^f256times2(a[2])))^f256times2(a[3]^f256times2(f256times2(a[3]))) ^a[3];
    plain[4*2+3] = f256times2(a[0]^f256times2(f256times2(a[0]))) ^a[0]^f256times2(f256times2(a[1]^f256times2(a[1]))) ^a[1]^f256times2(f256times2(f256times2(a[2]))) ^ a[2]^f256times2(a[3]^f256times2(a[3]^f256times2(a[3])));
    
    memcpy(a, plain+4*3, 4*sizeof(unsigned char));
    plain[4*3]   = f256times2(a[0]^f256times2(a[0]^f256times2(a[0])))^f256times2(a[1]^f256times2(f256times2(a[1]))) ^a[1]^f256times2(f256times2(a[2]^f256times2(a[2]))) ^a[2]^f256times2(f256times2(f256times2(a[3]))) ^ a[3];
    plain[4*3+1] = f256times2(f256times2(f256times2(a[0]))) ^ a[0]^f256times2(a[1]^f256times2(a[1]^f256times2(a[1])))^f256times2(a[2]^f256times2(f256times2(a[2]))) ^a[2]^f256times2(f256times2(a[3]^f256times2(a[3]))) ^a[3];
    plain[4*3+2] = f256times2(f256times2(a[0]^f256times2(a[0]))) ^a[0]^f256times2(f256times2(f256times2(a[1]))) ^ a[1]^f256times2(a[2]^f256times2(a[2]^f256times2(a[2])))^f256times2(a[3]^f256times2(f256times2(a[3]))) ^a[3];
    plain[4*3+3] = f256times2(a[0]^f256times2(f256times2(a[0]))) ^a[0]^f256times2(f256times2(a[1]^f256times2(a[1]))) ^a[1]^f256times2(f256times2(f256times2(a[2]))) ^ a[2]^f256times2(a[3]^f256times2(a[3]^f256times2(a[3])));
    
    // InvShiftRows(plain);
    
    unsigned char tmp;
    plain[0]=Invsbox[plain[0]];
    plain[4]=Invsbox[plain[4]];
    plain[8]=Invsbox[plain[8]];
    plain[12]=Invsbox[plain[12]];
    /* row 1 */
    tmp=plain[13];
    plain[13]=Invsbox[plain[9]];
    plain[9]=Invsbox[plain[5]];
    plain[5]=Invsbox[plain[1]];
    plain[1]=Invsbox[tmp];
     /* row 2 */
    tmp = plain[2];
    plain[2]=Invsbox[plain[10]];
    plain[10]=Invsbox[tmp];
    tmp = plain[6];
    plain[6]=Invsbox[plain[14]];
    plain[14]=Invsbox[tmp];
    /* row 3 */
    tmp=plain[3];
    plain[3]=Invsbox[plain[7]];
    plain[7]=Invsbox[plain[11]];
    plain[11]=Invsbox[plain[15]];
    plain[15]=Invsbox[tmp];
  }
  
  // for (j=0;j<16;j++) plain[j] ^=w[j];
  
  plain[0] ^=w[0];
  plain[1] ^=w[1];
  plain[2] ^=w[2];
  plain[3] ^=w[3];
  plain[4] ^=w[4];
  plain[5] ^=w[5];
  plain[6] ^=w[6];
  plain[7] ^=w[7];
  plain[8] ^=w[8];
  plain[9] ^=w[9];
  plain[10] ^=w[10];
  plain[11] ^=w[11];
  plain[12] ^=w[12];
  plain[13] ^=w[13];
  plain[14] ^=w[14];
  plain[15] ^=w[15];
  
  /* Freed w to prevent memory leaks */
  free(w);
  return;
}
