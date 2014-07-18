/*
 * operMode.cpp
 *  分组密码的工作模式
 *  Created on: 2013-10-17
 *  Author: star qiu
 */

#include "Des.h"
#include <stdlib.h>
#include <stdio.h>

void enECB(char* plainTxt,int len,char* key,char* result);//电码本模式加密
void deECB(char* ciperTxt,int len,char* key,char* result);//电码本模式解密
void enCBC(char* plainTxt,int len,char* key,char* IV,char* result);//密文分组链接模式加密
void deCBC(char* ciperTxt,int len,char* key,char* IV,char* result);//密文分组链接模式解密
void enCFB(char* plainTxt,int len,char* key,char* IV,int s,char* result);//密文反馈模式加密
void deCFB(char* ciperTxt,int len,char* key,char* IV,int s,char* result);//密文反馈模式解密
void xor_16(char* data1,char* data2,char* result);//两个16位的16进制数异或
void xor_s(char* data1,char* data2,char* result,int s);//两个16进制数异或s位
//void padding(char* data,char* result);//数据填充
#define MAX_LENGTH 1024
#define LENTH_16 16
/*
int main(int argc,char** argv){
	
	
	char* key = (char*) malloc(LENTH_16*sizeof(char));
	char* IV = (char*) malloc(LENTH_16*sizeof(char));
	char* pLen = (char*) malloc(4*sizeof(char));
	char* input = (char*) malloc(MAX_LENGTH*sizeof(char));
	for(int i =0;i<MAX_LENGTH;i++){
		*(input+i)='0';
	}
	int len = 0;	
	char* plainTxt;
	char* ciperTxt;

	char* opr =(char*)malloc(sizeof(char));//操作
	while(true){
		printf("请选择您需要进行的操作：\n1 ECB加密\n2 ECB解密\n\n3 CBC加密\n4 CB解密\n\n5 CFB加密\n6 CFB解密\n\n0 退出\n");
		scanf("%s", opr);
		switch(*opr){
			case '0':
				return 0;
			case '1':
				printf("请输入要加密的数据数据长度（16进制，为16的倍数）：\n");
				scanf("%s",pLen);
				len = atoi(pLen);
				plainTxt = (char*) malloc(len*sizeof(char));
				ciperTxt = (char*) malloc(len*sizeof(char));
				printf("请输入%d位16进制明文(超过则截取,不足则补0):\n",len);
				scanf("%s",input);
				strCopy(input,plainTxt,len);
				printf("请输入长度为%d位的16进制密钥(超过则截取,不足则补0)：\n",LENTH_16);
				scanf("%s",input);
				strCopy(input,key,LENTH_16);
				enECB(plainTxt,len,key,ciperTxt);
				break;
			case '2':
				printf("请输入要解密的数据数据长度（16进制，为16的倍数）：\n");
				scanf("%s",pLen);
				len = atoi(pLen);
				plainTxt = (char*) malloc(len*sizeof(char));
				ciperTxt = (char*) malloc(len*sizeof(char));
				printf("请输入%d位16进制密文(超过则截取,不足则补0):\n",len);
				scanf("%s",input);
				strCopy(input,ciperTxt,len);
				printf("请输入长度为%d位的16进制密钥(超过则截取,不足则补0)：\n",LENTH_16);
				scanf("%s",input);
				strCopy(input,key,LENTH_16);
				deECB(ciperTxt,len,key,plainTxt);
				break;
			case '3':
				printf("请输入要加密的数据数据长度（16进制，为16的倍数）：\n");
				scanf("%s",pLen);
				len = atoi(pLen);
				plainTxt = (char*) malloc(len*sizeof(char));
				ciperTxt = (char*) malloc(len*sizeof(char));
				printf("请输入%d位16进制明文(超过则截取,不足则补0):\n",len);
				scanf("%s",input);
				strCopy(input,plainTxt,len);
				printf("请输入长度为%d位的16进制密钥(超过则截取,不足则补0)：\n",LENTH_16);
				scanf("%s",input);
				strCopy(input,key,LENTH_16);
				printf("请输入长度为%d位的16进制初始向量（IV (超过则截取,不足则补0)）:\n",LENTH_16);
				scanf("%s",input);
				strCopy(input,IV,LENTH_16);
				enCBC(plainTxt,len,key,IV,ciperTxt);
				break;
			case '4':
				printf("请输入要解密的数据数据长度（16进制，为16的倍数）：\n");
				scanf("%s",pLen);
				len = atoi(pLen);
				plainTxt = (char*) malloc(len*sizeof(char));
				ciperTxt = (char*) malloc(len*sizeof(char));
				printf("请输入%d位16进制密文(超过则截取,不足则补0):\n",len);
				scanf("%s",input);
				strCopy(input,ciperTxt,len);
				printf("请输入长度为%d位的16进制密钥(超过则截取,不足则补0)：\n",LENTH_16);
				scanf("%s",input);
				strCopy(input,key,LENTH_16);
				printf("请输入长度为%d位的16进制初始向量（IV (超过则截取,不足则补0)）:\n",LENTH_16);
				scanf("%s",input);
				strCopy(input,IV,LENTH_16);
				deCBC(ciperTxt,len,key,IV,plainTxt);
				break;
			case '5':
				printf("请输入要加密的数据数据长度（16进制，为16的倍数）：\n");
				scanf("%s",pLen);
				len = atoi(pLen);
				plainTxt = (char*) malloc(len*sizeof(char));
				ciperTxt = (char*) malloc(len*sizeof(char));
				printf("请输入%d位16进制明文(超过则截取,不足则补0):\n",len);
				scanf("%s",input);
				strCopy(input,plainTxt,len);
				printf("请输入长度为%d位的16进制密钥(超过则截取,不足则补0)：\n",LENTH_16);
				scanf("%s",input);
				strCopy(input,key,LENTH_16);
				printf("请输入长度为%d位的16进制初始向量（IV (超过则截取,不足则补0)）:\n",LENTH_16);
				scanf("%s",input);
				strCopy(input,IV,LENTH_16);
				enCFB(plainTxt,len, key, IV, 2, ciperTxt);
				break;
			case '6':
				printf("请输入要解密的数据数据长度（16进制，为16的倍数）：\n");
				scanf("%s",pLen);
				len = atoi(pLen);
				plainTxt = (char*) malloc(len*sizeof(char));
				ciperTxt = (char*) malloc(len*sizeof(char));
				printf("请输入%d位16进制密文(超过则截取,不足则补0):\n",len);
				scanf("%s",input);
				strCopy(input,ciperTxt,len);
				printf("请输入长度为%d位的16进制密钥(超过则截取,不足则补0)：\n",LENTH_16);
				scanf("%s",input);
				strCopy(input,key,LENTH_16);
				printf("请输入长度为%d位的16进制初始向量（IV (超过则截取,不足则补0)）:\n",LENTH_16);
				scanf("%s",input);
				strCopy(input,IV,LENTH_16);
				deCFB(ciperTxt,len, key, IV,2,plainTxt);
				break;
			default:
				break;
		}
	}
	system("pause");
	return 0;
}*/

/*
 * 电码本模式加密
 * @param plainTxt 明文
 * @param len 明文长度(16进制)
 * @param key 16位16进制密钥
 * @param result 返回加密结果
 */
void enECB(char* plainTxt,int len,char* key,char* result){
	printf("电码本模式加密:\n");
	int blockNum = len/16;//明文块数
	for(int i=0;i<blockNum;i++){
		enDES(plainTxt+i*16,key,result+i*16);
	}
	prtCharPoint(result,len);
}

/*
 * 电码本模式解密
 * @param ciperTxt 密文
 * @param len 密文长度(16进制)
 * @param key 16位16进制密钥
 * @param result 返回解密结果
 */
void deECB(char* ciperTxt,int len,char* key,char* result){
	printf("电码本模式解密:\n");
	int blockNum = len/16;//明文块数
	for(int i=0;i<blockNum;i++){
		deDES(ciperTxt+i*16,key,result+i*16);
	}
	prtCharPoint(result,len);
}

/*
 * 密文分组链接模式加密
 * @param plainTxt 明文
 * @param len 明文长度(16进制)
 * @param key 16位16进制密钥
 * @param IV 16位16进制初始向量
 * @param result 返回加密结果
 */
void enCBC(char* plainTxt,int len,char* key,char* IV,char* result){
	printf("密文分组链接模式加密:\n");
	char* temp = (char*) malloc(17*sizeof(char));
	int blockNum = len/16;//明文块数
	xor_16(plainTxt,IV,temp);
	enDES(temp,key,result);
	for(int i=1;i<blockNum;i++){
		xor_16(plainTxt+i*16,result+(i-1)*16,temp);
		enDES(temp,key,result+i*16);
	}
	free(temp);
	prtCharPoint(result,len);
}

/*
 * 密文分组链接模式解密
 * @param ciperTxt 密文
 * @param len 密文长度(16进制)
 * @param key 16位16进制密钥
 * @param IV 16位16进制初始向量
 * @param result 返回解密结果
 */
void deCBC(char* ciperTxt,int len,char* key,char* IV,char* result){
	printf("密文分组链接模式解密:\n");
	int blockNum = len/16;//明文块数
	char* temp = (char*) malloc(17*sizeof(char));
	deDES(ciperTxt,key,temp);
	xor_16(temp,IV,result);
	for(int i=1;i<blockNum;i++){
		deDES(ciperTxt+i*16,key,temp);
		xor_16(temp,ciperTxt+(i-1)*16,result+i*16);
	}
	free(temp);
	prtCharPoint(result,len);
}
/*
 * 密文反馈模式加密
 * @param plainTxt 明文
 * @param len 明文长度(16进制)
 * @param key 16位16进制密钥
 * @param IV 16位16进制初始向量
 * @param s 传输单元s位16进制位 ，一般为2，即表示传输1字节
 * @param result 返回加密结果
 */
void enCFB(char* plainTxt,int len,char* key,char* IV,int s,char* result){
	printf("密文反馈模式加密:\n");
	int blockNum = len/s;//明文块数
	char* temp = (char*) malloc(16*sizeof(char));//分组为b=64位 16位16进制数组
	for(int i=0;i<blockNum;i++){
		enDES(IV,key,temp);
		xor_s(plainTxt+i*s,temp,result+i*s,s*4);
		//IV左移s位，并将C(i)拼接到IV尾s位,得到新的IV
		for(int j=0;j<16-s;j++){
			*(IV+j)=*(IV+j+s);
		}
		for(int k=0;k<s;k++){
			*(IV+16+k-s)=*(result+i*s+k);
		}
	}
	prtCharPoint(result,len);
}

/*
 * 密文反馈模式解密
 * @param ciperTxt 密文
 * @param len 密文长度(16进制)
 * @param key 16位16进制密钥
 * @param IV 初始向量
 * @param s 传输单元s位16进制位，一般为2，即表示传输1字节
 * @param result 返回解密结果
 */
void deCFB(char* ciperTxt,int len,char* key,char* IV,int s,char* result){
	printf("密文反馈模式解密:\n");
	int blockNum = len/s;//明文块数
	char* temp = (char*) malloc(16*sizeof(char));//分组为b=64位 16位16进制数组
	for(int i=0;i<blockNum;i++){
		enDES(IV,key,temp);
		xor_s(ciperTxt+i*s,temp,result+i*s,s*4);
		//IV左移s位，并将C(i)拼接到IV尾s位,得到新的IV
		for(int j=0;j<16-s;j++){
			*(IV+j)=*(IV+j+s);
		}
		for(int k=0;k<s;k++){
			*(IV+16+k-s)=*(ciperTxt+i*s+k);
		}
	}
	prtCharPoint(result,len);
}

/*
 * 两个16位的16进制数异或
 * @param data1 16位的16进制数
 * @param data2 16位的16进制数
 * @param result 16位的16进制数
 */
void xor_16(char* data1,char* data2,char* result){
	char* data1_64 = (char*)malloc(64*sizeof(char));
	char* data2_64 = (char*)malloc(64*sizeof(char));
	hex2Binary(data1,16,data1_64);
	hex2Binary(data2,16,data2_64);
	for(int i = 0;i<64;i++){
		data1_64[i]=data1_64[i]^data2_64[i];
	}
	binary2Hex(data1_64,result,64);
	free(data1_64);
	free(data2_64);
}

/*
 * 两个len位的16进制数异或
 * @param data1 16位的16进制数
 * @param data2 16位的16进制数
 * @param result 16位的16进制数
 * @param s 需要异或的位数(2进制)
 */
void xor_s(char* data1,char* data2,char* result,int s){
	char* data1_s = (char*)malloc(s*sizeof(char));
	char* data2_s = (char*)malloc(s*sizeof(char));
	hex2Binary(data1,s/4,data1_s);
	hex2Binary(data2,s/4,data2_s);
	for(int i = 0;i<s;i++){
		data1_s[i]=data1_s[i]^data2_s[i];
	}
	binary2Hex(data1_s,result,s);
	free(data1_s);
	free(data2_s);
}
