/*
 * operMode.cpp
 *  ��������Ĺ���ģʽ
 *  Created on: 2013-10-17
 *  Author: star qiu
 */

#include "Des.h"
#include <stdlib.h>
#include <stdio.h>

void enECB(char* plainTxt,int len,char* key,char* result);//���뱾ģʽ����
void deECB(char* ciperTxt,int len,char* key,char* result);//���뱾ģʽ����
void enCBC(char* plainTxt,int len,char* key,char* IV,char* result);//���ķ�������ģʽ����
void deCBC(char* ciperTxt,int len,char* key,char* IV,char* result);//���ķ�������ģʽ����
void enCFB(char* plainTxt,int len,char* key,char* IV,int s,char* result);//���ķ���ģʽ����
void deCFB(char* ciperTxt,int len,char* key,char* IV,int s,char* result);//���ķ���ģʽ����
void xor_16(char* data1,char* data2,char* result);//����16λ��16���������
void xor_s(char* data1,char* data2,char* result,int s);//����16���������sλ
//void padding(char* data,char* result);//�������
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

	char* opr =(char*)malloc(sizeof(char));//����
	while(true){
		printf("��ѡ������Ҫ���еĲ�����\n1 ECB����\n2 ECB����\n\n3 CBC����\n4 CB����\n\n5 CFB����\n6 CFB����\n\n0 �˳�\n");
		scanf("%s", opr);
		switch(*opr){
			case '0':
				return 0;
			case '1':
				printf("������Ҫ���ܵ��������ݳ��ȣ�16���ƣ�Ϊ16�ı�������\n");
				scanf("%s",pLen);
				len = atoi(pLen);
				plainTxt = (char*) malloc(len*sizeof(char));
				ciperTxt = (char*) malloc(len*sizeof(char));
				printf("������%dλ16��������(�������ȡ,������0):\n",len);
				scanf("%s",input);
				strCopy(input,plainTxt,len);
				printf("�����볤��Ϊ%dλ��16������Կ(�������ȡ,������0)��\n",LENTH_16);
				scanf("%s",input);
				strCopy(input,key,LENTH_16);
				enECB(plainTxt,len,key,ciperTxt);
				break;
			case '2':
				printf("������Ҫ���ܵ��������ݳ��ȣ�16���ƣ�Ϊ16�ı�������\n");
				scanf("%s",pLen);
				len = atoi(pLen);
				plainTxt = (char*) malloc(len*sizeof(char));
				ciperTxt = (char*) malloc(len*sizeof(char));
				printf("������%dλ16��������(�������ȡ,������0):\n",len);
				scanf("%s",input);
				strCopy(input,ciperTxt,len);
				printf("�����볤��Ϊ%dλ��16������Կ(�������ȡ,������0)��\n",LENTH_16);
				scanf("%s",input);
				strCopy(input,key,LENTH_16);
				deECB(ciperTxt,len,key,plainTxt);
				break;
			case '3':
				printf("������Ҫ���ܵ��������ݳ��ȣ�16���ƣ�Ϊ16�ı�������\n");
				scanf("%s",pLen);
				len = atoi(pLen);
				plainTxt = (char*) malloc(len*sizeof(char));
				ciperTxt = (char*) malloc(len*sizeof(char));
				printf("������%dλ16��������(�������ȡ,������0):\n",len);
				scanf("%s",input);
				strCopy(input,plainTxt,len);
				printf("�����볤��Ϊ%dλ��16������Կ(�������ȡ,������0)��\n",LENTH_16);
				scanf("%s",input);
				strCopy(input,key,LENTH_16);
				printf("�����볤��Ϊ%dλ��16���Ƴ�ʼ������IV (�������ȡ,������0)��:\n",LENTH_16);
				scanf("%s",input);
				strCopy(input,IV,LENTH_16);
				enCBC(plainTxt,len,key,IV,ciperTxt);
				break;
			case '4':
				printf("������Ҫ���ܵ��������ݳ��ȣ�16���ƣ�Ϊ16�ı�������\n");
				scanf("%s",pLen);
				len = atoi(pLen);
				plainTxt = (char*) malloc(len*sizeof(char));
				ciperTxt = (char*) malloc(len*sizeof(char));
				printf("������%dλ16��������(�������ȡ,������0):\n",len);
				scanf("%s",input);
				strCopy(input,ciperTxt,len);
				printf("�����볤��Ϊ%dλ��16������Կ(�������ȡ,������0)��\n",LENTH_16);
				scanf("%s",input);
				strCopy(input,key,LENTH_16);
				printf("�����볤��Ϊ%dλ��16���Ƴ�ʼ������IV (�������ȡ,������0)��:\n",LENTH_16);
				scanf("%s",input);
				strCopy(input,IV,LENTH_16);
				deCBC(ciperTxt,len,key,IV,plainTxt);
				break;
			case '5':
				printf("������Ҫ���ܵ��������ݳ��ȣ�16���ƣ�Ϊ16�ı�������\n");
				scanf("%s",pLen);
				len = atoi(pLen);
				plainTxt = (char*) malloc(len*sizeof(char));
				ciperTxt = (char*) malloc(len*sizeof(char));
				printf("������%dλ16��������(�������ȡ,������0):\n",len);
				scanf("%s",input);
				strCopy(input,plainTxt,len);
				printf("�����볤��Ϊ%dλ��16������Կ(�������ȡ,������0)��\n",LENTH_16);
				scanf("%s",input);
				strCopy(input,key,LENTH_16);
				printf("�����볤��Ϊ%dλ��16���Ƴ�ʼ������IV (�������ȡ,������0)��:\n",LENTH_16);
				scanf("%s",input);
				strCopy(input,IV,LENTH_16);
				enCFB(plainTxt,len, key, IV, 2, ciperTxt);
				break;
			case '6':
				printf("������Ҫ���ܵ��������ݳ��ȣ�16���ƣ�Ϊ16�ı�������\n");
				scanf("%s",pLen);
				len = atoi(pLen);
				plainTxt = (char*) malloc(len*sizeof(char));
				ciperTxt = (char*) malloc(len*sizeof(char));
				printf("������%dλ16��������(�������ȡ,������0):\n",len);
				scanf("%s",input);
				strCopy(input,ciperTxt,len);
				printf("�����볤��Ϊ%dλ��16������Կ(�������ȡ,������0)��\n",LENTH_16);
				scanf("%s",input);
				strCopy(input,key,LENTH_16);
				printf("�����볤��Ϊ%dλ��16���Ƴ�ʼ������IV (�������ȡ,������0)��:\n",LENTH_16);
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
 * ���뱾ģʽ����
 * @param plainTxt ����
 * @param len ���ĳ���(16����)
 * @param key 16λ16������Կ
 * @param result ���ؼ��ܽ��
 */
void enECB(char* plainTxt,int len,char* key,char* result){
	printf("���뱾ģʽ����:\n");
	int blockNum = len/16;//���Ŀ���
	for(int i=0;i<blockNum;i++){
		enDES(plainTxt+i*16,key,result+i*16);
	}
	prtCharPoint(result,len);
}

/*
 * ���뱾ģʽ����
 * @param ciperTxt ����
 * @param len ���ĳ���(16����)
 * @param key 16λ16������Կ
 * @param result ���ؽ��ܽ��
 */
void deECB(char* ciperTxt,int len,char* key,char* result){
	printf("���뱾ģʽ����:\n");
	int blockNum = len/16;//���Ŀ���
	for(int i=0;i<blockNum;i++){
		deDES(ciperTxt+i*16,key,result+i*16);
	}
	prtCharPoint(result,len);
}

/*
 * ���ķ�������ģʽ����
 * @param plainTxt ����
 * @param len ���ĳ���(16����)
 * @param key 16λ16������Կ
 * @param IV 16λ16���Ƴ�ʼ����
 * @param result ���ؼ��ܽ��
 */
void enCBC(char* plainTxt,int len,char* key,char* IV,char* result){
	printf("���ķ�������ģʽ����:\n");
	char* temp = (char*) malloc(17*sizeof(char));
	int blockNum = len/16;//���Ŀ���
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
 * ���ķ�������ģʽ����
 * @param ciperTxt ����
 * @param len ���ĳ���(16����)
 * @param key 16λ16������Կ
 * @param IV 16λ16���Ƴ�ʼ����
 * @param result ���ؽ��ܽ��
 */
void deCBC(char* ciperTxt,int len,char* key,char* IV,char* result){
	printf("���ķ�������ģʽ����:\n");
	int blockNum = len/16;//���Ŀ���
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
 * ���ķ���ģʽ����
 * @param plainTxt ����
 * @param len ���ĳ���(16����)
 * @param key 16λ16������Կ
 * @param IV 16λ16���Ƴ�ʼ����
 * @param s ���䵥Ԫsλ16����λ ��һ��Ϊ2������ʾ����1�ֽ�
 * @param result ���ؼ��ܽ��
 */
void enCFB(char* plainTxt,int len,char* key,char* IV,int s,char* result){
	printf("���ķ���ģʽ����:\n");
	int blockNum = len/s;//���Ŀ���
	char* temp = (char*) malloc(16*sizeof(char));//����Ϊb=64λ 16λ16��������
	for(int i=0;i<blockNum;i++){
		enDES(IV,key,temp);
		xor_s(plainTxt+i*s,temp,result+i*s,s*4);
		//IV����sλ������C(i)ƴ�ӵ�IVβsλ,�õ��µ�IV
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
 * ���ķ���ģʽ����
 * @param ciperTxt ����
 * @param len ���ĳ���(16����)
 * @param key 16λ16������Կ
 * @param IV ��ʼ����
 * @param s ���䵥Ԫsλ16����λ��һ��Ϊ2������ʾ����1�ֽ�
 * @param result ���ؽ��ܽ��
 */
void deCFB(char* ciperTxt,int len,char* key,char* IV,int s,char* result){
	printf("���ķ���ģʽ����:\n");
	int blockNum = len/s;//���Ŀ���
	char* temp = (char*) malloc(16*sizeof(char));//����Ϊb=64λ 16λ16��������
	for(int i=0;i<blockNum;i++){
		enDES(IV,key,temp);
		xor_s(ciperTxt+i*s,temp,result+i*s,s*4);
		//IV����sλ������C(i)ƴ�ӵ�IVβsλ,�õ��µ�IV
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
 * ����16λ��16���������
 * @param data1 16λ��16������
 * @param data2 16λ��16������
 * @param result 16λ��16������
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
 * ����lenλ��16���������
 * @param data1 16λ��16������
 * @param data2 16λ��16������
 * @param result 16λ��16������
 * @param s ��Ҫ����λ��(2����)
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
