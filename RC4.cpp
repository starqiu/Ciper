#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#define uchar unsigned char
void swap(uchar& a,uchar& b);
void rc4(uchar* key,int keyLen);
/*int main(){
	uchar* key = (uchar*)malloc(256*sizeof(uchar));
	printf("�����볤�Ȳ�����256����Կ��\n");
	scanf("%s",key);
	int len=0;
	while('\0'!=*(key++)){
		len++;
	}
	rc4(key,len);
	system("pause");
	return 0;
}

void rc4(uchar* key,int keyLen){
	uchar S[256];
	uchar T[256];
	int j=0;
	int i=0;
	//��ʼ��S����
	for(i=0;i<256;i++){
		S[i]=i;
		T[i]=*(key+i%keyLen);
	}
	//��ʼ��S���û�
	i=0;
	for(i=0;i<256;i++){
		j=(j+S[i]+T[i])%256;
		swap(S[i],S[j]);
	}
	//��Կ��������
	i=j=0;
	int t=0;
	uchar* pchar =(uchar*) malloc(sizeof(uchar));//��������
	uchar* cchar =(uchar*) malloc(sizeof(uchar));//��������
	uchar k;
	while(true){
		i=(i+1)%256;
		j=(j+S[i])%256;
		swap(S[i],S[j]);
		t=(S[i]+S[j])%256;
		k=S[t];
		printf("�����뵥�����ģ�");
		scanf("%s",pchar);
		printf("%c ���ܺ������Ϊ��%c\n",*pchar,k^*pchar);
		printf("�����뵥�����ģ�");
		scanf("%s",cchar);
		printf("%c ���ܺ������Ϊ��%c\n",*cchar,k^*cchar);
	}
}*/

void swap(uchar &a,uchar &b){
	a = a^b;
	b = a^b;
	a = a^b;
}