/*
 * DES�ļ��������
 * Created on: 2013-10-8
 * Author: star qiu
 */
//#include <iostream>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
//using namespace std;

//��������
void gen_key(char* key,char** result);
void init_pmt(char* plainText,char* result);
void init_pmt_reverse(char* data,char* result);
void left_cir_shift(char* key, int rc);
void pmt_choice_1(char* key,char* result );
void pmt_choice_2(char* key,char* result );
void pmt_E(char* data,char* result);
void pmt_P(char* data,char* result);
void pmt_S(char* data,char* result);
void enDES(char* plainText,char* key,char* result);
void deDES(char* ciperText,char* key,char* result);
void hex2Binary(char* data,int len,char* result);
void binary2Hex(char* data,int len);
void binary2Hex(char* data,char* result,int len);
void prtCharPoint(char* data,int len);
void strCopy(char* src,char* desc,int len);

/*int main(){
	char* plainText = (char*)malloc(16*sizeof(char));//����
	char* key = (char*)malloc(16*sizeof(char));//��Կ
	char* ciperText = (char*)malloc(16*sizeof(char));//����
	char* opr =(char*)malloc(sizeof(char));//����
	char* result =(char*)malloc(16*sizeof(char));//���ܻ���ܽ��
	int t1,t2;//ʱ��
	//plainText="02468aceeca86420";//16����
	//ciperText="da02ce3a89ecac3b";
	//key="0f1571c947d9e859";//16����
	while(true){
		printf("��ѡ������Ҫ���еĲ�����\n1 ����\n2 ����\n0 �˳�\n");
		scanf("%s", opr);
		switch(*opr){
			case '0':
				return 0;
			case '1':
				printf("������16λ16�������ģ�");
				scanf("%s", plainText);
				printf("\n");
				printf("������16λ16������Կ��");
				scanf("%s", key);
				printf("\n");
				t1=clock();
				enDES(plainText,key,result);
				prtCharPoint(result,16);
				t2=clock();
				printf("����ʱ�䣺%f s\n",double(t2-t1)/CLOCKS_PER_SEC);
				break;
			case '2':
				printf("������16λ16�������ģ�");
				scanf("%s", ciperText);
				printf("\n");
				printf("������16λ16������Կ��");
				scanf("%s", key);
				printf("\n");
				t1=clock();
				deDES(ciperText,key,result);
				prtCharPoint(result,16);
				t2=clock();
				printf("����ʱ�䣺%f s\n",double(t2-t1)/CLOCKS_PER_SEC);
				break;
			default:
				printf("������0��1��2�ֱ��ʾ�˳������ܼ����ܹ��ܣ�\n");
				break;
		}
	}
	system("pause");
	return 0;

}*/

//������ʼ����
//��ʼ�û���IP  
int TBL_IP[64] = 
				{57,49,41,33,25,17,9,1,  
                 59,51,43,35,27,19,11,3,  
                 61,53,45,37,29,21,13,5,  
                 63,55,47,39,31,23,15,7,  
                 56,48,40,32,24,16,8,0,  
                 58,50,42,34,26,18,10,2,  
                 60,52,44,36,28,20,12,4,  
                 62,54,46,38,30,22,14,6};   
//���ʼ�û���IP^-1  
int TBL_IP_REVERSE[64] = 
          {39,7,47,15,55,23,63,31,  
           38,6,46,14,54,22,62,30,  
           37,5,45,13,53,21,61,29,  
           36,4,44,12,52,20,60,28,  
           35,3,43,11,51,19,59,27,  
           34,2,42,10,50,18,58,26,  
           33,1,41,9,49,17,57,25,  
           32,0,40,8,48,16,56,24};  
  
//�����û���E  
int TBL_E[48] = {31, 0, 1, 2, 3, 4,  
                  3,  4, 5, 6, 7, 8,  
                  7,  8,9,10,11,12,  
                  11,12,13,14,15,16,  
                  15,16,17,18,19,20,  
                  19,20,21,22,23,24,  
                  23,24,25,26,27,28,  
                  27,28,29,30,31, 0};  
  
//�û�����P  
int TBL_P[32] = {15,6,19,20,28,11,27,16,  
                  0,14,22,25,4,17,30,9,  
                  1,7,23,13,31,26,2,8,  
                  18,12,29,5,21,10,3,24};  
  
//S��  
int TBL_S[8][4][16] =
             //S1  
            {{{14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},  
              {0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},  
			  {4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},  
			  {15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}},  
              //S2  
              {{15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},  
              {3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},  
              {0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},  
              {13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}},  
              //S3  
              {{10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},  
              {13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},  
              {13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},  
              {1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}},  
              //S4  
              {{7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},  
              {13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},  
              {10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},  
              {3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}},  
              //S5  
              {{2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},  
              {14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},  
              {4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},  
              {11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}},  
              //S6  
              {{12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},  
              {10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},  
              {9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},  
              {4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}},  
              //S7  
              {{4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},  
              {13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},  
              {1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},  
              {6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}},  
              //S8  
              {{13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},  
              {1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},  
              {7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},  
              {2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}}};  
//�û�ѡ��1  
int TBL_PC_1[56] = 
             {56,48,40,32,24,16,8,  
              0,57,49,41,33,25,17,  
              9,1,58,50,42,34,26,  
              18,10,2,59,51,43,35,  
              62,54,46,38,30,22,14,  
              6,61,53,45,37,29,21,  
              13,5,60,52,44,36,28,  
              20,12,4,27,19,11,3};  
  
//�û�ѡ��2  
int TBL_PC_2[48] = 
             {13,16,10,23,0,4,2,27,  
              14,5,20,9,22,18,11,3,  
              25,7,15,6,26,19,12,1,  
              40,51,30,36,46,54,29,39,  
              50,44,32,47,43,48,38,55,
              33,52,45,41,49,35,28,31};  
  
//�����ƴ����Ĺ涨  
int TBL_RC[16] = {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};

/*
 *DES����
 *���룺plainText 16λ���ģ�16���ƣ��� key 16λ��Կ��16���ƣ�
 *�����result ���ܺ�Ľ�� 16λ���ģ�16���ƣ�
 */
void enDES(char* plainText,char* key,char* result){
	printf("�������ݿ�ʼ��\n");

	char*  dataL=(char*) malloc(32*sizeof(char));//������벿��
	char*  dataR=(char*) malloc(32*sizeof(char));//�����Ұ벿��
	char*  dataL_cp=(char*) malloc(32*sizeof(char));//������벿�ֿ���
	char*  dataR_cp=(char*) malloc(32*sizeof(char));//�����Ұ벿�ֿ���
	char*  data_48=(char*) malloc(48*sizeof(char));//48λ�м�����
	char*  data_64=(char*) malloc(64*sizeof(char));//64λ��ʼ���ݳ�ʼ�û�������
	char*  data_64_I=(char*) malloc(64*sizeof(char));//64λ��ʼ����
	//16��48λ��Կ�ռ�
	char**  keys =(char**) malloc(16*sizeof(char*));
	for(int i=0;i<16;i++){
		*(keys+i) = (char*) malloc(48*sizeof(char));
	}
	//�õ�16��48λ��Կ
	gen_key(key,keys);
	//16��������ת����2����
	hex2Binary(plainText,16,data_64_I);
	//��ʼ�û�
	init_pmt(data_64_I,data_64);
	strCopy(data_64,dataL,32);
	strCopy(data_64+32,dataR,32);

	//�ֱ任��ѭ��16��
	for(int rc=1;rc<=16;rc++){
		//printf("��%d�����ݣ�",rc);
		//��չ�û�E
		pmt_E(dataR,data_48);
		strCopy(dataL,dataL_cp,32);
		strCopy(dataR,dataL,32);
		//���
		for(int i = 0 ;i < 48;i++){
			data_48[i] = data_48[i]^keys[rc-1][i];
		}
		//S���û�/ѡ��
		pmt_S(data_48,dataR_cp);
		//P�û�
		pmt_P(dataR_cp,dataR);
		//���
		for(int i = 0 ;i < 32;i++){
			dataR[i] = dataL_cp[i]^dataR[i];
		}
		binary2Hex(dataL,32);//��ӡ��벿��
		printf("  ");
		binary2Hex(dataR,32);//��ӡ�Ұ벿��
		printf("\n");
	}

	//32λ����
	strCopy(dataR,data_64_I,32);
	strCopy(dataL,data_64_I+32,32);
	//���ʼ�û�
	init_pmt_reverse(data_64_I,data_64);
	printf("����Ϊ: ");
	binary2Hex(data_64,result,64);

	free(data_64);
	free(dataL);
	free(dataR);
	free(dataL_cp);
	free(dataR_cp);
	free(data_48);
	free(data_64_I);
	free(keys);
}

/*
 *DES����
 *���룺plainText 16λ���ģ�16���ƣ��� key 16λ��Կ��16���ƣ�
 *��������ܺ�Ľ�� ���ܺ�Ľ�� 16λ���ģ�16���ƣ�
 */
void deDES(char* ciperText,char* key,char* result){
	printf("�������ݿ�ʼ��\n");

	char*  dataL=(char*) malloc(32*sizeof(char));//������벿��
	char*  dataR=(char*) malloc(32*sizeof(char));//�����Ұ벿��
	char*  dataL_cp=(char*) malloc(32*sizeof(char));//������벿�ֿ���
	char*  dataR_cp=(char*) malloc(32*sizeof(char));//�����Ұ벿�ֿ���
	char*  data_48=(char*) malloc(48*sizeof(char));//48λ�м�����
	char*  data_64=(char*) malloc(64*sizeof(char));//64λ��ʼ���ݳ�ʼ�û�������
	char*  data_64_I=(char*) malloc(64*sizeof(char));//64λ��ʼ����
	//16��48λ��Կ�ռ�
	char**  keys =(char**) malloc(16*sizeof(char*));
	for(int i=0;i<16;i++){
		*(keys+i) = (char*) malloc(48*sizeof(char));
	}
	//�õ�16��48λ��Կ
	gen_key(key,keys);
	//16��������ת����2����
	hex2Binary(ciperText,16,data_64_I);
	//��ʼ�û�
	init_pmt(data_64_I,data_64);
	strCopy(data_64,dataL,32);
	strCopy(data_64+32,dataR,32);

	//�ֱ任��ѭ��16��
	for(int rc=1;rc<=16;rc++){
		//printf("��%d�����ݣ�",rc);
		//��չ�û�E
		pmt_E(dataR,data_48);
		strCopy(dataL,dataL_cp,32);
		strCopy(dataR,dataL,32);
		//���
		for(int i = 0 ;i < 48;i++){
			data_48[i] = data_48[i]^keys[16-rc][i];
		}
		//S���û�/ѡ��
		pmt_S(data_48,dataR_cp);
		//P�û�
		pmt_P(dataR_cp,dataR);
		//���
		for(int i = 0 ;i < 32;i++){
			dataR[i] = dataL_cp[i]^dataR[i];
		}
		binary2Hex(dataL,32);//��ӡ��벿��
		printf("  ");
		binary2Hex(dataR,32);//��ӡ�Ұ벿��
		printf("\n");
	}

	//32λ����
	strCopy(dataR,data_64_I,32);
	strCopy(dataL,data_64_I+32,32);
	//���ʼ�û�
	init_pmt_reverse(data_64_I,data_64);
	printf("����Ϊ: ");
	binary2Hex(data_64,result,64);

	free(data_64);
	free(dataL);
	free(dataR);
	free(dataL_cp);
	free(dataR_cp);
	free(data_48);
	free(data_64_I);
	free(keys);
}

/*
 *������Կ
 *���룺16������Կ
 *���أ�result 16��48λ��Կ
 */
void gen_key(char* key,char** result){
	char*  key_56=(char*) malloc(56*sizeof(char));//56λ��Կ
	char*  key_64=(char*) malloc(64*sizeof(char));//64λ��Կ
	//16������Կת����2���ƣ��������û�ѡ��1ת��56λ��Կ b
	hex2Binary(key,16,key_64);
	pmt_choice_1(key_64,key_56);
	free(key_64);
	for(int i=0;i<16;i++){
		left_cir_shift(key_56,i);
		pmt_choice_2(key_56,*(result+i));
		//binary2Hex(*(result+i),48);
	}
	free(key_56);
}

/*
 *initial permutation ���ĳ�ʼ�û�
 *���룺plainText 64λ����
 *���أ�result 64λ����
 */
void init_pmt(char* plainText,char* result){
	for(int i = 0;i<64;i++){
		result[i] = plainText[TBL_IP[i]];
	}
	//printf("���ĳ�ʼ�������");
	//binary2Hex(result,64);
}

/*
 *initial permutation ���ʼ�û�
 *���룺data 64λ����
 *���أ�result 64λ����
 */
void init_pmt_reverse(char* data,char* result){
	for(int i = 0;i<64;i++){
		result[i] = data[TBL_IP_REVERSE[i]];
	}
	//printf("���ĳ�ʼ�������");
	//binary2Hex(result,64);
}

/*
 *��չ/�û���E��
 *���룺data 32λ����
 *���أ�result 48λ����
 */
void pmt_E(char* data,char* result){
	for(int i = 0;i<48;i++){
		result[i] = data[TBL_E[i]];
	}
	//printf("��չ/�û���E����");
	//binary2Hex(result,48);
}

/*
 *S���û�
 *���룺48λ���ݣ���S��ת��
 *���أ�result 32λ����
 */
void pmt_S(char* data ,char* result){
	int row = 0;
	int col = 0;
	int temp = 0;//��S���û���ֵ
	for(int k = 0;k<8;k++){
		row=(data[k*6]<<1)|data[k*6+5];
		col=(data[k*6+1]<<3)|(data[k*6+2]<<2)|(data[k*6+3]<<1)|(data[k*6+4]);
		temp = TBL_S[k][row][col];	
		for(int m = 0;m<4;m++){
			result[k*4-m+3] = temp%2;
			temp=temp>>1;
		}
	}
	//printf("S���û���");
	//binary2Hex(result,32);
}

/*
 *�û�(P)
 *���룺32λ���ݣ���P�û�
 *���أ�result 32λ����
 */
void pmt_P(char* data ,char* result){
	for(int i=0;i<32;i++){
		result[i] = data[TBL_P[i]];
	}
	//printf("�û�(P)��");
	//binary2Hex(result,32);
}

/*
 *permuted choice 1 �û�ѡ��1
 *��Կȥ��8�ı���λ �����û�ѡ��1 64λ���ı��56λ(������0��ʼ)
 *���룺 key 64λ��Կ
 *���أ� result 56λ��Կ
 */
void pmt_choice_1(char* key,char* result ){
	for(int i=0;i<56;i++){
		result[i] = key[TBL_PC_1[i]];
	}
	//printf("�û�ѡ��1��");
	//binary2Hex(result,56);
}

/*
 *left circular shif ѭ������
 *���룺 key 56λ��Կ,rc ����
 *���أ� key 56λ��Կ
 */
void left_cir_shift(char* key, int rc){
	int temp=key[0];
	rc = TBL_RC[rc];
	if(1 == rc){//ѭ������һλ
		for(int i = 0;i<27;i++){//��벿��ѭ������
			key[i] = key[i+1];
		}
		key[27] = temp;

		temp = key[28];
		for(int i = 28;i<55;i++){//�Ұ벿��ѭ������
			key[i] = key[i+1];
		}
		key[55] = temp;
	}else{//ѭ������2λ
		int temp2 = key[1];
		for(int i = 0;i<26;i++){//��벿��ѭ������
			key[i] = key[i+2];
		}
		key[26] = temp;
		key[27] = temp2;

		temp = key[28];
		temp2 = key[29];
		for(int i = 28;i<54;i++){//�Ұ벿��ѭ������
			key[i] = key[i+2];
		}
		key[54] = temp;
		key[55] = temp2;
	}
	//printf("ѭ�����ƣ�");
	//binary2Hex(key,56);
}


/*
 *permuted choice 2 �û�ѡ��2
 *��Կȥ��8�ı���λ 56λ��Կ���48λ(������0��ʼ)
 *���룺 key 56λ��Կ
 *���أ� result 48λ��Կ
 */
void pmt_choice_2(char* key, char* result ){
	for(int i=0;i<48;i++){
		result[i] = key[TBL_PC_2[i]];
	}
	//printf("�û�ѡ��2��");
	//binary2Hex(result,48);
}

/*
 *��16����ת��2����
 *���룺 data 16��������,len ��Ҫװ����16����������
 *���أ�����������
 */
void hex2Binary(char* data,int len,char* result){
	for(int i =0 ,j=0;i<len;i++,j = i<<2){
		switch(*(data+i)){
			case '0':
				*(result+j)=0x0;*(result+j+1)=0x0;*(result+j+2)=0x0;*(result+j+3)=0x0;break;
			case 0:
				*(result+j)=0x0;*(result+j+1)=0x0;*(result+j+2)=0x0;*(result+j+3)=0x0;break;
			case '1':
				*(result+j)=0x0;*(result+j+1)=0x0;*(result+j+2)=0x0;*(result+j+3)=0x1;break;
			case '2':
				*(result+j)=0x0;*(result+j+1)=0x0;*(result+j+2)=0x1;*(result+j+3)=0x0;break;
			case '3':
				*(result+j)=0x0;*(result+j+1)=0x0;*(result+j+2)=0x1;*(result+j+3)=0x1;break;
			case '4':
				*(result+j)=0x0;*(result+j+1)=0x1;*(result+j+2)=0x0;*(result+j+3)=0x0;break;
			case '5':
				*(result+j)=0x0;*(result+j+1)=0x1;*(result+j+2)=0x0;*(result+j+3)=0x1;break;
			case '6':
				*(result+j)=0x0;*(result+j+1)=0x1;*(result+j+2)=0x1;*(result+j+3)=0x0;break;
			case '7':
				*(result+j)=0x0;*(result+j+1)=0x1;*(result+j+2)=0x1;*(result+j+3)=0x1;break;
			case '8':
				*(result+j)=0x1;*(result+j+1)=0x0;*(result+j+2)=0x0;*(result+j+3)=0x0;break;
			case '9':
				*(result+j)=0x1;*(result+j+1)=0x0;*(result+j+2)=0x0;*(result+j+3)=0x1;break;
			case 'a':
			case 'A':
				*(result+j)=0x1;*(result+j+1)=0x0;*(result+j+2)=0x1;*(result+j+3)=0x0;break;
			case 'b':
			case 'B':
				*(result+j)=0x1;*(result+j+1)=0x0;*(result+j+2)=0x1;*(result+j+3)=0x1;break;
			case 'c':
			case 'C':
				*(result+j)=0x1;*(result+j+1)=0x1;*(result+j+2)=0x0;*(result+j+3)=0x0;break;
			case 'd':
			case 'D':
				*(result+j)=0x1;*(result+j+1)=0x1;*(result+j+2)=0x0;*(result+j+3)=0x1;break;
			case 'e':
			case 'E':
				*(result+j)=0x1;*(result+j+1)=0x1;*(result+j+2)=0x1;*(result+j+3)=0x0;break;
			case 'f':
			case 'F':
				*(result+j)=0x1;*(result+j+1)=0x1;*(result+j+2)=0x1;*(result+j+3)=0x1;break;
		}
	}
}

/*
 *��2����ת��16����  ����ӡ16��������
 *@param data 2��������
 *@param len 2��������ĳ���
 */
void binary2Hex(char* data,int len){
	for(int i=0;i<len;i+=4){
		printf("%x", *(data+i)*8+*(data+i+1)*4+*(data+i+2)*2+*(data+i+3));
	}
}

/*
 *��2����ת��16���Ʊ���ת�����  ����ӡ16��������
 *@param data 2��������
 *@param len 2��������ĳ���
 */
void binary2Hex(char* data,char* result,int len){
	int temp = 0;
	for(int i=0;i<len;i+=4){
		temp = *(data+i)*8+*(data+i+1)*4+*(data+i+2)*2+*(data+i+3);
		sprintf_s(result+i/4,2,"%x",temp);
	}
}

/*
 * ֱ�Ӵ�ӡ����
 * @param data ����
 * @param len ���鳤��
 */
void prtCharPoint(char* data,int len){
	for(int i=0;i<len;i++){
		printf("%c", *(data+i));
	}
	printf("\n");
}
/*
 * �����ַ���
 * @param src Դ�ַ���
 * @param desc Ŀ���ַ���
 * @len Ҫ�����ĳ���
 *
 */
void strCopy(char* src,char* desc,int len){
	for(int i=0;i<len;i++){
		*(desc+i) = *(src+i);
	}
}
