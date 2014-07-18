/*
 * Des.h
 *  引用Des.cpp的方法
 *  Created on: 2013-10-17
 *  Author: starqiu
 */

#ifndef DES_H_
#define DES_H_

void enDES(char* plainText,char* key,char* result);
void deDES(char* ciperText,char* key,char* result);
void hex2Binary(char* data,int len,char* result);
void binary2Hex(char* data,char* result,int len);
void strCopy(char* src,char* desc,int len);
void prtCharPoint(char* data,int len);

#endif /* DES_H_ */
