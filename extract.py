#!/usr/bin/python

import sys
import os

if len(sys.argv)==1:
    print "Enter the filename you want to convert. Example: python test.py ~/mnc/rule.txt" #요런식으로 실행하면 됨.
    exit(1)

in_f=open(sys.argv[1], 'r')              # 파일읽어오는 것
out_f=open('P4_1_0.txt', 'a')        # output 파일의 이름임. 

lines = in_f.readlines()                #파일의 line을 읽어옴
sum_data = 0                # 추후 평균을 내기위해 데이터들이 모두 더해지는 sum값인데,  초기화하는것
max_data = 0                # 최대값을 초기화
min_data = 999999999        # 최소값을 초기화

for line in lines:          # line의 수만큼 반복
    item = line.split(" ")  # line의 문자열들간에 공백이 있으면 공백을 경계로 분리하고, 각각을 item이라는 리스트안에 넣음
    if "value" in line:     # line에서 value라는 문자열이 있으면, (내가 찾는 값이 로그중 value라는 문자 바로 다음에 오는 값이었음.)
        data = int(item[item.index("value")+1]) # item이라는 리스트 안에서 value라는 문자 바로 다음(+1)에 오는 값을 int형식으로 바꿔서 data에 넣음.
        
        if max_data < data: # 최대값 찾는 과정
            max_data = data
        if min_data > data: # 최소값 찾는 과정
            min_data = data
        sum_data = sum_data + data # 전체 데이터의 합을 구하는 과정 (추후 평균 계산을 위함)
        out_f.write(str(data)+'\n') # 모든 data들을 파일에 출력하는 것

#for line in lines:
#    item = line.split(" ")
#    if "value" in line:
#        new_data = int(item[item.index("value")+1])
#        w_data = w_data + new_data
        

expectation = sum_data/1000     #평균 구하기 (나는 1000개의 패킷을 보냈으니 수정해야할 것)


print "%d" %(expectation)   #평균 출력
print "%d" %(max_data)  #최대값 출력
print "%d" %(min_data)  #최소값 출력

in_f.close()
out_f.close()