#!/usr/bin/python
#coding:utf-8 


import ConfigParser
import requests
import weibo
import os
import time
import base64
import re
import binascii
import sys
import rsa
import urllib2
import urllib,cookielib
import httplib
import json
#strUrl="https://login.sina.com.cn/sso/prelogin.php?#entry=openapi&callback=sinaSSOController.preloginCallBack&su=MTg3MTA2NDY1OTc=&rsakt=mod&checkpin=1&client=ssologin.js###(v1.4.18)&_=1487555417094"
cookie_file='cookie.txt'
"""
"Cookie":"SCF=AsS5CdZ2mPJTs4UVlxkooBbYmD6kky-v1bdnwtLOWNySJt1evbaWWbWVk8OLxHi4bcOI5EfXR9PlJvLbCYzWjlc.; SUHB=0y0ZTsgVA7M6EL; SINAGLOBAL=231735294847.79797.1487403140977; ULV=1487643562440:19:19:17:8302781118122.396.1487643562426:1487599931095; SUBP=0033WrSXqPxfM725Ws9jqgMF55529P9D9WF9vdEFJQwWasXb2RT292rX5JpX5K2hUgL.Foqpehe41he71hM2dJLoIpqLxK.LB.zL1hBLxK-LBonL1hHbUg8y; UOR=,,login.sina.com.cn; wvr=6; JSESSIONID=3ED19EBB64587578EE6B4C5B0DE2DB1B; SUB=_2A251r9P4DeRxGeBP61EY-C3MwzuIHXVW3UIwrDV8PUJbktANLWL2kW-icCCWMoJsyrvegM9BjKPaQutlSA..; _s_tentry=-; Apache=8302781118122.396.1487643562426"

"""
cook="UOR=news.ifeng.com,widget.weibo.com,news.ifeng.com; SUB=_2A2518zWyDeRhGeBP61EY-C3MwzuIHXVWiSB6rDV8PUNbmtAKLUnfkW8X7PUgHunBvV2drpmv5ZQFDj9s-g..;\ SUBP=0033WrSXqPxfM725Ws9jqgMF55529P9D9WF9vdEFJQwWasXb2RT292rX5JpX5K2hUgL.Foqpehe41he71hM2dJLoIpqLxK.LB.zL1hBLxK-LBonL1hHbUg8y; _s_tentry=-; \   SCF=As58ypE2Y9s9UlMmBFXAy1Eyo9lXG8duTm0J6xM1hZYtQOC4PkRufDkpVsQglE9IQD_pbfbGAZhA4ox_qeM9yIc.;SUHB=0TPVXr5MUkDsFv; ALF=1493205090; SSOLoginState=1492600290; un=18710646597" 
get_pic_url='http://picupload.service.weibo.com/interface/pic_upload.php?mime=image%2Fjpeg&data=base64&url=0&markpos=1&logo=&nick=0&marks=1&app=miniblog'
class myAPIClient(weibo.APIClient):
	def __init__(self, app_key, app_secret, redirect_uri=None, response_type='code', domain='api.weibo.com', version='2'):
		weibo.APIClient.__init__(self, app_key, app_secret, redirect_uri, response_type='code', domain='api.weibo.com', version='2')
		



class sinaWeiBo():
	def __init__(self):
		cp=ConfigParser.SafeConfigParser()
		cp.read('config')
		self.app_key=str(cp.get("science","APP_KEY"))
		self.app_secret=str(cp.get("science","APP_SECRET"))
		self.call_back=str(cp.get("science","CALL_BACK"))
		self.username=str(cp.get("science","username"))
		self.password=str(cp.get("science","password"))
		self.client=myAPIClient(self.app_key,self.app_secret,self.call_back)
		self.auth_url=self.client.get_authorize_url()
		self.su=base64.encodestring(self.username)
		self.strUrl="https://login.sina.com.cn/sso/prelogin.php?entry=openapi&callback=sinaSSOController.preloginCallBack&su="+self.su+"&rsakt=mod&checkpin=1&client=ssologin.js(v1.4.18)&_=1487555417094"
		
	def login(self):
		get_arg=requests.get(self.strUrl)
		#self.cookie=get_arg.cookies
		#print self.cookie.get_dict()
		get_arg_content=get_arg.content
		get_arg_content_split=get_arg_content.split(',')
		servertime=get_arg_content_split[1].split(':')[1]
		nonce=get_arg_content_split[3].split(':')[1][1:-1]
		pubkey=get_arg_content_split[4].split(':')[1][1:-1]
		rsakv=get_arg_content_split[5].split(':')[1][1:-1]
		#print "servertime"+servertime
		#print "nonce"+nonce
		#print "pub"+pubkey
		#print "rsa"+rsakv
		get_ticket_url="https://login.sina.com.cn/sso/login.php?client=ssologin.js(v1.4.18)&_=1487555423991&openapilogin=qrcode"
		rsaPublickey=int(pubkey,16)
		key=rsa.PublicKey(rsaPublickey,65537)
		message=str(servertime)+'\t'+str(nonce)+'\n'+str(self.password)
		sp=rsa.encrypt(message,key)
		sp=binascii.b2a_hex(sp)
		postPara={
			'entry':'openapi',\
			'gateway':'1',\
			'from':'',\
			'savestate':'0',\
			'useticket':'1',\
			'pagerefer':'',\
			'ct':'1800',\
			's':'1',\
			'vsnf':'1',\
			'vsnval':'',\
			'door':'',\
			'appkey':"2sfPWz",\
			'su':self.su,\
			'service':'miniblog',\
			'servertime':servertime,\
			'nonce':nonce,\
			'pwencode':'rsa2',\
			'rsakv':rsakv,\
			'sp':sp,\
			'sr':'800*600',\
			'encoding':'utf-8',\
			'cdult':'2',\
			'domain':'weibo.com',\
			'prelt':'177',\
			'returntype':'TEXT'}
		req=requests.post(get_ticket_url,postPara)
		ticket=req.content.split(',')[1].split(':')[1]
		print ticket
		fields={
			'action':'login',\
			'display':'default',\
			'withOfficalFlag':'0',\
			'quick_auth':'false',\
			'withOfficalAccount':'',\
			'scope':'',\
			'ticket':ticket,
			'isLoginSina':'',\
			'response_type':'code',\
			'regCallback':"https://api.weibo.com/2/oauth2/authorize?client_id="+self.app_key+'&response_type=code&display=default&redirect_uri='+self.call_back+'&from=&with_cookie=',\
			'redirect_uri':self.call_back,\
			'client_id':self.app_key,\
			'appkey62':'2sfPWz',\
			'state':'',\
			'verifyToken':'null',\
			'from':'',\
			'switchLogin':'0',\
			'userId':'',\
			'passwd':''\
			}
#"Referer":auth_url
		self.headers={"Host":"api.weibo.com",\
"User-Agent":"Mozilla/5.0 (X11; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0",\
}
		post_url="https://api.weibo.com/oauth2/authorize"
		#allow_redirects=False   cookies=self.cookie
		get_code_url=requests.post(post_url,data=fields,headers=self.headers)
		login_url="http://my.sina.com.cn/"
		r=requests.session().get(login_url)
		#print r.request.headers
		r=requests.session().get(login_url)
		print r.request.headers['Cookie']
		self.cookie=r.request.headers['Cookie']
		self.headers={"Host":"api.weibo.com",\
"User-Agent":"Mozilla/5.0 (X11; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0",\
"Cookie":"SCF=AsS5CdZ2mPJTs4UVlxkooBbYmD6kky-v1bdnwtLOWNySJt1evbaWWbWVk8OLxHi4bcOI5EfXR9PlJvLbCYzWjlc.; SUHB=0y0ZTsgVA7M6EL; SINAGLOBAL=231735294847.79797.1487403140977; ULV=1487643562440:19:19:17:8302781118122.396.1487643562426:1487599931095; SUBP=0033WrSXqPxfM725Ws9jqgMF55529P9D9WF9vdEFJQwWasXb2RT292rX5JpX5K2hUgL.Foqpehe41he71hM2dJLoIpqLxK.LB.zL1hBLxK-LBonL1hHbUg8y; UOR=,,login.sina.com.cn; wvr=6; JSESSIONID=3ED19EBB64587578EE6B4C5B0DE2DB1B; SUB=_2A251r9P4DeRxGeBP61EY-C3MwzuIHXVW3UIwrDV8PUJbktANLWL2kW-icCCWMoJsyrvegM9BjKPaQutlSA..; _s_tentry=-; Apache=8302781118122.396.1487643562426"}
		#r=requests.session().get(login_url)
		#print r.request.headers
		#print get_code_url.headers
		#print get_code_url.status_code,get_code_url.reason
	def get_code(self):
		r=requests.get(self.auth_url,headers=self.headers,allow_redirects=False)
		print r.url,r.status_code,r.headers
		print r.headers["location"].split("code=")[1]
		self.code=r.headers["location"].split("code=")[1]
		r=self.client.request_access_token(self.code)
		self.uid=r.uid
		self.access_token=r.access_token
		self.client.set_access_token(r.access_token,r.expires_in)
	def send_text(self,text):
		params={"access_token":self.access_token,"status":text}
		send_url="https://api.weibo.com/2/statuses/update.json"
		r=requests.post(send_url,headers=self.headers,data=params)
		print r.text
		#self.client.statuses.update.post(status=text)
		print "send successfully"
	def send_text_pic(self,text=None,filepath=None):
		if filepath==None:
			sys.exit(0)
		if os.path.isfile(filepath):		
			f=open(filepath,"rb")
			self.client.statuses.upload.post(status=text,pic=f)
			f.close()
		else:
			print "file not exist"
	def send_text_pic2(self,text=None,filepath=None):
		if filepath==None:
			sys.exit(0)
		if len(filepath)>1:
			for i in range(len(filepath)):
				content=open(filepath[i],'rb').read()
				#print base64.encodestring(content)
				headers2={"Cookie":cook,"Host":"picupload.service.weibo.com",\
				"Referer":"http://weibo.com/6103983087/profile?topnav=1&wvr=6&is_all=1",\
				"User-Agent":"Mozilla/5.0 (X11; Linux x86_64; rv:45.0) Gecko/20100101 Firefox/45.0"}
				params1={'b64_data':base64.b64encode(content)}
				data=urllib.urlencode(params1)
				r=requests.post(get_pic_url,headers=headers2,data=data,allow_redirects=False)
				print  r.status_code
				print r.text
				#text=r.text.decode('utf-8').encode('utf-8')
				#print text
				#d=re.search(r'{.*}}',text).group(0)
				#result=json.loads(d)
				#p=result['data']['pics']['pic_1']
				break
				#print p
					
			#self.client.statuses.upload.post(status=text,pic=temp)
                        

	def get_uid(self):
		return self.uid
	def get_weibo_content(self,uid=0,max_id=0,count=20,page=1,feature=0):
		#huoqu weibo id  neirong
		if uid==0:
			uid=self.uid
		r=self.client.statuses.user_timeline.get(uid=uid,max_id=max_id,count=count,page=page,feature=feature)
		#r=client.statuses.user_timeline.ids.get(uid=uid)
		for str in r.statuses:
			#print self.client.statuses.show.get(id=str)["text"]+"-----"+str
			print str.text
		#print client.statuses.count.get(id=str)
		#client.statuses.count.get(id=str)[0]["comments"],
		#client.statuses.count.get(id=str)[0]["reposts"]
	def get_weibo_all_ids(self):
		r=self.client.statuses.user_timeline.ids.get(uid=self.uid)
		for str in r.statuses:
			print str
	#all"id"------all"content"
	def get_weibo_ids_contents(self):
		r=self.client.statuses.user_timeline.ids.get(uid=self.uid)
		for str in r.statuses:
			print str+"--------"+self.client.statuses.show.get(id=str)["text"]	
	def get_weibo_id_content(self,id):
		print self.client.statuses.show.get(id=id)["text"]
	#comment must u''
	def add_weibo_commmet(self,id,comment):
		self.client.comments.create.post(id=id,comment=comment)
	def get_weibo_all_comments(self):
		r=self.client.comments.timeline.get()
		for i in range(0,len(r["comments"])):
			print r["comments"][i]["text"]
	def repost_weibo(self,id,status,is_comment):
		self.client.statuses.repost.post(id=id,status=status,is_comment=is_comment)
	def delete_weibo(self,id):
		self.client.statuses.destroy.post(id=id)

#shanchu yitiao weibo
#r=client.statuses.destroy.post(id=4076847560401321)
a=sinaWeiBo()
filepath="/home/ren/temp/jiqi/abstract/1.png"
l=[]
for i in range(2):
	l.append(filepath)
print l
a.login()
a.get_code()
a.send_text_pic2(text='haha',filepath=l)
#a.send_text("caaaaaaaa")
#a.send_text_pic("hello","/home/ren/michaelliao-sinaweibopy-7b4408a/1.png")
#a.get_weibo_all_ids()
#a. get_weibo_id_content(4077906529474211)
#a.get_weibo_content(a.get_uid())
#a.add_weibo_commmet(4077906529474211,'666')
#a. get_weibo_id_content(4077906529474211)
#a.get_weibo_all_comments()
#a.repost_weibo(4077906529474211,"hello",3)

