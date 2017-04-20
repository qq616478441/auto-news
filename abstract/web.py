#!/usr/bin/python
#coding:utf-8 
import tornado.web  
import tornado.ioloop
from  send_sina_weibo import   sinaWeiBo
from tornado.options import define,options,parse_command_line  
 
define('port',default=10000,help='run on the port',type=int)  

import urllib
import sys
import time
import re

import codecs
from textrank4zh import TextRank4Keyword, TextRank4Sentence
reload(sys)
sys.setdefaultencoding('utf-8')
#db=MySQLdb.connect('127.0.0.1','root','','test')
#print db
#db.set_character_set('utf8')
#cursor=db.cursor()
#cursor.execute('SET NAMES utf8;')
#cursor.execute('SET CHARACTER SET utf8;')
#cursor.execute('SET character_set_connection=utf8;')

l=[]
test=sinaWeiBo()  
class MainHandler(tornado.web.RequestHandler):  
    def get(self):  
        self.render('a.html',title='haha',items=l)  
    def post(self):  
        count=1  
        print(self.request.remote_ip) 
        if self.request.body_arguments.has_key('arg'):
            arg=self.request.body_arguments['arg']
            #print (arg[0] )
	    #print (arg[1])
	    #print (arg[2])
            print ("------------------")
            #print (urllib.unquote(arg[2]))
            #print ('----------------')
            #abstract= urllib.unquote(arg[3])[9:]
            #print abstract
            #print ('-------------------')
            #news_origin=urllib.unquote(arg[4])[12:]
            print ('-------------------')
            article=urllib.unquote(arg[5])[13:]
	    a=re.sub("{{(.*?)}}", " ",article)
	    b=re.findall(r"{{(.*?)}}",article)
            print "hahahahaha"+str(len(b))
            for i in range(len(b)):
                f=requests.get(str(b[i]))
                file_temp="./news_toutiao_"+str(i)+'.png'
		print file_temp
		temp_file=open(file_temp,'w+')
		temp_file.write(f.content)
                temp_file.close()		
		#print a
            
	    tr4s = TextRank4Sentence()
	    tr4s.analyze(text=a, lower=True, source = 'all_filters')
            
            str1=''		
	    print( '摘要：' )
	    for item in tr4s.get_key_sentences(num=2.5):
    		#print(item.index, item.weight, item.sentence)
    	        print(item.sentence)
                str1=str1+item.sentence
            print str1
            test.login()
            test.get_code()
            #test.send_text(str[0:100])
               
            test.send_text_pic(str1[0:100],"/home/ren/temp/jiqi/abstract/news_toutiao_2.png")
            for i in range(len(b)):
                file_temp='./news_toutiao_'+str(i)+'.png'
		os.remove(file_temp)
        elif self.request.body_arguments.has_key('temp'):
		article=self.request.body_arguments['temp'][0]
		
		a=re.sub("{{(.*?)}}", " ",article)
		
		#print a
		tr4s = TextRank4Sentence()
		tr4s.analyze(text=a, lower=True, source = 'all_filters')

		
		print( '摘要：' )
		for item in tr4s.get_key_sentences(num=2.5):
    		#print(item.index, item.weight, item.sentence)
    			print(item.sentence)
        #l.append(talk)

        #self.render('a.html',title='haha',items=l)  
def main():  
    parse_command_line()  
    app=tornado.web.Application(  
            [  
                (r'/',MainHandler),  
                ],  
            )  
  
    app.listen(options.port)  
    tornado.ioloop.IOLoop.instance().start()  
      
if __name__=='__main__':  
    main()  
