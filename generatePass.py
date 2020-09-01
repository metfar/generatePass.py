#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#  generatePass.py
#  
#  Copyright 2020 William Martinez Bas <metfar@gmail.com>
#  
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#  
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#  
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.
#  
#  Proposal: Write a password generator in Python 
#            ( strong passwords have a mix of lowercase letters, 
#               uppercase letters, numbers and symbols ). 
#            The passwords should be random generating a new 
#            password every time the user asks for a new password.

#includes
import sys;
import random;
from json import dumps, loads;
import os.path;
from datetime import datetime;

try:
	HOME=os.path.expanduser("~");
except:
	try:
		from pathlib import Path;
		HOME = str(Path.home());
	except:
		HOME=os.path.abspath("");

randInt=randint=random.randint;
basename=os.path.basename;
dirname=os.path.dirname;


#CONFIG
ARGV=sys.argv;
APP=basename(ARGV[0]);
FILENAME="."+APP+".conf";
true=TRUE=ON=True;
false=FALSE=OFF=False;
null=NULL=None;

CONFIGFILE=HOME+os.sep;
CONFIGFILE=CONFIGFILE+FILENAME;
CONFIGFILE=CONFIGFILE.replace(os.sep+"."+os.sep,os.sep);
CONFIGFILE=CONFIGFILE.replace(os.sep+os.sep,os.sep);
#DEFAULT CHARACTERS
CHARSET={   "UPPERS":   'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
			"LOWERS":   'abcdefghijklmnopqrstuvwxyz',
			"NUMBERS":  '0123456789',
			"SYMBOLS":  '!@#%&*/:-+=_'
			};


PASSWDS=[];
HASHPWDS=[];

def DBG():
	global debug;
	try:
		debug;
	except:
		debug=False;
	return(debug);

def now():
	return(datetime.now());
	
def timestampToString(x):
	return(datetime.fromtimestamp(x).strftime("%Y-%m-%d %H:%M:%S"));

def timestamp(inTime=None):
	try:
		inp=datetime.fromisoformat(inTime);
	except:
		inp=now();  
	return(datetime.timestamp(inp));

class Register:
	def __init__(self, time, passwd,desc=""):
		self.time=time;#store timestamp
		self.passwd=passwd;#store password rotated
		self.desc=desc;#just to add a commentary into the file
		
	def to_dict(self):
		return({"time":self.time,"passwd":self.passwd,"desc":self.desc});

def loadConfig():
	global PASSWDS,HASHPWDS;
	try:
		cFile=open(CONFIGFILE,"r+");
		cFileData=loads(cFile.read());
		cFile.close();
	except IOError:
		cFileData={};
	PASSWDS=[];
	HASHPWDS=[];
	for f in cFileData:
		PASSWDS.append(Register(f["time"],f["passwd"],f["desc"]));
		HASHPWDS.append(f["passwd"]);

def saveConfig():
	saveList=[];
	for f in PASSWDS:
		saveList.append(f.to_dict());
	try:
		cFile=open(CONFIGFILE,"w+");
		cFile.write(dumps(saveList));
		cFile.close();
	except:
		print(CONFIGFILE+" could not be saved");
		sys.exit(5);
	return(True);
	
def addPass(passwd,desc=""):
	global PASSWDS;
	nRegister = Register(timestamp(),passwd,desc);
	PASSWDS.append(nRegister);
	saveConfig();


def listPass():
	print("%20s\t%s" % ("TIME","HASH"));
	print("%20s\t%s" % ("----","----"));
	for f in PASSWDS:
		print("%20s\t%s"%(timestampToString(f.time),f.passwd));

def listExtended():
	print("%20s\t%s" % ("TIME","""HASH [minLen,maxLen,atLeastLow,atlUpp,atlSym,atlNum,lowers,uppers,syms,nums]"""));
	print("%20s\t%s" % ("----","---- [···]"));
	for f in PASSWDS:
		print("%20s\t%s %32s"%(timestampToString(f.time),f.passwd,f.desc));

def HELP():
	print("""
"""+APP+"""
				Without argument it generates an 'unique' 
				strong password.
				It stores a pseudo-encrypted version of it,
				so it can control to no-repeat.

-h|--help|-?
				Shows this help.

		-C      Clear storage.
		-R      Review storage.
		-X      Extended storage list.

		-g      Generate Password
				
        -n1     At least 1 number
        -l1     At least 1 lowercase character
        -u1     At least 1 uppercase character
        -s1     At least 1 symbol
		
        -m8     Minimum length 8
        -M32    Maximum length 32
		
        -L      Include Lowercase Characters
        -U      Include Uppercase Characters
        -N      Include Numeric Characters
        -S      Include Symbols

        --L     Do Not Include Lowercase Characters
        --U     Do Not Include Uppercase Characters
        --N     Do Not Include Numeric Characters
        --S     Do Not Include Symbols
		
		-v      Verbose on
		
		metfar@gmail.com	
								
	""");
	return(1);

def rot(inString):  #similar to rot13 but with every 
					#even string from CHARSET
	out="";
	for f in inString:
		charac="";
		for n in CHARSET:
			a=CHARSET[n];
			lim=len(a);
			if (f in a):
				i=a.index(f);
				num=(i+lim//2)%lim;
				charac=a[num];
				if(charac!=a[a.index(f)]):
					break;
		
		out+=charac;
		
	return(out);

def conv(inChar):#convert whatever to string if it is possible, else ""
	out="";
	try:
		out=str(inChar);
	except:
		pass;
	return(out);
	
def filt(inArray):#filter into string trimming spaces
	tmp="";
	for f in inArray:
		t=conv(f);
		if(len(t)>0 and t!=" "):
			tmp+=t;
	return(tmp);

def length(inArray):#calculate length trimming spaces
	return(len(filt(inArray)));
	

def randomString(   minLength=8,
					maxLength=32,
					leastLow=1,
					leastUpp=1,
					leastSym=1,
					leastNum=1,
					lowers=True,
					uppers=True,
					symbols=True,
					numbers=True
					):
	try:
		minLength,maxLength=int(minLength),int(maxLength);
		leastLow,leastUpp=int(leastLow),int(leastUpp);
		leastSym,leastNum=int(leastSym),int(leastNum);
	except:
		print("Wrong type of input parameters");
		sys.exit(2);
	
	minLength,maxLength=min(minLength,maxLength),max(minLength,maxLength);
	
	if(minLength<(leastLow+leastUpp+leastSym+leastNum)):
		minLength=leastLow+leastUpp+leastSym+leastNum;
	
	lim={   "UPPERS":   leastUpp,
			"LOWERS":   leastLow,
			"NUMBERS":  leastNum,
			"SYMBOLS":  leastSym};#lower limit
	WHAT=[];
	if(lowers):
		WHAT.append("LOWERS");
	if(uppers):
		WHAT.append("UPPERS");
	if(symbols):
		WHAT.append("SYMBOLS");
	if(numbers):
		WHAT.append("NUMBERS");
	
	if(len(WHAT)<1 or int(minLength)<1 or int(maxLength)<int(minLength)):
		print("Wrong parameters, you need at least one group of characters");
		sys.exit(1);
	
	choseLength=randint(minLength,maxLength);
	out=[];
	for f in range(choseLength):
		out.append(" ");
	cursor=0;#actual character index
	rounds=0;   #count rounds trying to generate a proper password
	limround=20;#limit of rounds so computer will not hang on it
	
	while (True):#it will generate password in round robin way
		kind=randInt(0,len(WHAT)-1);
		
		inp=CHARSET[WHAT[kind]];
		charac=inp[randInt(0,len(inp)-1)];
		out[cursor]=charac;
		cursor+=1;
		#check if password is finished
		if (length(out)==choseLength):#proper length
			condit=True;
			for f in WHAT:
				if(countIn(CHARSET[f],out)<lim[f]):
					condit=False;
			if(condit):
				pw=filt(out);
				if(not (pw in HASHPWDS)):
					return(pw);
				else:
					condit=False;
				
		if(cursor>=choseLength):
			rounds+=1;
			cursor=0;
			if(DBG()):
				print(str(rounds)+":"+filt(out)+" |x|="+str(length(out)));
			if(rounds>limround):
				print("Sorry, it could not generate a proper password");
				sys.exit(3);
		
def countIn(which,where):
	"""
		countIn
		IN:
			which       Single data or array of data to search in
			where       Array or string where "which" would be seached.
		
		OUT:
						returns how many 'which' were found in 'where'.
	"""
	out=0;
	WHICH=[];
	if(type(which)!=type(list())):
		for f in which:
			if(not (f in WHICH)):
				WHICH.append(f);
	else:
		WHICH=list(set(which));
	
	cnt=0;
	
	for f in where:
		if(f in WHICH):
			cnt+=1;
	return(cnt);
	
	
def isIn(which,where,atLeastOne=True):
	"""
		isIn
		
		IN:
			which       Single data or array of data to search in
			where       Array or string where "which" would be seached.
			atLeastOne  True:   returns true if at least one 
								of the which is found.
						False:  returns true if all the 'which' chars
								are in 'where'
	"""
	out=False;
	if(type(which)==type(list())):
		tmp=len(which);
		y=0;
		for f in which:
			if(f in where):
				y+=1;
		if(atLeastOne):
			out=y>0;
		else:
			out= (y==len(which));
	else:
		try:
			out=which in where;
		except:
			pass;
	return(out);

def generatePassword(minLength,
					maxLength,
					leastLow,
					leastUpp,
					leastSym,
					leastNum,
					lowers,
					uppers,
					symbols,
					numbers
					):
	passw=randomString(minLength,
					maxLength,
					leastLow,
					leastUpp,
					leastSym,
					leastNum,
					lowers,
					uppers,
					symbols,
					numbers
					);
	addPass(passw,str([minLength,
					maxLength,
					leastLow,
					leastUpp,
					leastSym,
					leastNum,
					lowers,
					uppers,
					symbols,
					numbers]));
	print(rot(passw));
	return(True);

def evaluateArgs(argv):
	global debug,PASSWDS,HASHPWDS;
	minLength=8;
	maxLength=32;
	leastLow=1;
	leastUpp=1;
	leastSym=1;
	leastNum=1;
	lowers=True;
	uppers=True;
	symbols=True;
	numbers=True;
	
	vargs=argv;
	try:
		vargs.pop(0);
	except:
		pass;
	if  (isIn(["-h","-H","--help","-?","/?"],vargs)):
		return(HELP());
	for f in vargs:
		if  (f.startswith("-D")):
				debug=ON;
		elif(f.startswith("-C")):
			PASSWDS,HASHPWDS=[],[];
			saveConfig();
			print("Store file cleaned");
		elif(f.startswith("-R")):
			listPass();
		elif(f.startswith("-X")):
			listExtended();
		elif(f.startswith("-n")):
			try:
				n=f[2:];
				leastNum=int(n);
			except:
				pass;
		elif(f.startswith("-l")):
			try:
				n=f[2:];
				leastLow=int(n);
			except:
				pass;
		elif(f.startswith("-u")):
			try:
				n=f[2:];
				leastUpp=int(n);
			except:
				pass;
		elif(f.startswith("-s")):
			try:
				n=f[2:];
				leastSym=int(n);
			except:
				pass;
		elif(f.startswith("-m")):
			try:
				n=f[2:];
				minLength=int(n);
			except:
				pass;
		elif(f.startswith("-M")):
			try:
				n=f[2:];
				maxLength=int(n);
			except:
				pass;
		elif(f.startswith("--L")):
			lowers=False;
		elif(f.startswith("--U")):
			uppers=False;
		elif(f.startswith("--N")):
			numbers=False;
		elif(f.startswith("--S")):
			symbols=False;

		elif(f.startswith("-L")):
			lowers=True;
		elif(f.startswith("-U")):
			uppers=True;
		elif(f.startswith("-N")):
			numbers=True;
		elif(f.startswith("-S")):
			symbols=True;

	if("-v" in vargs):
		print("Parameters:");
		print("minLength:\t"+str(minLength));
		print("maxLength:\t"+str(maxLength));
		print("   lowers:\t"+str(lowers));
		print(" leastLow:\t"+str(leastLow));
		print("   uppers:\t"+str(uppers));
		print(" leastUpp:\t"+str(leastUpp));
		print("  symbols:\t"+str(symbols));
		print(" leastSym:\t"+str(leastSym));
		print("  numbers:\t"+str(numbers));
		print(" leastNum:\t"+str(leastNum));
		
			
	if("-g" in vargs	or	len(vargs)<1):
			generatePassword(minLength,
					maxLength,
					leastLow,
					leastUpp,
					leastSym,
					leastNum,
					lowers,
					uppers,
					symbols,
					numbers);
	
def main(*vargs):
	loadConfig();
	argv=list(*vargs);
	evaluateArgs(argv);
	return(0);
	
if __name__ == '__main__':
	sys.exit(main(ARGV));
