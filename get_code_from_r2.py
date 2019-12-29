#!/usr/bin/env python3
import sys
import argparse
import r2pipe


def CutThis(_writePath):
	lines = open(_writePath, 'r').readlines()
	with open(_writePath, 'w') as lineCutter:
		for line in lines:
			line = line[43:]
			newline = ""
			flag = False
			for sym in line:
				if (sym ==';' or flag == True) and (sym != '\n'):
					sym = ' '
					flag = True
				newline += sym
			lineCutter.write(newline)


def Analyse(_readPath, _writePath, _startAddr, arch, _instSize = 10):
	try:
		if _instSize == None:
			print("Standart instSize = 10")
			_instSize = 10
		r2 = r2pipe.open(filename = _readPath, flags=['-a', arch])
		r2.cmd("e asm.esil = true; s " +_startAddr)
		writer = open(_writePath, 'w')
		#writer.write("Start address is {0}".format(_startAddr))
		writer.write(r2.cmd("pd " + str(_instSize)))
		writer.close()
		CutThis(_writePath)
		print("\n\nSuccessful")
	except:
		print ("Invalid arguments")
	
def createParser():
	parser = argparse.ArgumentParser()
	parser.add_argument('-f', '--filein', help = "Путь к анализиемому файлу", required = True)
	parser.add_argument('-o', '--outfile', help = "Путь к файлу вывода", required = True)
	parser.add_argument('-s', '--start', help = "Адрес начала анализа", required = True)
	parser.add_argument('-n', '--number', help = "Кол-во анализируемых инструкций")
	parser.add_argument('-a', '--arch', help = "Архитектура процессора")
	return parser


def main():
	parser = createParser()
	namespace = parser.parse_args(sys.argv[1:])
	readPath = namespace.filein
	writePath = namespace.outfile
	startAddr = namespace.start
	instSize = namespace.number
	arch = namespace.arch
	Analyse(readPath, writePath, startAddr, arch, instSize)



if __name__ == '__main__':
	print("\n\n===============================")
	print("         Started.")
	print("==============================")
	main()