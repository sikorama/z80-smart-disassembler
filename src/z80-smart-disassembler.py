# Z80 Smart Disassembler
# by Stephane Sikora
# with some code from https://github.com/deadsy/py_z80/blob/master/z80da.py

from z80da import disassemble
import subprocess
import argparse

def hx( v ):
   "Converts a number to an hex string"
   return '#'+format(v, '02x')   

def addJump(adrfrom,adrto,jptype,stack,jpl):
    #print(stack,jpl)
    stack.append(adrto)
    jpl.append([adrfrom,adrto,jptype])
    #print(stack,jpl)

def arrayAsDB(a):
    res = "db "
    for i in range(len(a)):
        if i != 0:
            res+= ','
        res+=a[i]
    return res


ap = argparse.ArgumentParser()
ap.add_argument('-i', '--input-file', default='input.bin', help='Input Binary file')
ap.add_argument('-o', '--output-prefix', help='Prefix used for generating output files')
ap.add_argument('-O', '--org', default=0, help='Adress of the beginning of the bin file in RAM')
ap.add_argument('-p', '--disark-path', default='', help='Path to Disark executable')
ap.add_argument('-d', '--use-disark', action='store_true', help='Use Disark for disassembling')
ap.add_argument('-a', '--start-adresses', nargs="+", help='Start adresses (in hex format)')
ap.add_argument('-s', '--symbols',  help='Symbol file to use for disassembling with disark.')
ap.add_argument('-r', '--regions',  help='Region file to use for disassembling with disark.')
ap.add_argument('-x', '--exclude-adresses',  nargs="+", help='Exclude adresses (in hex format)')
ap.add_argument('-v', '--verbose', action='store_true', help='Increase Verbosity')
ap.add_argument('-D', '--dot', action='store_true' , help='Generates a dot (graphviz) file')
args = vars(ap.parse_args())

if 'verbose' in args:
    for a in args:
        print(a, ':' , args[a])

output_prefix=args['input_file']
if args['output_prefix']!=None:
    output_prefix=args['output_prefix']

# Memory = 64Kb
mem= [0] * 65536
# Code areas
# Exceptions: memcode[pc] = -1. will be ignored
memcode= [-1] * 65536
memopcode= {}
abels={}
comments={}
#For generating dot graph
jplist=[] 


fileName=args['input_file']
with open(fileName, mode='rb') as file: 
    fileContent = file.read()

#Copy file content to mem (FIXME: could be musch faster)
offset = args['org']
for i in range(len(fileContent)):
    mem[i+offset] = fileContent[i]
    memcode[i+offset] = 0

#Exclude
if args['exclude_adresses'] != None:
    for a in args['exclude_adresses']:
        memcode[int(a,16)] = -1        

#Bytes distribution
#dist= [0] * 256
#for i in fileContent:
#    dist[i] += 1
#print(len((fileContent)))

#print(disassemble(fileContent,0x38))
if mem[0x38]==0xC3:
    print('Interruption #38 Handler: JP' , hx(mem[0x39] + 256*mem[0x3a]))

pcstack=[]
if 'start_adresses' in args:
    for a in args['start_adresses']:
        pcstack.append(int(a,16))

#Start parsing
while len(pcstack)>0:
    start_pc = pc =pcstack.pop(0)    
    while True:
        # decoder l'instruction en PC de facon simple
        try:
            op = disassemble(mem,pc)        
            (opcode,data,sz) = op
        except Exception as e:
            print(e,pc)
            break;

        if memcode[pc]<0:
            break;

        if memcode[pc]>1: # and memcode[pc]!=1:
            print(hx(start_pc), hx(pc), 'Warning: Jumping in the middle of an instruction!' )
            break;

        if memcode[pc]>0:
            break;
                
        #Mark as code (>0)
        for i in range(0,op[2]):
            memcode[pc+i] = 1+i
        
        memopcode[pc] = op

        if opcode=='ld':
            ldp=data.split(',')
            if ldp[0]==ldp[1]:
                print(hx(start_pc), hx(pc), 'Warning, unusual instruction:', opcode,data)

        if opcode=='jp' or opcode=='jr' or opcode=='rst':
            #is it a jp(hl) jp(ix) ... ?
            if ('hl' in data) or ('ix' in data) or ('iy' in data):
                print(hx(start_pc), hx(pc), 'JP ('+data+') encoutered') 
                break;
            #is there a condition?        
            if ',' in op[1]:
                ii = op[1].index(',')+1
                #print (hx(start_pc), hx(pc),opcode,data,sz,op[1][ii:], hx(int(op[1][ii:],16)))
                addJump(pc, int(op[1][ii:],16),opcode,pcstack,jplist)
                #pcstack.append(int(op[1][ii:],16))
                pc += op[2]
            else:
                #print (hx(start_pc), hx(pc),op)                
                pc = int(op[1],16)
                start_pc = pc
        elif opcode=='call':
            if ',' in op[1]:
                ii = op[1].index(',')+1
            else:
                ii = 0
            #print (hx(start_pc), hx(pc),opcode,data,sz,op[1][ii:], hx(int(op[1][ii:],16)))
            addJump(pc, int(op[1][ii:],16),opcode,pcstack,jplist)
            #pcstack.append(int(op[1][ii:],16))
            pc += op[2]
        elif opcode=='ret' and data=='':
            break
        else:
            pc += op[2]
        

#Generate Region file
#TODO: concatenate symbol file
symfilename = args['regions']
if args['regions'] == None :
    # Symbols (for disark)
    curZoneCodeType=True
    curZoneStart=0
    curZoneEnd=0
    symfilename=output_prefix+'.sym'
    symfile = open(symfilename,"w") 

    i = 0
    while i<len(mem):
        t = memcode[i]>0

        if t != curZoneCodeType:
            # Zone complete curZoneStart-curZoneEnd
            #print(';Zone',curZoneCodeType, hx(curZoneStart),hx(curZoneEnd-curZoneStart))
            if curZoneCodeType==False:
                symfile.write('DisarkByteRegionStart'+hx(curZoneStart)+' '+hx(curZoneStart)+ '\n');
                symfile.write('DisarkByteRegionEnd'+hx(curZoneStart)+' '+hx(curZoneEnd+1)+ '\n');
            curZoneStart = i
            curZoneCodeType = t

        if t==True:
            curZoneEnd=i+memopcode[i][2]-1
            i+=memopcode[i][2]
        else:
            curZoneEnd=i
            i+=1

    symfile.close()

#TODO: additional symbols files
if args['symbols'] != None :
    print('TODO: concatenate Symbol files')

#Last zone?

outasm = output_prefix+".asm"
# Disark
if args['use_disark']==True:
    tmpfilename=output_prefix+".tmp"
    path=  args['disark_path'] + "Disark"
    print('Now running disark...', path, tmpfilename, symfilename)
    res = subprocess.run([path, args["input_file"], tmpfilename, "--genLabels", "--src8bitsValuesInHex", "--src16bitsValuesInHex", "--undocumentedOpcodesToBytes",  "--symbolFile",symfilename])
    print(res)

    print('Post processing result')
    dotfile = open(output_prefix+".dot","w") 
    # Post processing
        
    
    with open(tmpfilename, mode='rt') as file: 
        fileContent = file.readlines()
    dbcount = 0
    dbl=[]
    asmfile = open(outasm,"w") 
    #print(fileContent)
    for l in fileContent:        
        ll=l.strip()        
        if ('db' in ll) and (ll.index('db')==0):
            dbl.append(ll[3:])
            if len(dbl)==8: 
                asmfile.write(arrayAsDB(dbl)+'\n')
                dbl=[]
        else:
            if len(dbl)>0: 
                asmfile.write(arrayAsDB(dbl)+'\n')
                dbl=[]
            asmfile.write(l)                
            
else:
    #Generate asm file
    print('Generating ', outasm)
    print("It's better to use disark with -d option")
    asmfile = open(outasm,"w") 
    i=0
    while i<len(mem):
        if memcode[i]>0:
            asmfile.write(' ' + memopcode[i][0] + ' ' + memopcode[i][1] + '\n')        
            i+=memopcode[i][2]
        else:
            #TODO: Group dbs
            asmfile.write(' db ' +  hx(mem[i]) + '\n')
            i+=1

    asmfile.close()


# Dot graph with all calls & jps
if args['dot']==True:
    print("Generating dot file",output_prefix+".dot")
    dotfile = open(output_prefix+".dot","w") 
    dotfile.write('digraph G {\n')
    #print(jplist)
    for i in jplist:
        options='[label="'+i[2]+'"]'
        dotfile.write('lab'+format(i[0],'02x')+' -> '+'lab'+format(i[1],'02x')+' '+options+';\n')
    dotfile.write('}\n')
    dotfile.close()

#python3.8.exe .\z80-smart-disassembler.py -a 5000 5003 5006 5009 5018 501e 5027 -i .\gng1985.BIN  -x b1 b941 5112 5269 -v -d -D   
