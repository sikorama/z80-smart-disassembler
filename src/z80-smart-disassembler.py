# Z80 Smart Disassembler
# by Stephane Sikora
# with some code from https://github.com/deadsy/py_z80/blob/master/z80da.py

#TODO/FIXME:
# Using external symbol files for dot graph

from z80da import disassemble
from z80cpc import checkFirmwareVector
import subprocess
import argparse
import string

#-- Globals

# Memory = 64Kb
mem= [0] * 65536
# Code areas
# Exceptions: memcode[pc] = -1. will be ignored
memcode= [-1] * 65536
memopcode= {}

comments={}

#Data for generating dot graph
#Jump list
jplist={} #[]
#Jump destination list
jptolist={}
#Consecutive opcodes for generating dot graph
nextopcode= {} #[-1] * 65536


def hx( v ):
   "Converts a number to an hex string"
   return '#'+format(v, '02x')

def addJump(adrfrom,adrto,opcode,jptype,stack,jpl):
    #print(stack,jpl)
    if stack!=None:
        stack.append(adrto)
    if jpl!=None:
        jpl[adrfrom] = [adrfrom,adrto,jptype,opcode]
    jptolist[adrto] = 1
    #print(stack,jpl)

def arrayAsDB(a):
    res = "db "
    st = ''
    nc = 0
    for i in range(len(a)):
        if i != 0:
            res+= ','
        # Check if there is some text
        if a[i][0]=='#':
            v = int(a[i][1:],16)
        else:
            v = int(a[i][0:])
        res+=hx(v) #a[i]
        l = v & 0xdf # Remove bit 5
        if l>=65 and l<65+26:
            nc+=1
            if v&32==32:
                st+=string.ascii_lowercase[l-65]
            else:
                st+=string.ascii_uppercase[l-65]
        else:
            st = st+'.'
    if nc>0:
        res += ' ;'+st
    return res


ap = argparse.ArgumentParser()
ap.add_argument('-i', '--input-file', default='input.bin', help='Input Binary file')
ap.add_argument('-o', '--output-prefix', help='Prefix used for generating output files')
ap.add_argument('-O', '--org', default="0", help='Adress of the beginning of the bin file in RAM')
ap.add_argument('-p', '--disark-path', default='', help='Path to Disark executable')
ap.add_argument('-d', '--use-disark', action='store_true', help='Use Disark for disassembling')
ap.add_argument('-a', '--start-adresses', nargs="+", help='Start adresses (in hex format)')
ap.add_argument('-s', '--symbols',  help='Additional symbol file to use for disassembling with disark.')
ap.add_argument('-r', '--regions',  help='Region file to use for disassembling with disark.')
ap.add_argument('-x', '--exclude-adresses',  nargs="+", help='Exclude adresses (in hex format)')
ap.add_argument('-v', '--verbose', default=0, action='count', help='Increase Verbosity')
ap.add_argument('-G', '--dot', action='store_true' , help='Generates a dot (graphviz) file')
ap.add_argument('-c', '--check',  action='store_true', help='Reassemble and diff')
ap.add_argument('-R', '--rasm',  default='rasm', help='Path to rasm binary')
ap.add_argument('-u', '--undocumentedOpcodes',  action='store_false', help='Undocumented Opcodes to bytes')

#ap.add_argument('-D', '--diff',  help='Path to diff tool')
args = vars(ap.parse_args())

if args['verbose']>0:
    print('Parameters:')
    for a in args:
        print(a, ':' , args[a])

output_prefix=args['input_file']
if args['output_prefix']!=None:
    output_prefix=args['output_prefix']

def storeNextPC(pc,nextpc):
    nextopaddr = pc + nextpc
    nextopcode[pc] = nextopaddr

fileName=args['input_file']
with open(fileName, mode='rb') as file:
    fileContent = file.read()

#Copy file content to mem (FIXME: could be much faster)
offset = int(args['org'],16)
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
            if args['verbose']>2:
                print(hx(pc),op,hx(mem[pc]))
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

        if opcode=='jp' or opcode=='jr' or ('rst' in opcode):
            #is it a jp(hl) jp(ix) ... ?
            if ('hl' in data) or ('ix' in data) or ('iy' in data):
                print(hx(start_pc), hx(pc), 'JP ('+data+') encoutered')
                break;
            #is there a condition?
            if ',' in op[1]:
                ii = op[1].index(',')+1
                #print (hx(start_pc), hx(pc),opcode,data,sz,op[1][ii:], hx(int(op[1][ii:],16)))
                addJump(pc, int(op[1][ii:],16),opcode,"jump cond", pcstack,jplist)
                #pcstack.append(int(op[1][ii:],16))
                storeNextPC(pc,op[2])
                pc += op[2]
            else:
                #print (hx(start_pc), hx(pc),op)
                addJump(pc, int(op[1],16),opcode,'jump',None,jplist)
                pc = int(op[1],16)
                start_pc = pc

        elif opcode=='call' :
            if ',' in op[1]:
                ii = op[1].index(',')+1
                jpl='call cond'
            else:
                ii = 0
                jpl='call'
            addJump(pc, int(op[1][ii:],16),opcode,jpl,pcstack,jplist)
            storeNextPC(pc,op[2])
            pc += op[2]
        elif  opcode=='djnz':
            addJump(pc, int(op[1],16),opcode,'jump cond',pcstack,jplist)
            storeNextPC(pc,op[2])
            pc += op[2]
        elif opcode=='ret' and data=='':
            #print('RET=> on arrete' , opcode,data,pc,op[2], pcstack)
            break
        else:
            #print(opcode,data)
            storeNextPC(pc,op[2])
            pc += op[2]


#Generate Region file
symfilename = args['regions']
if args['regions'] == None :
    # Symbols (for disark)
    curZoneCodeType=True
    curZoneStart=0
    curZoneEnd=0
    symfilename=output_prefix+'.reg'
    symfile = open(symfilename,"w")

    for a in args['start_adresses']:
        symfile.write('start_'+a + ' #' + a + '\n');
        #symfile.write('start'+format(a,'04x') + ' equ ' + hx(a) + '\n');

    i = 0
    while i<len(mem):
        t = memcode[i]>0

        if t != curZoneCodeType:
            # Zone complete curZoneStart-curZoneEnd
            #print(';Zone',curZoneCodeType, hx(curZoneStart),hx(curZoneEnd-curZoneStart))
            if curZoneCodeType==False:
                symfile.write('data'+format(curZoneStart,'04x')+' '+hx(curZoneStart)+ '\n');
                symfile.write('DisarkByteRegionStart'+hx(curZoneStart)+' '+hx(curZoneStart)+ '\n');
                symfile.write('DisarkByteRegionEnd'+hx(curZoneStart)+' '+hx(curZoneEnd+1)+ '\n');
            curZoneStart = i
            curZoneCodeType = t


        if t==True:
            try:
                curZoneEnd=i+memopcode[i][2]-1
                i+=memopcode[i][2]
            except Exception as e:
                print(Exception, e, t, "i==",i,memcode[i])
                curZoneEnd=i
                i+=1
        else:
            curZoneEnd=i
            i+=1

    #Last region
    if curZoneCodeType==False:
        symfile.write('DisarkByteRegionStartLast'+' '+hx(curZoneStart)+ '\n');
        symfile.write('DisarkByteRegionEndLast'+' '+hx(curZoneEnd)+ '\n');


    symfile.close()


#Additional symbols files: concatenate region file and symbol file
if args['symbols'] != None :
    fullsymfilename =output_prefix+'-full.sym'
    with open(fullsymfilename, "w") as f1:
        with open(symfilename) as f:
            for line in f:
                f1.write(line)
        with open(args['symbols']) as f:
            for line in f:
                f1.write(line)
    symfilename = fullsymfilename

outasm = output_prefix+".asm"
# Disark
if args['use_disark']==True:
    tmpfilename=output_prefix+".tmp"
    path=  args['disark_path'] + "Disark"
    print('Now running disark...', path, tmpfilename, symfilename)
    options = [path, args["input_file"], tmpfilename, "--loadAddress", str(offset) , "--genLabels", "--src8bitsValuesInHex", "--src16bitsValuesInHex", "--symbolFile",symfilename]
    if args['undocumentedOpcodes']==False:
        options.append("--undocumentedOpcodesToBytes")

    print(options)
    res = subprocess.run(options)
    print(res)

    print('Post processing...')
    # Post processing
    with open(tmpfilename, mode='rt') as file:
        dfileContent = file.readlines()
    dbcount = 0
    dbl=[]
    asmfile = open(outasm,"w")
    #print(fileContent)

    #TODO: handle dw
    for l in dfileContent:
        ll=l.strip()
        # starts by a label?
        if ('start' in ll and ll.index('start')==0) or ('data' in ll and ll.index('data')==0) or ('lab' in ll and ll.index('lab')==0):
            if len(dbl)>0:
                asmfile.write('  '+arrayAsDB(dbl)+'\n')
                dbl=[]
            spl = ll.split(' ')
            asmfile.write(spl[0]+':\n')
            ll = ll[len(spl[0])+1:]

        if ('db' in ll) and (ll.index('db')==0):
            dbl.append(ll[3:])
            if len(dbl)==8:
                asmfile.write('  '+arrayAsDB(dbl)+'\n')
                dbl=[]
        else:
            if len(dbl)>0:
                asmfile.write('  '+arrayAsDB(dbl)+'\n')
                dbl=[]
            # Add comments
            comment=''
            comment = checkFirmwareVector(ll)
            if comment is False:
                comment=''
            else:
                comment=' ; Firmware: '+comment
            asmfile.write('  '+ll+comment + '\n')
    asmfile.close()
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

if args['check']==True:
    rasmpath=args['rasm']

    print('- running rasm', rasmpath, outasm)
    res = subprocess.run([rasmpath, outasm])
    print(res)

    print('- comparing')
    if res.returncode ==0:
        with open('rasmoutput.bin', mode='rb') as file:
            checkContent = file.read()
        l1 = len(fileContent)
        l2 = len(checkContent)
        if l1!=l2:
            print('Warning! File Length not matching ',l1,l2)
        for i in range(l1):
            if fileContent[i]!=checkContent[i]:
                print(hx(i+offset) , 'Not Matching! ', hx(fileContent[i]), hx(checkContent[i]) )

# Dot graph with all calls & jps
if args['dot']==True:
    print("Generating graphviz/dot file",output_prefix+".dot")
    dotfile = open(output_prefix+".dot","w")
    dotfile.write('digraph G {\n')
    #print(jplist)
    nodeAttributes = {}
    #Touis les sauts
    for j in jplist:
        i = jplist[j]
        options='[label="'+i[2]+'"]'
        nodeAttributes[i[0]]=1
        nodeAttributes[i[1]]=1
        dotfile.write('lab'+format(i[0],'04x')+' -> '+'lab'+format(i[1],'04x')+' '+options+';\n')

    # Bloc 1st and last address
    k0=None
    k1=0

    #print(sorted(list(nextopcode.keys())))
    # Consecutive instructions
    for k in sorted(list(nextopcode.keys())):
        nxt = nextopcode[k]
        #1st opcode of a series of instructions
        if k0==None:
            k0=k
            k1=k
        else:
            #Is there a jump at k ?
            if k in jplist:
                #adrfrom => [adrfrom,adrto,jptype,opcode]
                jpt = jplist[k][2]
                #Is it a conditional jump or a call?
                if ('cond' in jpt) or ('call' in jpt):
                    n1 = 'lab'+format(k0,'04x')
                    n2 = 'lab'+format(k,'04x')
                    dotfile.write(n1+' -> '+ n2 +' [style=dotted;] ;\n')
                    nodeAttributes[k0]=1
                    nodeAttributes[k]=1
                    k0=k
                    k1=k
                else:
                    k0=None
            else:
                #Did we jump here from somewhere?
                if k in jptolist:
                    n1 = 'lab'+format(k0,'04x')
                    n2 = 'lab'+format(k,'04x')
                    dotfile.write(n1+' -> '+ n2 +' [style=dotted;] ;\n')
                    nodeAttributes[k0]=1
                    nodeAttributes[k]=1
                    k0=k
                    k1=k
                else:
                    k1=nxt
                    if nxt in nextopcode:
                        #print(k,nxt, memopcode[k]);
                        options=''
                    else:
                        print(hx(k),hx(nxt), memopcode[k],memopcode[nxt]);
                        dotfile.write('lab'+format(k0,'04x')+' -> '+'lab'+format(k1,'02x')+'[style=dotted] ;\n')
                        nodeAttributes[k0]=1
                        nodeAttributes[k1]=1
                        k0=None

    for k in nodeAttributes:
        dotfile.write('lab'+format(k,'04x') + ' ['+'label="#'+format(k,'04x')+'"' +']'+';\n')

    dotfile.write('}\n')
    dotfile.close()

#python3.8.exe .\z80-smart-disassembler.py -a 5000 5003 5006 5009 5018 501e 5027 -i .\gng1985.BIN  -x b1 b941 5112 5269 -v -d -D
