s = 'C2POOL{0}_{1}(func,'

file = open('result_macro.txt', "w")

method_name = "ENUMERATE"

#first line
file.write("#define {0}v1) func(v1)\n".format(s.format(2, method_name)))

#other lines 
# [1------------------------][2---] [3--------------------] [4-------------------]
# #define C2POOL3_PASTE(func,v1,v2) C2POOL2_PASTE(func, v1) C2POOL2_PASTE(func,v2)
for i in range(3, 65):
    # 1:
    line = "#define "
    line += s.format(i, method_name)

    # 2:
    for h in range(1, i):
        line += 'v{0},'.format(h)
    line = line[:-1]
    line += ") "

    # 3:
    line += s.format(2, method_name) + " v1) "
    
    # 4:
    line += s.format(i-1, method_name)
    for h in range(2, i):
        line += 'v{0},'.format(h)
    line = line[:-1]
    line += ") "

    # end line
    file.write(line+"\n")

file.close()