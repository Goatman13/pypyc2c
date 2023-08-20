#
# PPC To C
#
# by working with the disassembled text this plugin should
# work with both big and little endian PPC.
#

from ida_bytes import *
from idaapi import *
from idc import *
import idaapi
import ida_bytes
import idc

MASK32_ALLSET = 0xFFFFFFFF
MASK64_ALLSET = 0xFFFFFFFFFFFFFFFF

g_mnem = 0
g_opnd_s0 = 0
g_opnd_s1 = 0
g_opnd_s2 = 0
g_opnd_s3 = 0
g_opnd_s4 = 0

g_RA = 0
g_RS = 0
g_RB = 0
g_SH = 0
g_MB = 0
g_ME = 0


# generates the mask between MaskBegin(MB) and MaskEnd(ME) inclusive
# MB and ME should be values 0 - 31
def GenerateMask32(MB, ME):
	
	if(	MB <  0 or ME <  0 or MB > 31 or ME > 31 ):
		msg("Error with paramters GenerateMask32({:d}, {:d})\n".format(MB, ME))
		return 0

	mask = 0
	if(MB < ME+1):
		# normal mask
		while MB < ME+1:
			mask = mask | (1<<(31-MB))
			MB += 1
	elif(MB == ME+1):
		# all mask bits set
		mask = MASK32_ALLSET
	elif(MB > ME+1):
		# split mask
		mask_lo = GenerateMask32(0, ME)
		mask_hi = GenerateMask32(MB, 31)
		mask = mask_lo | mask_hi

	return mask


# generates the mask between MaskBegin(MB) and MaskEnd(ME) inclusive
# MB and ME should be values 0 - 63
def GenerateMask64(MB, ME):
	
	if(	MB <  0 or ME <  0 or MB > 63 or ME > 63 ):
		msg("Error with paramters GenerateMask64({:d}, {:d})\n".format(MB, ME))
		return 0

	mask = 0
	if(MB < ME+1):
		# normal mask
		while MB < ME+1:
			mask = mask | (1<<(63-MB))
			MB += 1
	elif(MB == ME+1):
		# all mask bits set
		mask = MASK64_ALLSET
	elif(MB > ME+1):
		# split mask
		mask_lo = GenerateMask64(0, ME)
		mask_hi = GenerateMask64(MB, 63)
		mask = mask_lo | mask_hi

	return mask


# generate string showing rotation or shifting within instruction
# returns:	true if string requires brackets if a mask is used, ie: (r4 << 2) & 0xFF
def GenerateRotate32(src, leftShift, rightShift, mask):
	
	ret_str = 0
	# work out "rotate" part of the instruction
	if(	(leftShift== 0 and rightShift==32) or (leftShift==32 and rightShift== 0 )):
		return src

	if(((MASK32_ALLSET<<leftShift ) & mask) == 0):
		# right shift only
		if((MASK32_ALLSET>>rightShift) == mask):
			mask = MASK32_ALLSET
		ret_str = src + " >> {:d}".format(rightShift)
	elif(((MASK32_ALLSET>>rightShift) & mask) == 0):
		# left shift only
		if((MASK32_ALLSET<<leftShift) == mask):
			mask = MASK32_ALLSET
		ret_str = src + " << {:d}".format(leftShift)
	else:
		# shift both ways
		ret_str = "(" + src + " << {:d}) | (".format(leftShift) + src + " >> {:d})".format(rightShift)
	return ret_str


# generate string showing rotation or shifting within instruction
# returns:	true if string requires brackets if a mask is used, ie: (r4 << 2) & 0xFF
def GenerateRotate64(src, leftShift, rightShift, mask):
	
	# work out "rotate" part of the instruction
	if((leftShift == 0 and rightShift == 64) or (leftShift == 64 and rightShift == 0)):
		# no rotation
		return src

	if(((MASK64_ALLSET<<leftShift ) & mask) == 0):
		# right shift only
		if((MASK64_ALLSET>>rightShift) == mask):
			mask = MASK64_ALLSET
		ret_str = src + " >> {:d}".format(rightShift)
	elif(((MASK64_ALLSET>>rightShift) & mask) == 0):
		# left shift only
		if((MASK64_ALLSET<<leftShift) == mask):
			mask = MASK64_ALLSET
		ret_str = src + " << {:d}".format(leftShift)
	else:
		# shift both ways
		ret_str = "(" + src + " << {:d}) | (".format(leftShift) + src + " >> {:d})".format(rightShift)
	return ret_str


# register rotate and immediate mask
def Rotate_iMask32(ea, g_mnem, g_RA, g_RS, leftRotate, mb, me):
	
	ret_str = 0
	# calculate the mask
	# if no mask, then result is always 0
	mask = GenerateMask32(mb, me)
	if(mask == 0):
		# no rotation
		ret_str = g_RA + " = 0"
		return ret_str

	# work out "rotate" part of the instruction
	# if all mask bits are set, then no need to use the mask
	rot_str = 0
	rot_str = g_RS + " << " + leftRotate + " | " + g_RS + " >> 32 - " + leftRotate
	if(mask == MASK32_ALLSET):
		#qsnprintf(buff, buffSize, "%s = (u32)(%s)", g_RA, rot_str)
		ret_str = g_RA + " = " + rot_str
		return ret_str

	# generate mask string
	mask_str = 0
	if (mask < 10):
		mask_str = "{:X}".format(mask)
	else:
		mask_str = "0x{:X}".format( mask)

	# generate the resultant string
	# "%s = (%s) & %s"
	ret_str = g_RA + " = " + "(" + rot_str + ") & " + mask_str
	return ret_str


# immediate rotate and immediate mask
def iRotate_iMask32(ea, g_mnem, g_RA, g_RS, leftRotate, mb, me):
	
	ret_str = 0
	# calculate the mask
	# if no mask, then result is always 0
	mask = GenerateMask32(mb, me)
	if(mask == 0):
		ret_str = g_RA + " = 0"
		return ret_str

	# work out "rotate" part of the instruction
	# if all mask bits are set, then no need to use the mask
	rot_str = 0
	rot_str = GenerateRotate32(g_RS, leftRotate, 32-leftRotate, mask)
	if(mask == MASK32_ALLSET):
		ret_str = g_RA + " = " + rot_str
		return ret_str

	# generate mask string
	mask_str = 0
	if (mask < 10):
		mask_str = "{:X}".format(mask)
	else:
		mask_str = "0x{:X}".format(mask)
		
	# generate the resultant string
	ret_str = g_RA + " = " + "(" + rot_str + ") & " + mask_str
	return ret_str


# insert immediate rotate and immediate mask
def insert_iRotate_iMask32(ea, g_mnem, g_RA, g_RS, leftRotate, mb, me):
	
	ret_str = 0
	# calculate the mask
	# if no mask, then result is always 0
	mask = GenerateMask32(mb, me)
	if(mask == 0):
		ret_str = g_RA + " = " + g_RA
		return ret_str

	# work out "rotate" part of the instruction
	# if all mask bits are set, then no need to use the mask
	rot_str = 0
	rot_str =  GenerateRotate32(g_RS, leftRotate, 32-leftRotate, mask)
	if(mask == MASK32_ALLSET):
		ret_str = g_RA + " = " + rot_str
		return ret_str

	# generate mask strings
	mask_str = 0
	not_mask = 0
	not_mask_str = 0
	
	# generate mask string
	if (mask < 10):
		mask_str = "{:X}".format(mask)
	else:
		mask_str = "0x{:X}".format( mask)
	
	#not_mask = ~mask
	## generate not_mask string
	#if (mask < 10):
	#	not_mask_str.format("{:X}", not_mask)
	#else:
	#	not_mask_str.format("0x{:X}", not_mask)
	#	
	# generate the resultant string
	#"%s = (%s & ~%s) | (%s & %s)"
	ret_str = g_RA + " = (" + g_RA + " & ~" + mask_str + ") | (" + rot_str + " & " + mask_str + ")"
	return ret_str



# register rotate and immediate mask
def Rotate_iMask64(ea, g_mnem, g_RA, g_RS, leftRotate, mb, me):
	
	ret_str = 0
	# calculate the mask
	# if no mask, then result is always 0
	mask = GenerateMask64(mb, me)
	if(mask == 0):
		ret_str = g_RA + " = 0"
		return ret_str

	# work out "rotate" part of the instruction
	# if all mask bits are set, then no need to use the mask
	rot_str = 0
	rot_str = g_RS + " << " + leftRotate + " | " + g_RS + " >> 64-" + leftRotate
	if(mask == MASK64_ALLSET):
		#qsnprintf(buff, buffSize, "%s = (u32)(%s)", g_RA, rot_str)
		ret_str = g_RA + " = " + rot_str
		return ret_str

	# generate mask string
	mask_str = 0
	if (mask < 10):
		mask_str = "{:X}".format(mask)
	else:
		mask_str = "0x{:X}".format( mask)

	# generate the resultant string
	ret_str = g_RA + " = " + "(" + rot_str + ") & " + mask_str
	return ret_str


# immediate rotate and immediate mask
def iRotate_iMask64(ea, g_mnem, g_RA, g_RS, leftRotate, mb, me):
	
	ret_str = 0
	# calculate the mask
	# if no mask, then result is always 0
	mask = GenerateMask64(mb, me)
	if(mask == 0):
		ret_str = g_RA + " = 0"
		return ret_str

	# work out "rotate" part of the instruction
	# if all mask bits are set, then no need to use the mask
	rot_str = 0
	rot_str = GenerateRotate64(g_RS, leftRotate, 64-leftRotate, mask)
	if(mask == MASK64_ALLSET):
		ret_str = g_RA + " = " + rot_str
		return ret_str

	# generate mask string
	mask_str = 0
	if (mask < 10):
		mask_str = "{:X}".format(mask)
	else:
		mask_str = "0x{:X}".format( mask)

	# generate the resultant string
	ret_str = g_RA + " = " + "(" + rot_str + ") & " + mask_str
	return ret_str


# insert immediate rotate and immediate mask
def insert_iRotate_iMask64(ea, g_mnem, g_RA, g_RS, leftRotate, mb, me):
	
	ret_str = 0
	# calculate the mask
	# if no mask, then result is always 0
	mask = GenerateMask64(mb, me)
	if(mask == 0):
		ret_str = g_RA + " = " + g_RA
		return ret_str

	# work out "rotate" part of the instruction
	# if all mask bits are set, then no need to use the mask
	rot_str = 0
	rot_str =  GenerateRotate64(g_RS, leftRotate, 64-leftRotate, mask)
	if(mask == MASK64_ALLSET):
		ret_str = g_RA + " = " + rot_str
		return ret_str

	# generate mask strings
	mask_str = 0
	not_mask = 0
	not_mask_str = 0
	
	# generate mask string
	if (mask < 10):
		mask_str = "{:X}".format(mask)
	else:
		mask_str = "0x{:X}".format(mask)
	
	#not_mask = ~mask
	## generate not_mask string
	#if (mask < 10):
	#	not_mask_str = "{:X}".format(not_mask)
	#else:
	#	not_mask_str  = "0x{:X}".format(not_mask)
		
	# generate the resultant string
	#"%s = (%s & ~%s) | (%s & %s)"
	ret_str = g_RA + " = (" + g_RA + " & ~" + mask_str + ") | (" + rot_str + " & " + mask_str + ")"
	return ret_str


# ==================================================================
#
# instructions
#
# ==================================================================


def clrlwi(ea, g_mnem, g_RA, g_RS, n):
	
	# Clear left immediate
	# clrlwi RA, RS, n
	# (rlwinm RA, RS, 0, n, 31)
	g_SH = 0
	g_MB = n
	g_ME = 31

	return iRotate_iMask32(ea, g_mnem, g_RA, g_RS, g_SH, g_MB, g_ME)


def clrldi(ea, g_mnem, g_RA, g_RS, n):
	
	# Rotate Left Double Word Immediate then Clear Left
	# rldicl RA, RS, SH, MB
	g_SH = 0
	g_MB = n
	g_ME = 63

	return iRotate_iMask64(ea, g_mnem, g_RA, g_RS, g_SH, g_MB, g_ME)


def clrrwi(ea, g_mnem, g_RA, g_RS, n):
	
	# Clear right immediate
	# clrrwi RA, RS, n
	# (rlwinm RA, RS, 0, 0, 31-n)
	g_SH = 0
	g_MB = 0
	g_ME = 31-n

	return iRotate_iMask32(ea, g_mnem, g_RA, g_RS, g_SH, g_MB, g_ME)


def clrrdi(ea, g_mnem, g_RA, g_RS, n):
	
	# Clear right immediate
	# clrrdi RA, RS, n
	# (rlwinm RA, RS, 0, 0, 31-n)
	g_SH = 0
	g_MB = 0
	g_ME = 63-n

	return iRotate_iMask64(ea, g_mnem, g_RA, g_RS, g_SH, g_MB, g_ME)


def clrlslwi(ea, g_mnem, g_RA, g_RS, b, n):
	
	# clrlslwi RA, RS, b, n
	# (rlwinm RA, RS, b-n, 31-n)
	g_SH = n
	g_MB = b-n
	g_ME = 31-n

	return iRotate_iMask32(ea, g_mnem, g_RA, g_RS, g_SH, g_MB, g_ME)


def clrlsldi(ea, g_mnem, g_RA, g_RS, b, n):
	
	# clrlsldi RA, RS, b, n
	# (rlwinm RA, RS, b-n, 31-n)
	g_SH = n
	g_MB = b-n
	g_ME = 63-n

	return iRotate_iMask64(ea, g_mnem, g_RA, g_RS, g_SH, g_MB, g_ME)


def extrwi(ea, g_mnem, g_RA, g_RS, n, b):
	
	# Extract and right justify immediate
	# extrwi RA, RS, n, b
	# rlwinm RA, RS, b+n, 32-n, 31
	g_SH = b+n
	g_MB = 32-n
	g_ME = 31

	return iRotate_iMask32(ea, g_mnem, g_RA, g_RS, g_SH, g_MB, g_ME)


def extrdi(ea, g_mnem, g_RA, g_RS, n ,b):
	
	# Rotate Left Double Word Immediate then Clear Left
	# rldicl RA, RS, SH, MB
	g_SH = b+n
	g_MB = 64-n
	g_ME = 63

	return iRotate_iMask64(ea, g_mnem, g_RA, g_RS, g_SH, g_MB, g_ME)


def extlwi(ea, g_mnem, g_RA, g_RS, n, b):
	
	# Extract and left justify immediate
	# extlwi RA, RS, n, b
	# rlwinm RA, RS, b, 0, n-1
	g_SH = b
	g_MB = 0
	g_ME = n-1

	return iRotate_iMask32(ea, g_mnem, g_RA, g_RS, g_SH, g_MB, g_ME)


def extldi(ea, g_mnem, g_RA, g_RS, n, b):
	
	# Extract and left justify immediate
	# extldi RA, RS, n, b
	# rlwinm RA, RS, b, 0, n-1
	g_SH = b
	g_MB = 0
	g_ME = n-1

	return iRotate_iMask64(ea, g_mnem, g_RA, g_RS, g_SH, g_MB, g_ME)


def inslwi(ea, g_mnem, g_RA, g_RS, n, b):
	
	# Insert from left immediate
	# inslwi RA, RS, n, b
	# rlwimi RA, RS, 32-b, b, (b+n)-1
	g_SH = 32-b
	g_MB = b
	g_ME = b+n-1

	return insert_iRotate_iMask32(ea, g_mnem, g_RA, g_RS, g_SH, g_MB, g_ME)


def insrwi(ea, g_mnem, g_RA, g_RS, n, b):
	
	# Insert from right immediate
	# insrwi RA, RS, n, b
	# rlwimi RA, RS, 32-(b+n), b, (b+n)-1
	g_SH = 32-(b+n)
	g_MB = b
	g_ME = b+n-1

	return insert_iRotate_iMask32(ea, g_mnem, g_RA, g_RS, g_SH, g_MB, g_ME)


def insrdi(ea, g_mnem, g_RA, g_RS, n, b):
	
	# Rotate Left Double Word Immediate then Mask Insert
	# rldimi RA, RS, SH, MB
	# n how many bits, b staring from
	g_SH = 64-(b+n)
	g_MB = b
	g_ME = ~n

	return insert_iRotate_iMask64(ea, g_mnem, g_RA, g_RS, g_SH, g_MB, g_ME)


def rlwinm(ea, g_mnem, g_RA, g_RS, g_SH, g_MB, g_ME):
	
	# Rotate Left Word Immediate Then AND with Mask
	# rlwinm RA, RS, SH, MB, ME

	return iRotate_iMask32(ea, g_mnem, g_RA, g_RS, g_SH, g_MB, g_ME)


def rlwnm(ea, g_mnem, g_RA, g_RS, g_RB, g_MB, g_ME):
	
	# Rotate Left Word Then AND with Mask
	# rlwnm RA, RS, RB, MB, ME

	return Rotate_iMask32(ea, g_mnem, g_RA, g_RS, g_RB, g_MB, g_ME)


def rotlwi(ea, g_mnem, g_RA, g_RS, n):
	
	# Rotate left immediate
	# rotlwi RA, RS, n
	# rlwinm RA, RS, n, 0, 31
	g_SH = n
	g_MB = 0
	g_ME = 31

	return iRotate_iMask32(ea, g_mnem, g_RA, g_RS, g_SH, g_MB, g_ME)


def rotrwi(ea, g_mnem, g_RA, g_RS, n):
	
	# Rotate right immediate
	# rotrwi RA, RS, n
	# rlwinm RA, RS, 32-n, 0, 31
	g_SH = 32-n
	g_MB = 0
	g_ME = 31

	return iRotate_iMask32(ea, g_mnem, g_RA, g_RS, g_SH, g_MB, g_ME)


def rotlw(ea, g_mnem, g_RA, g_RS, g_RB):
	
	# Rotate left
	# rotlw RA, RS, RB
	# rlwnm RA, RS, RB, 0, 31
	g_MB = 0
	g_ME = 31

	return Rotate_iMask32(ea, g_mnem, g_RA, g_RS, g_RB, g_MB, g_ME)


def slwi(ea, g_mnem, g_RA, g_RS, n):
	
	# Shift left immediate
	# slwi RA, RS, n
	# rlwinm RA, RS, n, 0, 31-n
	g_SH = n
	g_MB = 0
	g_ME = 31-n

	return iRotate_iMask32(ea, g_mnem, g_RA, g_RS, g_SH, g_MB, g_ME)


def srwi(ea, g_mnem, g_RA, g_RS, n):
	
	# Shift right immediate
	# srwi RA, RS, n
	# rlwinm RA, RS, 32-n, n, 31
	g_SH = 32-n
	g_MB = n
	g_ME = 31

	return iRotate_iMask32(ea, g_mnem, g_RA, g_RS, g_SH, g_MB, g_ME)


def sldi(ea, g_mnem, g_RA, g_RS, n):
	
	# Shift left immediate
	# sldi RA, RS, n
	# rlwinm RA, RS, n, 0, 31-n
	g_SH = n
	g_MB = 0
	g_ME = 63-n

	return iRotate_iMask64(ea, g_mnem, g_RA, g_RS, g_SH, g_MB, g_ME)


def srdi(ea, g_mnem, g_RA, g_RS, n):
	
	# Shift right immediate
	# srdi RA, RS, n
	# rlwinm RA, RS, 32-n, n, 31
	g_SH = 64-n
	g_MB = n
	g_ME = 63

	return iRotate_iMask64(ea, g_mnem, g_RA, g_RS, g_SH, g_MB, g_ME)


# 64bit instructions

def rldcr(ea, g_mnem, g_RA, g_RS, g_RB, g_ME):
	
	# Rotate Left Double Word then Clear Right
	# rldcr RA, RS, RB, ME
	g_MB = 0

	return Rotate_iMask64(ea, g_mnem, g_RA, g_RS, g_RB, g_MB, g_ME)


def rldic(ea, g_mnem, g_RA, g_RS, g_SH, g_MB):
	
	# Rotate Left Double Word Immediate then Clear
	# rldic RA, RS, SH, MB
	g_ME = 63 - g_SH

	return iRotate_iMask64(ea, g_mnem, g_RA, g_RS, g_SH, g_MB, g_ME)


def rldicl(ea, g_mnem, g_RA, g_RS, g_SH, g_MB):
	
	# Rotate Left Double Word Immediate then Clear Left
	# rldicl RA, RS, SH, MB
	g_ME = 63

	return iRotate_iMask64(ea, g_mnem, g_RA, g_RS, g_SH, g_MB, g_ME)


def rldicr(ea, g_mnem, g_RA, g_RS, g_SH, g_ME):
	
	# Rotate Left Double Word Immediate then Clear Right
	# rldicr RA, RS, SH, ME
	g_MB = 0

	return iRotate_iMask64(ea, g_mnem, g_RA, g_RS, g_SH, g_MB, g_ME)


def rldimi(ea, g_mnem, g_RA, g_RS, g_SH, g_MB):
	
	# Rotate Left Double Word Immediate then Mask Insert
	# rldimi RA, RS, SH, MB
	g_ME = 63 - g_SH

	return insert_iRotate_iMask64(ea, g_mnem, g_RA, g_RS, g_SH, g_MB, g_ME)


def rlwimi(ea, g_mnem, g_RA, g_RS, g_SH, g_MB, g_ME):
	
	# Rotate Left Word Immediate Then Mask Insert
	# rlwimi RA, RS, SH, MB, ME

	return insert_iRotate_iMask32(ea, g_mnem, g_RA, g_RS, g_SH, g_MB, g_ME)


# try to do as much work in this function as possible in order to
# simplify each "instruction" handling function
def PPCAsm2C(ea):
	
	# make sure address is valid and that it points to the start of an instruction
	if(ea == BADADDR):
		return False
	if(is_code(ida_bytes.get_flags(ea)) == 0):
		return False

	# get instruction mnemonic
	g_mnem = print_insn_mnem(ea)
	if(g_mnem == 0):
		return False
	
	is_ok = False
	accepted = ["clrlwi", "clrldi", "clrrwi", "clrrdi", "clrlslwi", "clrlsldi",
				"extlwi", "extldi", "extrwi", "extrdi", "inslwi", "insrwi", "insrdi",
				"rlwinm", "rlwnm", "rotlw", "rotlwi", "rotrwi", "slwi", "srwi", "sldi",
				"srdi", "rldcr", "rldic", "rldicl", "rldicr", "rldimi", "rlwimi"]
	for x in accepted:
		if (g_mnem == x):
			is_ok = True
			break
	if (is_ok == False):
		return False
	
	#Remove rc bit if exist - todo
	#char* ptr = (char*)qstrstr(g_mnem, ".")
	#if(ptr) *ptr = 0

	# get instruction operand strings
	# IDA only natively supports 3 operands
	g_opnd_s0 = print_operand(ea, 0)
	g_opnd_s1 = print_operand(ea, 1)
	g_opnd_s2 = print_operand(ea, 2)

	# use some string manipulation to extract additional operands
	# when more than 3 operands are used
	g_opnd_s4 = 0
	g_opnd_s3 = 0
	comma1 = ","
	comma1 = g_opnd_s2.find(comma1)
	if(comma1 != -1):
		# operand-3 exists
		g_opnd_s3 = g_opnd_s2[comma1+1:]
		g_opnd_s2 = g_opnd_s2[0:comma1]
		
		comma2 = ","
		comma2 = g_opnd_s3.find(comma2)
		if(comma2 != -1):
				# operand-4 exists
			g_opnd_s4 = g_opnd_s3[comma2+1:]
			g_opnd_s3 = g_opnd_s3[0:comma2]
			g_opnd_s4 = int(g_opnd_s4)
		g_opnd_s3 = int(g_opnd_s3)
	
	# convert s2 to int, except when s2 is reg nr.
	if (g_mnem != "rldcr" and g_mnem != "rotlw" and g_mnem != "rlwnm"):
		g_opnd_s2 = int(g_opnd_s2)
	
	# below is a list of supported instructions
	
	# clear
	if(g_mnem == "clrlwi"):
		return clrlwi(ea, g_mnem, g_opnd_s0, g_opnd_s1, g_opnd_s2)
	elif(g_mnem == "clrldi"):
		return clrldi(ea, g_mnem, g_opnd_s0, g_opnd_s1, g_opnd_s2)
	elif(g_mnem == "clrrwi"):
		return clrrwi(ea, g_mnem, g_opnd_s0, g_opnd_s1, g_opnd_s2)
	elif(g_mnem == "clrrdi"):
		return clrrdi(ea, g_mnem, g_opnd_s0, g_opnd_s1, g_opnd_s2)
	elif(g_mnem == "clrlslwi"):
		return clrlslwi(ea, g_mnem, g_opnd_s0, g_opnd_s1, g_opnd_s2, g_opnd_s3)
	elif(g_mnem == "clrlsldi"):
		return clrlsldi(ea, g_mnem, g_opnd_s0, g_opnd_s1, g_opnd_s2, g_opnd_s3)
	
	# extract
	elif(g_mnem == "extlwi"):
		return extlwi(ea, g_mnem, g_opnd_s0, g_opnd_s1, g_opnd_s2, g_opnd_s3)
	elif(g_mnem == "extldi"):
		return extldi(ea, g_mnem, g_opnd_s0, g_opnd_s1, g_opnd_s2, g_opnd_s3)
	elif(g_mnem == "extrwi"):
		return extrwi(ea, g_mnem, g_opnd_s0, g_opnd_s1, g_opnd_s2, g_opnd_s3)
	elif(g_mnem == "extrdi"):
		return extrdi(ea, g_mnem, g_opnd_s0, g_opnd_s1, g_opnd_s2, g_opnd_s3)
	
	# insert
	elif(g_mnem == "inslwi"):
		return inslwi(ea, g_mnem, g_opnd_s0, g_opnd_s1, g_opnd_s2, g_opnd_s3)
	elif(g_mnem == "insrwi"):
		return insrwi(ea, g_mnem, g_opnd_s0, g_opnd_s1, g_opnd_s2, g_opnd_s3)
	elif(g_mnem == "insrdi"):
		return insrdi(ea, g_mnem, g_opnd_s0, g_opnd_s1, g_opnd_s2, g_opnd_s3)
	
	# rotate and mask
	elif(g_mnem == "rlwinm"):
		return rlwinm(ea, g_mnem, g_opnd_s0, g_opnd_s1, g_opnd_s2, g_opnd_s3, g_opnd_s4)
	elif(g_mnem == "rlwnm"):
		return rlwnm(ea, g_mnem, g_opnd_s0, g_opnd_s1, g_opnd_s2, g_opnd_s3, g_opnd_s4)
	
	# rotate - todo: 64 bit
	elif(g_mnem == "rotlw"):
		return rotlw(ea, g_mnem, g_opnd_s0, g_opnd_s1, g_opnd_s2)
	elif(g_mnem == "rotlwi"):
		return rotlwi(ea, g_mnem, g_opnd_s0, g_opnd_s1, g_opnd_s2)
	elif(g_mnem == "rotrwi"):
		return rotrwi(ea, g_mnem, g_opnd_s0, g_opnd_s1, g_opnd_s2)
		
	# shift
	elif(g_mnem == "slwi"):
		return slwi(ea, g_mnem, g_opnd_s0, g_opnd_s1, g_opnd_s2)
	elif(g_mnem == "srwi"):
		return srwi(ea, g_mnem, g_opnd_s0, g_opnd_s1, g_opnd_s2)
	elif(g_mnem == "sldi"):
		return sldi(ea, g_mnem, g_opnd_s0, g_opnd_s1, g_opnd_s2)
	elif(g_mnem == "srdi"):
		return srdi(ea, g_mnem, g_opnd_s0, g_opnd_s1, g_opnd_s2)
		
	# 64bit versions of the above
	elif(g_mnem == "rldcr"):
		return rldcr(ea, g_mnem, g_opnd_s0, g_opnd_s1, g_opnd_s2, g_opnd_s3)
	elif(g_mnem == "rldic"):
		return rldic(ea, g_mnem, g_opnd_s0, g_opnd_s1, g_opnd_s2, g_opnd_s3)
	elif(g_mnem == "rldicl"):
		return rldicl(ea, g_mnem, g_opnd_s0, g_opnd_s1, g_opnd_s2, g_opnd_s3)
	elif(g_mnem == "rldicr"):
		return rldicr(ea, g_mnem, g_opnd_s0, g_opnd_s1, g_opnd_s2, g_opnd_s3)
	elif(g_mnem == "rldimi"):
		return rldimi(ea, g_mnem, g_opnd_s0, g_opnd_s1, g_opnd_s2, g_opnd_s3)
	elif(g_mnem == "rlwimi"):
		return rlwimi(ea, g_mnem, g_opnd_s0, g_opnd_s1, g_opnd_s2, g_opnd_s3, g_opnd_s4)

	return 0

def run_task(start_addr, end_addr, always_insert_comment):

	# convert all instructions within the bounds
	addr = start_addr
	while(addr < end_addr):
		print_str = PPCAsm2C(addr)
		if(print_str != 0):
			set_cmt(addr, print_str, False)
		elif (always_insert_comment == True):
			msg("0x{:X}: Error converting PPC to C code\n".format(addr))
		addr += 4

def PluginMain():
	
	# select current line or selected lines
	always_insert_comment = False
	start_addr = read_selection_start()
	end_addr = read_selection_end()
	if(start_addr == BADADDR):
		start_addr = get_screen_ea();
		end_addr = start_addr + 4;
		always_insert_comment = True
	
	run_task(start_addr, end_addr, always_insert_comment)


def PluginMainF():
	
	# convert current function
	p_func = get_func(get_screen_ea());
	if(p_func == None):
		msg("Not in a function, so can't do PPC to C conversion for the current function!\n");
		return;
	start_addr = p_func.start_ea;
	end_addr = p_func.end_ea;
	always_insert_comment = False;
	
	run_task(start_addr, end_addr, always_insert_comment)


#/***************************************************************************************************
#*
#*	Strings required for IDA Pro's PLUGIN descriptor block
#*
#***************************************************************************************************/
#
G_PLUGIN_COMMENT = "PPC To C Conversion Assist"
G_PLUGIN_HELP = "This plugin assists in converting PPC instructions into their relevant C code.\nIt is especially useful for the tricky bit manipulation and shift instructions.\n"
G_PLUGIN_NAME = "PPC To C: Selected Lines"

#/***************************************************************************************************
#*
#*	This 'PLUGIN' data block is how IDA Pro interfaces with this plugin.
#*
#***************************************************************************************************/



class ActionHandler(idaapi.action_handler_t):

    def __init__(self, callback):
        
        idaapi.action_handler_t.__init__(self)
        self.callback = callback
    
    def activate(self, ctx):

        self.callback()
        return 1

    def update(self, ctx):
        
        return idaapi.AST_ENABLE_ALWAYS

def register_actions():   

    actions = [
        {
            'id': 'start:plg',
            'name': G_PLUGIN_NAME,
            'hotkey': 'F10',
            'comment': G_PLUGIN_COMMENT,
            'callback': PluginMain,
            'menu_location': 'Start Plg'
        },
        {
            'id': 'start:plg1',
            'name': 'pypyc2c unimplemented',
            'hotkey': 'Alt-Shift-F10',
            'comment': G_PLUGIN_COMMENT,
            'callback': PluginMainF,
            'menu_location': 'Start Plg1'
        }
    ]


    for action in actions:

        if not idaapi.register_action(idaapi.action_desc_t(
            action['id'], # Must be the unique item
            action['name'], # The name the user sees
            ActionHandler(action['callback']), # The function to call
            action['hotkey'], # A shortcut, if any (optional)
            action['comment'] # A comment, if any (optional)
        )):

            print('Failed to register ' + action['id'])

        if not idaapi.attach_action_to_menu(
            action['menu_location'], # The menu location
            action['id'], # The unique function ID
            0):

            print('Failed to attach to menu '+ action['id'])

class ppc_helper_t(idaapi.plugin_t):
	flags = idaapi.PLUGIN_HIDE
	comment = G_PLUGIN_COMMENT
	help = G_PLUGIN_HELP
	wanted_name = G_PLUGIN_NAME
	wanted_hotkey = "F10"

	def init(self):
		if (idaapi.ph.id == idaapi.PLFM_PPC):
			register_actions()
			idaapi.msg("pypyc2c: loaded\n")
			return idaapi.PLUGIN_KEEP

		return idaapi.PLUGIN_SKIP
	
	def run(self, arg):
		idaapi.msg("pypyc2c: run\n")
	
	def term(self):
		pass

def PLUGIN_ENTRY():
	return ppc_helper_t()
