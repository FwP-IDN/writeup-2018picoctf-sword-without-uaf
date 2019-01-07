# Write Up 2018 PicoCTF : Sword

So, I am in a holiday and try to solve this, and the flag is `picoCTF{usE_aFt3R_fr3e_1s_aN_1ssu3_XXXXXXXX}` so that means that the intended is using use after free. But I solve it without use after free and just using the first fist behaviour. Not important right? Yes.

First thing to do is look in the source in sword.c. There is a hint in line 180. `/* Vuln. */`, they say. If we look deeper into the source, 
```
void synthe_sword() {
	int slot_1, slot_2;
	printf("What's the index of the first sword?\n");
	slot_1 = get_int();
	if (slot_1 < 0 || slot_1 >= MAX_SWORD_NUM ||
		!sword_lists[slot_1].is_used) {
		printf("I don't trust your number!!!!\n");
		exit(-1);
	}

	printf("What's the index of the second sword?\n");
	slot_2 = get_int();
	if (slot_2 < 0 || slot_2 >= MAX_SWORD_NUM ||
		!sword_lists[slot_2].is_used) {
		printf("I don't trust your number!!!!\n");
		exit(-1);
	}

	printf("OK.... Forge two swords now!!\n");
	struct sword_list_s sword1_list = sword_lists[slot_1];
	struct sword_list_s sword2_list = sword_lists[slot_2];

	/* Two swords are lost. */
	sword1_list.is_used = sword2_list.is_used = 0;

	sleep(FORGE_TIME);

	/* Combinne two names together. */
	sword2_list.sword->sword_name = realloc(sword2_list.sword->sword_name,
		sword1_list.sword->name_len + sword2_list.sword->name_len + 1);
	if (!sword2_list.sword->sword_name) {
		exit(-1);
	}

	memcpy(sword2_list.sword->sword_name + sword2_list.sword->name_len,
		sword1_list.sword->sword_name, sword1_list.sword->name_len);

	sword2_list.sword->name_len += sword1_list.sword->name_len;
	
	/* New sword is created. */
	sword2_list.is_used = 1;

	/* Clear the first sword. */
	free(sword1_list.sword->sword_name);

	printf("YOu have the NEW sword!\n");
```

It's very clear right? realloc(sword2_list.sword->sword_name), and free(sword1_list.sword->sword_name), and then sword\{i\}\_list is based on input. So we just use same index and syntesize it to get use after free.

But something vuln that actually affect the heap is the structure of struct.
```
struct sword_s {
	int name_len;
	int weight;
	
	char *sword_name;
	void (*use_sword)(char *ptr);
	int is_hardened;
};
```

the heap metadata only can overwrite name_len and weight. So function pointer use_sword doesn't get affected when the chunk in free state.

The other vuln that lead to first fit abuse is they use malloc instead of calloc. malloc doesn't fill zero to allocated chunk. Beside that, there are 2 use of malloc with different "color".

first use of malloc in line 236
```
	}

	sword_lists[slot].sword = malloc(sizeof(struct sword_s));
	if (!sword_lists[slot].sword) {
	        puts("malloc() returned NULL. Out of Memory\n");
```
and the second use of malloc in line 137
```

	/* Get sword name. */
	sword_lists[slot].sword->sword_name = malloc(len + 1);

	if (!sword_lists[slot].sword->sword_name) {
```

In the first malloc, we allocate a function pointer and the second malloc, we can write **Any data** of **Any length** and function pointer that allocated in first malloc **doesn't get any effect** when it's freed.


So, the attack is based on 2 stages. Leaking and Attacking

## Leaking

Simply just make sure that second malloc value is <padding 8 bytes><address of GOT> then we free and we malloc again and libc leaked

## Attacking
Just like leaking but the value is of second malloc is <padding 8 bytes><pointer to string bin/sh><pointer to system>. Freed the chunk and malloc again. When we call equip, it will spawn system("/bin/sh") without even use command number 2 (syntesize)

