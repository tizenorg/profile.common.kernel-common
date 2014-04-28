/* flags definitions */
#define IMA_FUNC        0x0001
#define IMA_MASK        0x0002
#define IMA_FSMAGIC     0x0004
#define IMA_UID         0x0008
#define IMA_FOWNER      0x0010
#define IMA_FSUUID      0x0020
#define IMA_PATH        0x0040

#define UNKNOWN         0
#define MEASURE         0x0001  /* same as IMA_MEASURE */
#define DONT_MEASURE    0x0002
#define APPRAISE        0x0004  /* same as IMA_APPRAISE */
#define DONT_APPRAISE   0x0008
#define AUDIT           0x0040

#define MAX_LSM_RULES 6
enum lsm_rule_types { LSM_OBJ_USER, LSM_OBJ_ROLE, LSM_OBJ_TYPE,
	LSM_SUBJ_USER, LSM_SUBJ_ROLE, LSM_SUBJ_TYPE
};

struct ima_rule_entry {
	struct list_head list;
	int action;
	unsigned int flags;
	enum ima_hooks func;
	int mask;
	unsigned long fsmagic;
	u8 fsuuid[16];
	kuid_t uid;
	kuid_t fowner;
	char *path;
	int path_len;
	struct {
		void *rule;     /* LSM file metadata specific */
		void *args_p;   /* audit value */
		int type;       /* audit type */
	} lsm[MAX_LSM_RULES];
};

extern struct list_head *ima_rules;
