#define mul2Inline        \
	VMOV	TW.D[1], I;                     \
	ASR	$63, I;                             \
	VMOV	I, K0.D2;                       \
	VAND	POLY.B16, K0.B16, K0.B16;       \
	\
	VUSHR	$63, TW.D2, K1.D2;              \
	VEXT	$8, K1.B16, ZERO.B16, K1.B16;   \
	VSLI	$1, TW.D2, K1.D2;               \
	VEOR	K0.B16, K1.B16, TW.B16

#define mul2GBInline        \
	VREV64 TW.B16, TW.B16;                  \
	VEXT	$8, TW.B16, TW.B16, TW.B16;     \
	\
	VMOV	TW.D[0], I;                     \
	LSL $63, I;                             \
	ASR $63, I;                             \
	VMOV	I, K0.D2;                       \
	VAND	POLY.B16, K0.B16, K0.B16;       \
	\
	VSHL $63, TW.D2, K1.D2;                 \
	VEXT	$8, ZERO.B16, K1.B16, K1.B16;   \
	VSRI	$1, TW.D2, K1.D2;               \
	VEOR	K0.B16, K1.B16, TW.B16;         \
	\
	VEXT	$8, TW.B16, TW.B16, TW.B16;     \
	VREV64 TW.B16, TW.B16

#define prepare4Tweaks \
	VMOV TW.B16, T0.B16;   \
	mul2Inline;            \
	VMOV TW.B16, T1.B16;   \
	mul2Inline;            \
	VMOV TW.B16, T2.B16;   \
	mul2Inline;            \
	VMOV TW.B16, T3.B16;   \
	mul2Inline

#define prepare8Tweaks \
	prepare4Tweaks;        \
	VMOV TW.B16, T4.B16;   \
	mul2Inline;            \
	VMOV TW.B16, T5.B16;   \
	mul2Inline;            \
	VMOV TW.B16, T6.B16;   \
	mul2Inline;            \
	VMOV TW.B16, T7.B16;   \
	mul2Inline

#define prepareGB4Tweaks \
	VMOV TW.B16, T0.B16;     \
	mul2GBInline;            \
	VMOV TW.B16, T1.B16;     \
	mul2GBInline;            \
	VMOV TW.B16, T2.B16;     \
	mul2GBInline;            \
	VMOV TW.B16, T3.B16;     \
	mul2GBInline

#define prepareGB8Tweaks \
	prepareGB4Tweaks;        \
	VMOV TW.B16, T4.B16;     \
	mul2GBInline;            \
	VMOV TW.B16, T5.B16;     \
	mul2GBInline;            \
	VMOV TW.B16, T6.B16;     \
	mul2GBInline;            \
	VMOV TW.B16, T7.B16;     \
	mul2GBInline
