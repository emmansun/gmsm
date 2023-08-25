#define sm4eEnc1block() \
	WORD $0xcec08660         \ //SM4E V0.4S, V19.4S
	WORD $0xcec08680         \ //SM4E V0.4S, V20.4S
	WORD $0xcec086a0         \ //SM4E V0.4S, V21.4S
	WORD $0xcec086c0         \ //SM4E V0.4S, V22.4S
	WORD $0xcec086e0         \ //SM4E V0.4S, V23.4S
	WORD $0xcec08700         \ //SM4E V0.4S, V24.4S
	WORD $0xcec08720         \ //SM4E V0.4S, V25.4S
	WORD $0xcec08740         \  //SM4E V0.4S, V26.4S
	VREV64 V0.B16, V0.B16    \
	VEXT $8, V0.B16, V0.B16, V0.B16

#define sm4eEnc8blocks() \
	sm4eEnc1block()         \
	WORD $0xcec08661         \ //SM4E V1.4S, V19.4S
	WORD $0xcec08681         \ //SM4E V1.4S, V20.4S
	WORD $0xcec086a1         \ //SM4E V1.4S, V21.4S
	WORD $0xcec086c1         \ //SM4E V1.4S, V22.4S
	WORD $0xcec086e1         \ //SM4E V1.4S, V23.4S
	WORD $0xcec08701         \ //SM4E V1.4S, V24.4S
	WORD $0xcec08721         \ //SM4E V1.4S, V25.4S
	WORD $0xcec08741         \ //SM4E V1.4S, V26.4S
	VREV64 V1.B16, V1.B16    \
	VEXT $8, V1.B16, V1.B16, V1.B16 \
	WORD $0xcec08662         \ //SM4E V2.4S, V19.4S
	WORD $0xcec08682         \ //SM4E V2.4S, V20.4S
	WORD $0xcec086a2         \ //SM4E V2.4S, V21.4S
	WORD $0xcec086c2         \ //SM4E V2.4S, V22.4S
	WORD $0xcec086e2         \ //SM4E V2.4S, V23.4S
	WORD $0xcec08702         \ //SM4E V2.4S, V24.4S
	WORD $0xcec08722         \ //SM4E V2.4S, V25.4S
	WORD $0xcec08742         \ //SM4E V2.4S, V26.4S
	VREV64 V2.B16, V2.B16    \
	VEXT $8, V2.B16, V2.B16, V2.B16 \
	WORD $0xcec08663         \ //SM4E V3.4S, V19.4S
	WORD $0xcec08683         \ //SM4E V3.4S, V20.4S
	WORD $0xcec086a3         \ //SM4E V3.4S, V21.4S
	WORD $0xcec086c3         \ //SM4E V3.4S, V22.4S
	WORD $0xcec086e3         \ //SM4E V3.4S, V23.4S
	WORD $0xcec08703         \ //SM4E V3.4S, V24.4S
	WORD $0xcec08723         \ //SM4E V3.4S, V25.4S
	WORD $0xcec08743         \ //SM4E V3.4S, V26.4S
	VREV64 V3.B16, V3.B16    \
	VEXT $8, V3.B16, V3.B16, V3.B16 \	
	WORD $0xcec08664         \ //SM4E V4.4S, V19.4S
	WORD $0xcec08684         \ //SM4E V4.4S, V20.4S
	WORD $0xcec086a4         \ //SM4E V4.4S, V21.4S
	WORD $0xcec086c4         \ //SM4E V4.4S, V22.4S
	WORD $0xcec086e4         \ //SM4E V4.4S, V23.4S
	WORD $0xcec08704         \ //SM4E V4.4S, V24.4S
	WORD $0xcec08724         \ //SM4E V4.4S, V25.4S
	WORD $0xcec08744         \ //SM4E V4.4S, V26.4S
	VREV64 V4.B16, V4.B16    \
	VEXT $8, V4.B16, V4.B16, V4.B16 \	
	WORD $0xcec08665         \ //SM4E V5.4S, V19.4S
	WORD $0xcec08685         \ //SM4E V5.4S, V20.4S
	WORD $0xcec086a5         \ //SM4E V5.4S, V21.4S
	WORD $0xcec086c5         \ //SM4E V5.4S, V22.4S
	WORD $0xcec086e5         \ //SM4E V5.4S, V23.4S
	WORD $0xcec08705         \ //SM4E V5.4S, V24.4S
	WORD $0xcec08725         \ //SM4E V5.4S, V25.4S
	WORD $0xcec08745         \ //SM4E V5.4S, V26.4S
	VREV64 V5.B16, V5.B16    \
	VEXT $8, V5.B16, V5.B16, V5.B16 \
	WORD $0xcec08666         \ //SM4E V6.4S, V19.4S
	WORD $0xcec08686         \ //SM4E V6.4S, V20.4S
	WORD $0xcec086a6         \ //SM4E V6.4S, V21.4S
	WORD $0xcec086c6         \ //SM4E V6.4S, V22.4S
	WORD $0xcec086e6         \ //SM4E V6.4S, V23.4S
	WORD $0xcec08706         \ //SM4E V6.4S, V24.4S
	WORD $0xcec08726         \ //SM4E V6.4S, V25.4S
	WORD $0xcec08746         \ //SM4E V6.4S, V26.4S
	VREV64 V6.B16, V6.B16    \
	VEXT $8, V6.B16, V6.B16, V6.B16 \	
	WORD $0xcec08667         \ //SM4E V7.4S, V19.4S
	WORD $0xcec08687         \ //SM4E V7.4S, V20.4S
	WORD $0xcec086a7         \ //SM4E V7.4S, V21.4S
	WORD $0xcec086c7         \ //SM4E V7.4S, V22.4S
	WORD $0xcec086e7         \ //SM4E V7.4S, V23.4S
	WORD $0xcec08707         \ //SM4E V7.4S, V24.4S
	WORD $0xcec08727         \ //SM4E V7.4S, V25.4S
	WORD $0xcec08747         \ //SM4E V7.4S, V26.4S    
	VREV64 V7.B16, V7.B16    \
	VEXT $8, V7.B16, V7.B16, V7.B16
