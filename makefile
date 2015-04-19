all: DES RSA CHAT
JAVA=javac

DES: DES.java
	$(JAVA) DES.java
RSA: RSA.java
	$(JAVA) RSA.java
CHAT: CHAT.java
	$(JAVA) CHAT.java