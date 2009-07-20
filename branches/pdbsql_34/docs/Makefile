XMLTO = xmlto

all: pdb_mysql.html pdb_pgsql.html

%.html: %.xml
	$(XMLTO) html-nochunks $<
