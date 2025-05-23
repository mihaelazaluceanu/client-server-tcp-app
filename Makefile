SOURCES1 = server.cpp
SOURCES2 = subscriber.cpp

exe1 = server
exe2 = subscriber
# Parametri pentru compilare.
CC = g++

.PHONY: build clean pack

build:
		$(CC) $(SOURCES1) -o $(exe1)
		$(CC) $(SOURCES2) -o $(exe2)

run-exe1:
		./$(exe1)
run-exe2:
		./$(exe2)

clean:
		rm -f $(exe1) $(exe2)

# Numele arhivei generate de comanda `pack`
ARCHIVE := 324CC_Zaluceanu_Mihaela_Tema2.zip

pack:
		@find $(SRC_DIR) \
		\( -path "./_utils/*" -prune \) -o \
		-regex ".*\.\(cpp\|h\)" -exec zip $(ARCHIVE) {} +
	@zip $(ARCHIVE) Makefile
	@[ -f readme.txt ] && zip $(ARCHIVE) readme.txt \
		|| echo "You should write readme.txt!"
	@echo "Created $(ARCHIVE)"
