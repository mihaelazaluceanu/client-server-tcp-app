SOURCES1 = server.cpp
SOURCES2 = subscriber.cpp
SOURCES3 = common.cpp

exe1 = server
exe2 = subscriber
# Parametri pentru compilare.
CCFLAGS := -std=c++17 -Wall -Wextra -O0 -lm
CC = g++

.PHONY: build clean pack

build:
		$(CC) $(CCFLAGS) $(SOURCES1) $(SOURCES3) -o $(exe1)
		$(CC) $(CCFLAGS) $(SOURCES2) $(SOURCES3) -o $(exe2)

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
		-regex ".*\.\(cpp\|h\|hpp\|java\)" -exec zip $(ARCHIVE) {} +
	@zip $(ARCHIVE) Makefile
	@[ -f README.md ] && zip $(ARCHIVE) README.md \
		|| echo "You should write README.md!"
	@echo "Created $(ARCHIVE)"
