NAME 		= anti

CC			= gcc
RM			= rm -f

SOURCES 	= $(shell find . -name "*.c")
HEADERS 	= $(shell find . -name "*.h")

OBJECTS 	= $(patsubst %.c, %.o, $(SOURCES))
DEPENDS 	= $(patsubst %.c, %.d, $(SOURCES))

DIETLIB 	= ../dietlibc
DIET		= $(DIETLIB)/bin-x86_64/diet
# strip the binary
CFLAGS 		= -s

all: $(NAME)

%.o: %.c
	@$(DIET) $(CC) -Iinclude $(CFLAGS) -MMD -MP -c $< -o $@

$(DIET):
	@echo "Compiling DietLibc..."
	@make -C $(DIETLIB) > /dev/null
	@echo "DietLibc Compiled !"

$(NAME): $(DIET) $(OBJECTS)
	@echo "Dependencies Compiled !"
	@$(DIET) $(CC) $(CFLAGS) $(OBJECTS) $(LIB) -o $(NAME)
	@echo "Compiled !"

clean:
	-@$(RM) $(OBJECTS) $(DEPENDS)
	@echo "Everything is Cleaned !"

fclean: clean
	@cd $(DIETLIB) && make clean > /dev/null
	@echo "dietlibc cleaned !"

re: clean all

.PHONY: re clean all

-include $(DEPENDS)
