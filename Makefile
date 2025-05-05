# Makefile for telnetclientpoc
# For use with NMAKE

# Compiler and flags
CC=cl
CFLAGS=/EHsc /W3 /nologo
LIBS=ws2_32.lib secur32.lib

# Source files
SOURCES=telnetclientpoc.cpp getopt.cpp stdafx.cpp

# Output executable
TARGET=telnetclientpoc.exe

# Default target (dynamic linking)
all: $(TARGET)

# Static linking target with /MT flag
static: 
	$(MAKE) CFLAGS="$(CFLAGS) /MT" $(TARGET)

# Main build rule
$(TARGET): $(SOURCES)
	$(CC) $(CFLAGS) $(SOURCES) $(LIBS) /Fe:$(TARGET)
	@echo Build complete: $(TARGET)

# Clean rule to remove all artifacts
clean:
	-del /Q *.obj *.exe *.pdb *.ilk *.exp *.lib 2>NUL
	-del /Q *.log *.hash 2>NUL
	@echo Clean complete

# Help target
help:
	@echo.
	@echo NMAKE Targets:
	@echo -------------
	@echo nmake        - Build with dynamic linking
	@echo nmake static - Build with static linking (/MT)
	@echo nmake clean  - Remove all build artifacts and log/hash files
	@echo nmake help   - Display this help message
	@echo. 