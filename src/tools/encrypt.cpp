/*
 * encrypt.cpp -- part of Captool, a traffic profiling framework
 *
 * Copyright (C) 2009, 2010 Ericsson AB
 */

/**
 * Encrypt file using a key.
 */

#include "util/crypt.h"
#include <fstream>

int
main (int argc, char *argv[])
{
    if (argc < 3)
    {
        std::cout << "Encrypt file.\nUsage: " << argv[0] << " infile outfile\n";
        return 1;
    }
    std::ofstream output (argv[2]);
    std::ifstream input (argv[1]);
    encrypt(input, output);
    return 0;
}
