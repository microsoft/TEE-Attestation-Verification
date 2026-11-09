// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// C++ oracle for the differential fuzzer, built against the pinned didx509cpp.h.
// `oracle DID CHAIN_PEM_PATH` prints `ok` and the leaf JWK, or `err` and a message.

#include "didx509cpp.h"

#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

int main(int argc, char** argv)
{
  if (argc != 3)
  {
    std::cerr << "usage: oracle DID CHAIN_PEM_PATH\n";
    return 2;
  }
  std::ifstream file(argv[2]);
  if (!file)
  {
    std::cerr << "cannot open chain file\n";
    return 2;
  }
  std::stringstream buffer;
  buffer << file.rdbuf();
  if (file.bad())
  {
    std::cerr << "cannot read chain file\n";
    return 2;
  }
  const std::string pem = buffer.str();

  const std::string footer = "-----END CERTIFICATE-----";
  std::vector<std::string> blocks;
  size_t start = 0;
  while (true)
  {
    const auto end = pem.find(footer, start);
    if (end == std::string::npos)
    {
      break;
    }
    blocks.push_back(pem.substr(start, end + footer.size() - start) + "\n");
    start = end + footer.size();
  }

  try
  {
    const std::string jwk = didx509::resolve_jwk(blocks, argv[1], false);
    std::cout << "ok\n" << jwk << "\n";
  }
  catch (const std::exception& e)
  {
    std::string message = e.what();
    for (auto& c : message)
    {
      if (c == '\n')
      {
        c = ' ';
      }
    }
    std::cout << "err\n" << message << "\n";
  }
  return 0;
}
