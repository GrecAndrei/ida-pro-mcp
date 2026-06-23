import sys
from ida_pro_mcp.host.server.server import main

if __name__ == "__main__":
    sys.argv[0] = "ida_pro_mcp"
    main()
