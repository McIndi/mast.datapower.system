from system import cli

# Fix issue with __main__.py messing up command line help
import sys
sys.argv[0] = "mast-accounts"

cli.Run()

