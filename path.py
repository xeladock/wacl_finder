import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(sys.argv[0])))
APP_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR,'data')
print("BASE_DIR is", BASE_DIR)
print("APP_DIR is", APP_DIR)
print("DATA_DIR is", DATA_DIR)

# DATA_DIR = os.path.join("/ram_disk",'data')

