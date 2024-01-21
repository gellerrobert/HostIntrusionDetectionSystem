from createCsvDataset import *
import glob

# Get all .exe files in the current directory
file_paths = glob.glob('*.exe')

# initialize with 0 when iterating over the windows files
# initialize with 1 when iterationg over the malware files
classification = 0

createCsvDatasetFromPE(file_paths, classification)
