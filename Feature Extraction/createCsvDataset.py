from extractFeaturesFromPe import *
import csv

featuresList = ['Machine', 'SizeOfOptionalHeader', 'Characteristics', 'MajorLinkerVersion', 'MinorLinkerVersion',
                'SizeOfCode', 'SizeOfInitializedData',
                'SizeOfUninitializedData', 'AddressOfEntryPoint', 'BaseOfCode', 'BaseOfData', 'ImageBase',
                'SectionAlignment', 'FileAlignment',
                'MajorOperatingSystemVersion', 'MinorOperatingSystemVersion', 'MajorImageVersion', 'MinorImageVersion',
                'MajorSubsystemVersion',
                'MinorSubsystemVersion', 'SizeOfImage', 'SizeOfHeaders', 'CheckSum', 'Subsystem', 'DllCharacteristics',
                'SizeOfStackReserve',
                'SizeOfStackCommit', 'SizeOfHeapReserve', 'SizeOfHeapCommit', 'LoaderFlags', 'NumberOfRvaAndSizes',
                'SectionsNb', 'SectionsMeanEntropy',
                'SectionsMinEntropy', 'SectionsMaxEntropy', 'SectionsMeanRawsize', 'SectionsMinRawsize',
                'SectionMaxRawsize', 'SectionsMeanVirtualsize',
                'SectionsMinVirtualsize', 'SectionMaxVirtualsize', 'ImportsNbDLL', 'ImportsNb', 'ImportsNbOrdinal',
                'ExportNb', 'ResourcesNb',
                'ResourcesMeanEntropy', 'ResourcesMinEntropy', 'ResourcesMaxEntropy', 'ResourcesMeanSize',
                'ResourcesMinSize', 'ResourcesMaxSize',
                'LoadConfigurationSize', 'VersionInformationSize', 'Class']

csv_file = 'dataset.csv'


def createCsvDatasetFromPE(file_paths, classification):
    """
    Processes each file, extracts features, adds a classification, and writes to a CSV file.

    Parameters:
    - file_paths (list): A list of file paths to process..
    - classification (int): The classification value (0 or 1) to add to each row.
    - csv_file (str): The path to the CSV file where the data will be written.
    """

    with open(csv_file, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.DictWriter(file, fieldnames=featuresList)
        writer.writeheader()

        for file_path in file_paths:
            featuresFromFilePath = extract_features(file_path)
            featuresFromFilePath['Class'] = classification
            writer.writerow(featuresFromFilePath)
