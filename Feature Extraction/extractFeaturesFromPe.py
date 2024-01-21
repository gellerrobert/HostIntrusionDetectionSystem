import pefile


def get_entropy(data):
    """
       Calculate the Shannon entropy of a byte array.

    Entropy is a measure of the randomness or disorder within a dataset. High entropy
    often indicates encrypted or compressed data. This function computes entropy
    using the Shannon entropy formula, which is useful in analyzing the characteristics
    of binary data, such as in files.

    :param data: PE object data (bytearray or bytes): The binary data for which to calculate the entropy.
    :return: The Shannon entropy of the input data, a measure of randomness.

         """
    import math
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(bytes([x]))) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy


def get_resource_data(pe):
    """
    Extract data from resources.
    :param pe: PE object
    :return: List of resource data
    """
    resource_data = []
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if hasattr(entry, 'directory'):
                for subentry in entry.directory.entries:
                    if hasattr(subentry, 'directory'):
                        for res in subentry.directory.entries:
                            data = pe.get_data(res.data.struct.OffsetToData, res.data.struct.Size)
                            resource_data.append(data)
    return resource_data


def extract_features(file_path):
    """
        Extracts a set of features from a Portable Executable (PE) file.

        This function analyzes various aspects of a PE file, including headers, sections,
        imports, exports, and resources, to extract features relevant for file analysis,
        such as in malware detection. The extracted features include details from the
        file header, optional header, sections, imported and exported symbols, resources,
        and more.


        :param file_path: The path to the PE file from which to extract features.
        :return: dict: A dictionary containing the extracted features, with feature names as keys
        and corresponding feature values.

        """

    pe = pefile.PE(file_path)

    # File Header Features added by default in the feature dictionary,
    # other features are going to be added further by some computations

    features = {'Machine': pe.FILE_HEADER.Machine, 'SizeOfOptionalHeader': pe.FILE_HEADER.SizeOfOptionalHeader,
                'Characteristics': pe.FILE_HEADER.Characteristics,
                'MajorLinkerVersion': pe.OPTIONAL_HEADER.MajorLinkerVersion,
                'MinorLinkerVersion': pe.OPTIONAL_HEADER.MinorLinkerVersion,
                'SizeOfCode': pe.OPTIONAL_HEADER.SizeOfCode,
                'SizeOfInitializedData': pe.OPTIONAL_HEADER.SizeOfInitializedData,
                'SizeOfUninitializedData': pe.OPTIONAL_HEADER.SizeOfUninitializedData,
                'AddressOfEntryPoint': pe.OPTIONAL_HEADER.AddressOfEntryPoint,
                'BaseOfCode': pe.OPTIONAL_HEADER.BaseOfCode, 'BaseOfData': pe.OPTIONAL_HEADER.BaseOfData,
                'ImageBase': pe.OPTIONAL_HEADER.ImageBase, 'SectionAlignment': pe.OPTIONAL_HEADER.SectionAlignment,
                'FileAlignment': pe.OPTIONAL_HEADER.FileAlignment,
                'MajorOperatingSystemVersion': pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
                'MinorOperatingSystemVersion': pe.OPTIONAL_HEADER.MinorOperatingSystemVersion,
                'MajorImageVersion': pe.OPTIONAL_HEADER.MajorImageVersion,
                'MinorImageVersion': pe.OPTIONAL_HEADER.MinorImageVersion,
                'MajorSubsystemVersion': pe.OPTIONAL_HEADER.MajorSubsystemVersion,
                'MinorSubsystemVersion': pe.OPTIONAL_HEADER.MinorSubsystemVersion,
                'SizeOfImage': pe.OPTIONAL_HEADER.SizeOfImage, 'SizeOfHeaders': pe.OPTIONAL_HEADER.SizeOfHeaders,
                'CheckSum': pe.OPTIONAL_HEADER.CheckSum, 'Subsystem': pe.OPTIONAL_HEADER.Subsystem,
                'DllCharacteristics': pe.OPTIONAL_HEADER.DllCharacteristics,
                'SizeOfStackReserve': pe.OPTIONAL_HEADER.SizeOfStackReserve,
                'SizeOfStackCommit': pe.OPTIONAL_HEADER.SizeOfStackCommit,
                'SizeOfHeapReserve': pe.OPTIONAL_HEADER.SizeOfHeapReserve,
                'SizeOfHeapCommit': pe.OPTIONAL_HEADER.SizeOfHeapCommit, 'LoaderFlags': pe.OPTIONAL_HEADER.LoaderFlags,
                'NumberOfRvaAndSizes': pe.OPTIONAL_HEADER.NumberOfRvaAndSizes, 'SectionsNb': len(pe.sections)}

    # Optional Header Features

    # Section Features
    entropies = [get_entropy(section.get_data()) for section in pe.sections]
    features['SectionsMeanEntropy'] = sum(entropies) / float(len(entropies))
    features['SectionsMinEntropy'] = min(entropies)
    features['SectionsMaxEntropy'] = max(entropies)
    raw_sizes = [section.SizeOfRawData for section in pe.sections]
    features['SectionsMeanRawsize'] = sum(raw_sizes) / float(len(raw_sizes))
    features['SectionsMinRawsize'] = min(raw_sizes)
    features['SectionMaxRawsize'] = max(raw_sizes)
    virtual_sizes = [section.Misc_VirtualSize for section in pe.sections]
    features['SectionsMeanVirtualsize'] = sum(virtual_sizes) / float(len(virtual_sizes))
    features['SectionsMinVirtualsize'] = min(virtual_sizes)
    features['SectionMaxVirtualsize'] = max(virtual_sizes)

    # Imports
    try:
        features['ImportsNbDLL'] = len(pe.DIRECTORY_ENTRY_IMPORT)
        imports = sum([len(dll.imports) for dll in pe.DIRECTORY_ENTRY_IMPORT])
        features['ImportsNb'] = imports
        features['ImportsNbOrdinal'] = len([imp for imp in pe.DIRECTORY_ENTRY_IMPORT if imp.name is None])
    except AttributeError:
        features['ImportsNbDLL'] = 0
        features['ImportsNb'] = 0
        features['ImportsNbOrdinal'] = 0

    # Exports
    try:
        features['ExportNb'] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
    except AttributeError:
        features['ExportNb'] = 0

    # Resources

    resources = get_resource_data(pe)
    features['ResourcesNb'] = len(resources)
    if len(resources) > 0:
        entropy = [get_entropy(r) for r in resources]
        sizes = [len(r) for r in resources]
        features['ResourcesMeanEntropy'] = sum(entropy) / float(len(entropy))
        features['ResourcesMinEntropy'] = min(entropy)
        features['ResourcesMaxEntropy'] = max(entropy)
        features['ResourcesMeanSize'] = sum(sizes) / float(len(sizes))
        features['ResourcesMinSize'] = min(sizes)
        features['ResourcesMaxSize'] = max(sizes)
    else:
        features['ResourcesMeanEntropy'] = 0.0
        features['ResourcesMinEntropy'] = 0
        features['ResourcesMaxEntropy'] = 0
        features['ResourcesMeanSize'] = 0.0
        features['ResourcesMinSize'] = 0
        features['ResourcesMaxSize'] = 0

    # Load Configuration Size
    try:
        features['LoadConfigurationSize'] = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.Size
    except AttributeError:
        features['LoadConfigurationSize'] = 0

    # Version Information Size
    try:
        features['VersionInformationSize'] = len(pe.FileInfo)
    except AttributeError:
        features['VersionInformationSize'] = 0

    return features
