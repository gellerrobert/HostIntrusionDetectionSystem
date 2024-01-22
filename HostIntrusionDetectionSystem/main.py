from featuresDataset import extractFeaturesFromPe
from model.histGradientBoosting import predict_with_hgb, hgb
from model.knnModel import predict_with_knn, knn
import tkinter as tk
from tkinter import filedialog, font
from tkinter import messagebox
from tkinter import PhotoImage
from PIL import Image, ImageTk
from gui.createGUI import *
"""
# Get all .exe files in the current directory
file_paths = glob.glob('non-malware\\*.exe')

# initialize with 0 when iterating over the windows files
# initialize with 1 when iterationg over the malware files
classification = 0

# Create dataset
createCsvDatasetFromPE(file_paths, classification)
"""

# Load the dataset
csv_file = 'C:\\Users\\rober\\PycharmProjects\\HostIntrusionDetectionSystem\\dataset.csv'

# Initialize the models
# knn
model, X_train = knn(csv_file)

# hgb
modelHgb = hgb(csv_file)

path = 'C:\\Users\\rober\\PycharmProjects\\HostIntrusionDetectionSystem\\non-malware\\xz.exe'

realTimeData = list(extractFeaturesFromPe.extract_features(path).values())

# Make prediction
predictionKnn = predict_with_knn(model, realTimeData, X_train)
predictionHgb = predict_with_hgb(modelHgb, realTimeData)





#Create GUI

def upload_file():
    global filename
    filename = filedialog.askopenfilename()  # Open file dialog to select a file
    if filename:
        messagebox.showinfo("Executable Selected Succesfully !", f"File: {filename}")


def trigger_function():
    if filename:
        realTimeData = list(extractFeaturesFromPe.extract_features(filename).values())
        result = predict_with_hgb(modelHgb, realTimeData)
        if result == 0:
            messagebox.showinfo("Scanning Result", "No Malware Detected !")
        else:
            messagebox.showinfo("Scanning Result", "Malware Detected !!!!")
    else:
        messagebox.showwarning("Warning", "Please select an executable first.")


generateApp(upload_file, trigger_function)