from createCsvDataset import *
import glob
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.neighbors import KNeighborsClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score
import pyarrow
# Get all .exe files in the current directory
file_paths = glob.glob('*.exe')

# initialize with 0 when iterating over the windows files
# initialize with 1 when iterationg over the malware files
classification = 0

# Create dataset
createCsvDatasetFromPE(file_paths, classification)

# Build the model - KNN

# Load the dataset
csv_file = 'C:\\Users\\rober\\PycharmProjects\\HostIntrusionDetectionSystem\\dataset.csv'
df = pd.read_csv(csv_file)

# Prepare the data
X = df.drop('Class', axis=1)  # Features
y = df['Class']  # Target label

# Preprocess the data (optional, depending on your data)
# For example, scaling the features
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Split the data into training and test sets
X_train, X_test, y_train, y_test = train_test_split(X_scaled, y, test_size=0.3, random_state=42)

# Train the KNN model
knn = KNeighborsClassifier(n_neighbors=5)
knn.fit(X_train, y_train)

# Evaluate the model
y_pred = knn.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f'Accuracy: {accuracy}')
