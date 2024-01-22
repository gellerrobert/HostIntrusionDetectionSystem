import numpy as np
import pandas as pd

from sklearn import preprocessing
from sklearn.model_selection import train_test_split
from sklearn.neighbors import KNeighborsClassifier
from sklearn import metrics
from sklearn.impute import SimpleImputer


def knn(csv_file):
    data = pd.read_csv(csv_file)
    temp_data = data.copy()
    # get the Class column
    class_column = temp_data.iloc[:, -1]
    # get the specific index for each class
    class_0_index = class_column[class_column == 0].index
    class_1_index = class_column[class_column == 1].index
    # calculate the mean for each class
    mean_class_0 = temp_data.iloc[class_0_index, :-1].mean()
    mean_class_1 = temp_data.iloc[class_1_index, :-1].mean()
    # fill the missing values with corresponding mean
    temp_data.iloc[class_0_index] = temp_data.iloc[class_0_index].fillna(mean_class_0)
    temp_data.iloc[class_1_index] = temp_data.iloc[class_1_index].fillna(mean_class_1)
    # update the X with new filled values
    X = temp_data.iloc[:, :-1]
    y = temp_data.iloc[:, -1]
    # Create an imputer object that fills 'NaN' values with the mean value of each column
    imputer = SimpleImputer(missing_values=np.nan, strategy='mean')
    # Now we fill the missing values in X
    X = imputer.fit_transform(X)
    # normalize the features
    X = preprocessing.StandardScaler().fit(X).transform(X.astype(float))
    # Split dataset into training set and test set
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2,
                                                        random_state=4)  # 80% training and 20% test
    # build the knn classifier
    knn_classifier = KNeighborsClassifier(n_neighbors=3)
    # Train the model using the training sets
    knn_classifier.fit(X_train, y_train)
    # Predict the response for test dataset
    y_pred = knn_classifier.predict(X_test)
    # Model Accuracy
    print("Accuracy:", metrics.accuracy_score(y_test, y_pred))
    return knn_classifier, X_train


def predict_with_knn(model, input_data, X_train):
    # Ensure input_data is in the correct format (e.g., a 2D array or DataFrame)
    if not isinstance(input_data, pd.DataFrame):
        input_data = pd.DataFrame([input_data])

    imputer = SimpleImputer(missing_values=np.nan,
                            strategy='mean')  # Assuming this is already fitted to the training data
    imputer.fit(X_train)  # Fit the imputer with the training data

    scaler = preprocessing.StandardScaler().fit(X_train)

    # Apply imputation to fill missing values
    input_data_imputed = imputer.transform(input_data)

    # Normalize the features
    input_data_normalized = scaler.transform(input_data_imputed)

    # Make a prediction using the pre-trained model
    prediction = model.predict(input_data_normalized)

    print("Prediction with KNN:\n")
    if prediction[0] == 0:
        print("No malware detected\n")
    else:
        print("Malware Detected !!!!\n")

    return prediction[0]