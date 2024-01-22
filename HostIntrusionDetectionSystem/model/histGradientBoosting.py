import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split


def hgb(csv_file):
    data = pd.read_csv(csv_file)
    # Split the dataset into features and target variable
    X = data.iloc[:, :-1]  # Assuming the last column is the target
    y = data.iloc[:, -1]
    # Split the data into training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    # Create a HistGradientBoosting Classifier
    clf = HistGradientBoostingClassifier()
    # Train the classifier
    clf.fit(X_train, y_train)
    # Make predictions on the test set
    predictions = clf.predict(X_test)
    # Calculate the accuracy
    accuracy = accuracy_score(y_test, predictions)
    print(f"Accuracy: {accuracy}")
    return clf


def predict_with_hgb(model, input_data):
    # Ensure input_data is in the correct format
    # If input_data is not a DataFrame, convert it to DataFrame
    if not isinstance(input_data, pd.DataFrame):
        input_data = pd.DataFrame([input_data], columns=model.feature_names_in_)

    # Make a prediction using the pre-trained model
    prediction = model.predict(input_data)
    print("Prediction with Hist Gradient Boosting:\n")
    if prediction[0] == 0:
        print("No malware detected\n")
    else:
        print("Malware Detected !!!!\n")

    return prediction[0]
