from sklearn.ensemble import IsolationForest

def train_model(X):
    model = IsolationForest(contamination=0.3, random_state=42)
    model.fit(X)
    return model

def predict(model, X):
    return model.predict(X), model.decision_function(X)
