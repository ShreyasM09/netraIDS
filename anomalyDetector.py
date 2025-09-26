# Core ML libraries
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
import joblib
import numpy as np
import pandas as pd
import pickle
import logging


class AnomalyDetector:
    """ML-based anomaly detection for network traffic"""
    
    def __init__(self):
        self.scaler = StandardScaler()
        self.label_encoders = {}
        self.models = {}
        self.feature_columns = []
        self.is_trained = False
        
    def preprocess_data(self, df):
        """Preprocess data for ML training"""
        # Handle categorical features
        categorical_cols = ['src_ip', 'dst_ip', 'protocol']
        
        for col in categorical_cols:
            if col in df.columns:
                if col not in self.label_encoders:
                    self.label_encoders[col] = LabelEncoder()
                    df[col] = self.label_encoders[col].fit_transform(df[col].astype(str))
                else:
                    # Handle unseen categories
                    unique_values = set(df[col].astype(str).unique())
                    known_values = set(self.label_encoders[col].classes_)
                    new_values = unique_values - known_values
                    
                    if new_values:
                        # Extend encoder with new categories
                        all_values = list(known_values) + list(new_values)
                        self.label_encoders[col].classes_ = np.array(all_values)
                    
                    df[col] = df[col].astype(str).apply(
                        lambda x: self.label_encoders[col].transform([x])[0] 
                        if x in self.label_encoders[col].classes_ else -1
                    )
        
        # Fill missing values
        df = df.fillna(0)
        
        # Select numeric columns for ML
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        df_numeric = df[numeric_cols]
        
        return df_numeric
    
    def train_models(self, df, target_col=None):
        """Train multiple ML models for anomaly detection"""
        print("🔄 Preprocessing data for ML training...")
        
        # Preprocess data
        processed_df = self.preprocess_data(df.copy())
        self.feature_columns = processed_df.columns.tolist()
        
        if target_col and target_col in processed_df.columns:
            # Supervised learning
            X = processed_df.drop(target_col, axis=1)
            y = processed_df[target_col]
            
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
            
            # Scale features
            X_train_scaled = self.scaler.fit_transform(X_train)
            X_test_scaled = self.scaler.transform(X_test)
            
            # Train supervised models
            models_to_train = {
                'random_forest': RandomForestClassifier(n_estimators=100, random_state=42),
                'logistic_regression': LogisticRegression(random_state=42, max_iter=1000)
            }
            
            for name, model in models_to_train.items():
                print(f"🎯 Training {name}...")
                model.fit(X_train_scaled, y_train)
                
                # Evaluate
                y_pred = model.predict(X_test_scaled)
                print(f"\n📊 {name} Performance:")
                print(classification_report(y_test, y_pred))
                
                self.models[name] = model
                
        else:
            # Unsupervised learning
            X = processed_df
            X_scaled = self.scaler.fit_transform(X)
            
            # Train unsupervised models
            print("🎯 Training Isolation Forest...")
            isolation_forest = IsolationForest(contamination=0.1, random_state=42)
            isolation_forest.fit(X_scaled)
            self.models['isolation_forest'] = isolation_forest
        
        self.is_trained = True
        print("✅ Model training completed!")
    
    def predict_anomaly(self, features):
        """Predict if traffic features indicate an anomaly"""
        if not self.is_trained:
            return False, 0.0
        
        try:
            # Convert to DataFrame
            df = pd.DataFrame([features])
            processed_df = self.preprocess_data(df)
            
            # Ensure same feature columns
            for col in self.feature_columns:
                if col not in processed_df.columns:
                    processed_df[col] = 0
            
            processed_df = processed_df[self.feature_columns]
            X_scaled = self.scaler.transform(processed_df)
            
            # Use Isolation Forest for prediction
            if 'isolation_forest' in self.models:
                prediction = self.models['isolation_forest'].predict(X_scaled)[0]
                score = self.models['isolation_forest'].decision_function(X_scaled)[0]
                
                # -1 indicates anomaly in Isolation Forest
                is_anomaly = prediction == -1
                confidence = abs(score)
                
                return is_anomaly, confidence
                
        except Exception as e:
            logging.error(f"Error in anomaly prediction: {e}")
            
        return False, 0.0
    
    def save_models(self, filepath="ids_models.pkl"):
        """Save trained models and preprocessors"""
        model_data = {
            'models': self.models,
            'scaler': self.scaler,
            'label_encoders': self.label_encoders,
            'feature_columns': self.feature_columns,
            'is_trained': self.is_trained
        }
        
        with open(filepath, 'wb') as f:
            pickle.dump(model_data, f)
        print(f"✅ Models saved to {filepath}")
    
    def load_models(self, filepath="ids_models.pkl"):
        """Load trained models and preprocessors"""
        try:
            with open(filepath, 'rb') as f:
                model_data = pickle.load(f)
            
            self.models = model_data['models']
            self.scaler = model_data['scaler']
            self.label_encoders = model_data['label_encoders']
            self.feature_columns = model_data['feature_columns']
            self.is_trained = model_data['is_trained']
            
            print(f"✅ Models loaded from {filepath}")
            return True
        except Exception as e:
            print(f"❌ Error loading models: {e}")
            return False
