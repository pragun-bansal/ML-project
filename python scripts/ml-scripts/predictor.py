import tensorflow as tf
import numpy as np

model = tf.keras.models.load_model('final.h5')  
new_data = np.array([[0.1, 0.2, 0.3, 0.4, 0.5, ..., 0.6]])  # Replace with your actual data

# Make predictions on the new data
predictions = model.predict(new_data)

# Display the predictions
print("Predictions:", predictions)
