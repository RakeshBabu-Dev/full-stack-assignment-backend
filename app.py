from flask import Flask
from api import blueprint  # Ensure this imports the correct blueprint
from flask_restx import Api
from db_config import initialize_db
from flask_cors import CORS
from flask_jwt_extended import JWTManager

app = Flask(__name__)

# Enable CORS
CORS(app, origins=["*"])

# Configure JWT
app.config['JWT_SECRET_KEY'] = 'I_AM_BATMAN'  # Use a secure key
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = 3600  # Access token expires in 1 hour
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = 86400  # Refresh token expires in 1 day

# Initialize JWT
jwt = JWTManager(app)

# Initialize Database
initialize_db('journal')

# API and Blueprint Setup
api = Api(app, title="My API", version="1.0", description="HomePage")
app.register_blueprint(blueprint, url_prefix="/api")

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
