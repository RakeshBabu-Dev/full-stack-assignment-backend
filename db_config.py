from mongoengine import connect 


def initialize_db(database_name):
    try:
        connect(db=database_name, host='mongodb://localhost:27017/')
        print(f"Connected to database: {database_name}")

    except Exception as e:
        print(f"Error connecting to MongoDB: {e}")