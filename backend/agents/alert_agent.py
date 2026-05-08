import os
from datetime import datetime, timezone
import logging
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure, PyMongoError

# Attempt to import configuration and logger
try:
    from backend.config.settings import MONGO_URI, DB_NAME, ALERT_COLLECTION
except ImportError:
    # Fallback defaults if config is missing during dev
    MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
    DB_NAME = "acds"
    ALERT_COLLECTION = "alerts"

try:
    from backend.core.logger import get_logger
except ImportError:
    logging.basicConfig(level=logging.INFO)
    def get_logger(name):
        return logging.getLogger(name)

class AlertAgent:
    """
    Agent responsible for creating and storing alerts in MongoDB when threats are detected.
    """

    def __init__(self):
        """
        Initialize the Alert Agent and establish MongoDB connection.
        """
        self.logger = get_logger(__name__)
        self.client = None
        self.db = None
        self.collection = None

        try:
            self.client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
            # Trigger a connection check
            self.client.admin.command('ping')
            
            self.db = self.client[DB_NAME]
            self.collection = self.db[ALERT_COLLECTION]
            self.logger.info(f"AlertAgent connected to MongoDB at {MONGO_URI}")
        except ConnectionFailure:
            self.logger.error("Failed to connect to MongoDB. Alerts will not be saved.")
        except Exception as e:
            self.logger.error(f"Unexpected error initializing MongoDB connection: {e}")

    def create_alert(self, threat_dict: dict) -> bool:
        """
        Create an alert record in the database.

        Args:
            threat_dict (dict): Dictionary containing threat details 
                                (filename, is_phishing, confidence).

        Returns:
            bool: True if alert was saved successfully, False otherwise.
        """
        if not self.collection:
            self.logger.error("Database collection not available. Cannot save alert.")
            return False

        try:
            # Ensure timestamp exists
            if "timestamp" not in threat_dict:
                threat_dict["timestamp"] = datetime.now(timezone.utc)

            # Insert into MongoDB
            result = self.collection.insert_one(threat_dict)
            
            if result.inserted_id:
                self.logger.info(f"Alert saved successfully for {threat_dict.get('filename', 'unknown')} (ID: {result.inserted_id})")
                return True
            else:
                self.logger.warning("Alert insertion failed (no ID returned).")
                return False

        except PyMongoError as e:
            self.logger.error(f"MongoDB error saving alert: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error saving alert: {e}")
            return False
