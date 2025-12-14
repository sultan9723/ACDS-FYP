import os
from motor.motor_asyncio import AsyncIOMotorClient
from pymongo.errors import ConnectionFailure
import logging
from typing import Optional, List, Dict, Any
from pydantic import ValidationError

from .models import Incident, IncidentStatus # Assuming Incident model is in .models

# Configure logging
logger = logging.getLogger(__name__)

# Environment variables for MongoDB connection
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
DB_NAME = os.getenv("DB_NAME", "acds_phishing_db")
INCIDENT_COLLECTION = os.getenv("INCIDENT_COLLECTION", "incidents")

class IncidentDatabase:
    """
    Handles MongoDB connection and CRUD operations for Incident data.
    """
    client: Optional[AsyncIOMotorClient] = None
    db = None
    collection = None

    async def connect(self):
        try:
            self.client = AsyncIOMotorClient(MONGO_URI, serverSelectionTimeoutMS=5000)
            await self.client.admin.command('ismaster')  # The ping command to check connection
            self.db = self.client[DB_NAME]
            self.collection = self.db[INCIDENT_COLLECTION]
            logger.info(f"Connected to MongoDB: {MONGO_URI}, Database: {DB_NAME}")
        except ConnectionFailure as e:
            logger.error(f"MongoDB connection failed: {e}")
            raise
        except Exception as e:
            logger.error(f"An unexpected error occurred during MongoDB connection: {e}")
            raise

    async def disconnect(self):
        if self.client:
            self.client.close()
            logger.info("Disconnected from MongoDB.")

    async def create_incident(self, incident: Incident) -> Incident:
        try:
            incident_dict = incident.model_dump(by_alias=True) # Use model_dump for Pydantic v2
            # Ensure _id is set for MongoDB, converting UUID to string if necessary
            if '_id' not in incident_dict:
                incident_dict['_id'] = str(incident.id)
            result = await self.collection.insert_one(incident_dict)
            incident.id = incident.id if incident.id else result.inserted_id # Ensure ID is set on model
            logger.info(f"Incident created with ID: {incident.id}")
            return incident
        except ValidationError as e:
            logger.error(f"Validation error creating incident: {e}")
            raise
        except Exception as e:
            logger.error(f"Error creating incident {incident.id}: {e}")
            raise

    async def get_incident(self, incident_id: str) -> Optional[Incident]:
        try:
            doc = await self.collection.find_one({"_id": incident_id})
            if doc:
                return Incident(**doc)
            return None
        except Exception as e:
            logger.error(f"Error getting incident {incident_id}: {e}")
            return None

    async def update_incident(self, incident_id: str, updates: Dict[str, Any]) -> Optional[Incident]:
        try:
            result = await self.collection.update_one({"_id": incident_id}, {"$set": updates})
            if result.modified_count:
                logger.info(f"Incident {incident_id} updated.")
                return await self.get_incident(incident_id)
            return None
        except Exception as e:
            logger.error(f"Error updating incident {incident_id}: {e}")
            raise

    async def delete_incident(self, incident_id: str) -> bool:
        try:
            result = await self.collection.delete_one({"_id": incident_id})
            if result.deleted_count:
                logger.info(f"Incident {incident_id} deleted.")
                return True
            return False
        except Exception as e:
            logger.error(f"Error deleting incident {incident_id}: {e}")
            raise

    async def get_all_incidents(self, skip: int = 0, limit: int = 100) -> List[Incident]:
        try:
            cursor = self.collection.find().skip(skip).limit(limit)
            incidents = [Incident(**doc) async for doc in cursor]
            return incidents
        except Exception as e:
            logger.error(f"Error getting all incidents: {e}")
            return []

# Singleton pattern for the database
incident_db = IncidentDatabase()

async def get_incident_db() -> IncidentDatabase:
    return incident_db
