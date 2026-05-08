"""
Feedback Service for Model Improvement
=======================================
Handles user feedback on detection results to improve model accuracy
and reduce false positives/negatives.
"""

import os
import json
import logging
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List
from enum import Enum

try:
    from backend.config.settings import (
        FEEDBACK_TYPES, MIN_FEEDBACK_FOR_RETRAIN,
        MONGO_URI, DB_NAME, FEEDBACK_COLLECTION
    )
    from backend.core.logger import get_logger
except ImportError:
    FEEDBACK_TYPES = [
        "false_positive", "false_negative", "correct_detection",
        "severity_adjustment", "general_feedback"
    ]
    MIN_FEEDBACK_FOR_RETRAIN = 100
    MONGO_URI = "mongodb://localhost:27017"
    DB_NAME = "acds"
    FEEDBACK_COLLECTION = "feedback"
    logging.basicConfig(level=logging.INFO)
    def get_logger(name):
        return logging.getLogger(name)

# Optional MongoDB support
try:
    from pymongo import MongoClient
    from pymongo.errors import ConnectionFailure
    MONGO_AVAILABLE = True
except ImportError:
    MONGO_AVAILABLE = False


class FeedbackType(Enum):
    """Types of feedback that can be submitted."""
    FALSE_POSITIVE = "false_positive"  # Legitimate email marked as phishing
    FALSE_NEGATIVE = "false_negative"  # Phishing email marked as safe
    CORRECT_DETECTION = "correct_detection"  # Correct classification
    SEVERITY_ADJUSTMENT = "severity_adjustment"  # Severity was wrong
    GENERAL_FEEDBACK = "general_feedback"  # Other feedback


class FeedbackService:
    """
    Service for collecting and managing user feedback on threat detections.
    Used to improve model accuracy through feedback loops.
    """
    
    def __init__(self):
        """Initialize the feedback service."""
        self.logger = get_logger(__name__)
        self.db = None
        self.collection = None
        self.local_storage_path = "data/feedback"
        
        # Initialize storage
        self._init_storage()
        
        # In-memory feedback cache
        self.feedback_cache: List[Dict] = []
        
        # Statistics
        self.stats = {
            'total_feedback': 0,
            'false_positives': 0,
            'false_negatives': 0,
            'correct_detections': 0,
            'pending_review': 0,
        }
        
        self.logger.info("FeedbackService initialized")
    
    def _init_storage(self) -> None:
        """Initialize storage backend (MongoDB or local files)."""
        if MONGO_AVAILABLE:
            try:
                client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
                client.admin.command('ping')
                self.db = client[DB_NAME]
                self.collection = self.db[FEEDBACK_COLLECTION]
                self.logger.info("Connected to MongoDB for feedback storage")
            except Exception as e:
                self.logger.warning(f"MongoDB unavailable, using local storage: {e}")
        
        # Ensure local storage directory exists
        os.makedirs(self.local_storage_path, exist_ok=True)
    
    def submit_feedback(
        self,
        scan_id: str,
        feedback_type: str,
        original_prediction: Dict[str, Any],
        correct_label: Optional[bool] = None,
        correct_severity: Optional[str] = None,
        user_comment: Optional[str] = None,
        submitted_by: Optional[str] = None,
        email_content: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Submit feedback for a detection result.
        
        Args:
            scan_id: ID of the original scan
            feedback_type: Type of feedback (false_positive, false_negative, etc.)
            original_prediction: The original prediction result
            correct_label: What the correct classification should be
            correct_severity: What the correct severity should be
            user_comment: Optional comment from the user
            submitted_by: User who submitted the feedback
            email_content: Original email content (for retraining)
        
        Returns:
            Dictionary with feedback submission result
        """
        # Validate feedback type
        if feedback_type not in FEEDBACK_TYPES:
            return {
                'success': False,
                'error': f'Invalid feedback type. Must be one of: {FEEDBACK_TYPES}'
            }
        
        feedback_entry = {
            'feedback_id': f"fb_{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}",
            'scan_id': scan_id,
            'feedback_type': feedback_type,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'original_prediction': {
                'is_phishing': original_prediction.get('is_phishing'),
                'confidence': original_prediction.get('confidence'),
                'severity': original_prediction.get('severity'),
            },
            'correction': {
                'correct_label': correct_label,
                'correct_severity': correct_severity,
            },
            'user_comment': user_comment,
            'submitted_by': submitted_by or 'anonymous',
            'status': 'pending_review',
            'reviewed': False,
            'reviewer': None,
            'review_timestamp': None,
            'used_for_retraining': False,
        }
        
        # Store email content separately if provided (for retraining)
        if email_content:
            feedback_entry['has_email_content'] = True
            self._store_email_content(feedback_entry['feedback_id'], email_content)
        
        # Save feedback
        saved = self._save_feedback(feedback_entry)
        
        if saved:
            # Update statistics
            self.stats['total_feedback'] += 1
            self.stats['pending_review'] += 1
            
            if feedback_type == 'false_positive':
                self.stats['false_positives'] += 1
            elif feedback_type == 'false_negative':
                self.stats['false_negatives'] += 1
            elif feedback_type == 'correct_detection':
                self.stats['correct_detections'] += 1
            
            self.logger.info(f"Feedback submitted: {feedback_entry['feedback_id']} ({feedback_type})")
            
            # Check if retraining threshold reached
            retrain_needed = self._check_retrain_threshold()
            
            return {
                'success': True,
                'feedback_id': feedback_entry['feedback_id'],
                'message': 'Feedback submitted successfully',
                'retrain_recommended': retrain_needed
            }
        
        return {
            'success': False,
            'error': 'Failed to save feedback'
        }
    
    def _save_feedback(self, feedback: Dict) -> bool:
        """Save feedback to storage."""
        try:
            # Try MongoDB first
            if self.collection is not None:
                self.collection.insert_one(feedback.copy())
            
            # Always save to local storage as backup
            filename = f"{feedback['feedback_id']}.json"
            filepath = os.path.join(self.local_storage_path, filename)
            with open(filepath, 'w') as f:
                json.dump(feedback, f, indent=2)
            
            # Add to cache
            self.feedback_cache.append(feedback)
            if len(self.feedback_cache) > 1000:
                self.feedback_cache = self.feedback_cache[-1000:]
            
            return True
        except Exception as e:
            self.logger.error(f"Error saving feedback: {e}")
            return False
    
    def _store_email_content(self, feedback_id: str, content: str) -> None:
        """Store email content for retraining purposes."""
        try:
            content_dir = os.path.join(self.local_storage_path, "email_content")
            os.makedirs(content_dir, exist_ok=True)
            filepath = os.path.join(content_dir, f"{feedback_id}.txt")
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
        except Exception as e:
            self.logger.error(f"Error storing email content: {e}")
    
    def _check_retrain_threshold(self) -> bool:
        """Check if enough feedback has been collected to trigger retraining."""
        total = self.stats['false_positives'] + self.stats['false_negatives']
        if total >= MIN_FEEDBACK_FOR_RETRAIN:
            self.logger.info(f"Retraining threshold reached: {total} feedback entries")
            return True
        return False
    
    def get_feedback(self, feedback_id: str) -> Optional[Dict]:
        """Get a specific feedback entry."""
        # Check cache first
        for fb in self.feedback_cache:
            if fb.get('feedback_id') == feedback_id:
                return fb
        
        # Check MongoDB
        if self.collection is not None:
            result = self.collection.find_one({'feedback_id': feedback_id})
            if result:
                result.pop('_id', None)
                return result
        
        # Check local storage
        filepath = os.path.join(self.local_storage_path, f"{feedback_id}.json")
        if os.path.exists(filepath):
            with open(filepath, 'r') as f:
                return json.load(f)
        
        return None
    
    def get_pending_feedback(self, limit: int = 50) -> List[Dict]:
        """Get feedback entries pending review."""
        pending = []
        
        if self.collection is not None:
            cursor = self.collection.find(
                {'status': 'pending_review'}
            ).sort('timestamp', -1).limit(limit)
            
            for doc in cursor:
                doc.pop('_id', None)
                pending.append(doc)
        else:
            # Load from local storage
            for filename in os.listdir(self.local_storage_path):
                if filename.endswith('.json'):
                    filepath = os.path.join(self.local_storage_path, filename)
                    try:
                        with open(filepath, 'r') as f:
                            feedback = json.load(f)
                            if feedback.get('status') == 'pending_review':
                                pending.append(feedback)
                    except:
                        continue
            
            # Sort by timestamp and limit
            pending.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
            pending = pending[:limit]
        
        return pending
    
    def review_feedback(
        self,
        feedback_id: str,
        approved: bool,
        reviewer: str,
        review_notes: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Review and approve/reject a feedback entry.
        
        Args:
            feedback_id: ID of the feedback to review
            approved: Whether the feedback is approved
            reviewer: Username of the reviewer
            review_notes: Optional notes from the reviewer
        
        Returns:
            Result of the review action
        """
        feedback = self.get_feedback(feedback_id)
        if not feedback:
            return {'success': False, 'error': 'Feedback not found'}
        
        feedback['reviewed'] = True
        feedback['reviewer'] = reviewer
        feedback['review_timestamp'] = datetime.now(timezone.utc).isoformat()
        feedback['status'] = 'approved' if approved else 'rejected'
        feedback['review_notes'] = review_notes
        
        # Update in storage
        if self.collection is not None:
            self.collection.update_one(
                {'feedback_id': feedback_id},
                {'$set': feedback}
            )
        
        # Update local file
        filepath = os.path.join(self.local_storage_path, f"{feedback_id}.json")
        if os.path.exists(filepath):
            with open(filepath, 'w') as f:
                json.dump(feedback, f, indent=2)
        
        self.stats['pending_review'] -= 1
        
        self.logger.info(f"Feedback {feedback_id} {'approved' if approved else 'rejected'} by {reviewer}")
        
        return {
            'success': True,
            'feedback_id': feedback_id,
            'status': feedback['status']
        }
    
    def get_retraining_data(self) -> Dict[str, Any]:
        """
        Get approved feedback data formatted for model retraining.
        
        Returns:
            Dictionary with training data and statistics
        """
        approved_feedback = []
        
        if self.collection is not None:
            cursor = self.collection.find({
                'status': 'approved',
                'used_for_retraining': False
            })
            for doc in cursor:
                doc.pop('_id', None)
                approved_feedback.append(doc)
        else:
            # Load from local storage
            for filename in os.listdir(self.local_storage_path):
                if filename.endswith('.json'):
                    filepath = os.path.join(self.local_storage_path, filename)
                    try:
                        with open(filepath, 'r') as f:
                            feedback = json.load(f)
                            if (feedback.get('status') == 'approved' and 
                                not feedback.get('used_for_retraining')):
                                approved_feedback.append(feedback)
                    except:
                        continue
        
        # Load email content for retraining
        training_samples = []
        content_dir = os.path.join(self.local_storage_path, "email_content")
        
        for fb in approved_feedback:
            if fb.get('has_email_content'):
                content_file = os.path.join(content_dir, f"{fb['feedback_id']}.txt")
                if os.path.exists(content_file):
                    try:
                        with open(content_file, 'r', encoding='utf-8') as f:
                            content = f.read()
                        
                        training_samples.append({
                            'content': content,
                            'label': fb['correction']['correct_label'],
                            'feedback_id': fb['feedback_id'],
                            'feedback_type': fb['feedback_type']
                        })
                    except:
                        continue
        
        return {
            'total_approved': len(approved_feedback),
            'with_content': len(training_samples),
            'samples': training_samples,
            'false_positives': len([f for f in approved_feedback if f['feedback_type'] == 'false_positive']),
            'false_negatives': len([f for f in approved_feedback if f['feedback_type'] == 'false_negative']),
        }
    
    def mark_used_for_retraining(self, feedback_ids: List[str]) -> int:
        """Mark feedback entries as used for retraining."""
        count = 0
        for fb_id in feedback_ids:
            if self.collection is not None:
                result = self.collection.update_one(
                    {'feedback_id': fb_id},
                    {'$set': {'used_for_retraining': True}}
                )
                if result.modified_count > 0:
                    count += 1
            
            # Update local file
            filepath = os.path.join(self.local_storage_path, f"{fb_id}.json")
            if os.path.exists(filepath):
                try:
                    with open(filepath, 'r') as f:
                        feedback = json.load(f)
                    feedback['used_for_retraining'] = True
                    with open(filepath, 'w') as f:
                        json.dump(feedback, f, indent=2)
                    count += 1
                except:
                    continue
        
        return count
    
    def get_feedback_summary(self) -> Dict[str, Any]:
        """Get a summary of all feedback."""
        summary = {
            'total': 0,
            'by_type': {},
            'by_status': {},
            'accuracy_metrics': {},
        }
        
        all_feedback = []
        
        if self.collection is not None:
            cursor = self.collection.find({})
            for doc in cursor:
                doc.pop('_id', None)
                all_feedback.append(doc)
        else:
            # Load from local storage
            for filename in os.listdir(self.local_storage_path):
                if filename.endswith('.json'):
                    filepath = os.path.join(self.local_storage_path, filename)
                    try:
                        with open(filepath, 'r') as f:
                            all_feedback.append(json.load(f))
                    except:
                        continue
        
        summary['total'] = len(all_feedback)
        
        for fb in all_feedback:
            fb_type = fb.get('feedback_type', 'unknown')
            fb_status = fb.get('status', 'unknown')
            
            summary['by_type'][fb_type] = summary['by_type'].get(fb_type, 0) + 1
            summary['by_status'][fb_status] = summary['by_status'].get(fb_status, 0) + 1
        
        # Calculate accuracy metrics
        fp = summary['by_type'].get('false_positive', 0)
        fn = summary['by_type'].get('false_negative', 0)
        correct = summary['by_type'].get('correct_detection', 0)
        total_labeled = fp + fn + correct
        
        if total_labeled > 0:
            summary['accuracy_metrics'] = {
                'accuracy': correct / total_labeled,
                'false_positive_rate': fp / total_labeled,
                'false_negative_rate': fn / total_labeled,
                'total_labeled': total_labeled,
            }
        
        return summary
    
    def get_stats(self) -> Dict[str, Any]:
        """Get feedback service statistics."""
        return {
            **self.stats,
            'retrain_threshold': MIN_FEEDBACK_FOR_RETRAIN,
            'storage_type': 'mongodb' if self.collection else 'local',
        }


# Singleton instance
_feedback_service: Optional[FeedbackService] = None


def get_feedback_service() -> FeedbackService:
    """Get or create the feedback service singleton."""
    global _feedback_service
    if _feedback_service is None:
        _feedback_service = FeedbackService()
    return _feedback_service
