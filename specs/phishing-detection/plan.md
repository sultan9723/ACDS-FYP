# Architectural Plan: Phishing Detection Module MVP

## 1. Scope and Dependencies

### In Scope (explicit MVP capabilities)
*   Automated detection of phishing emails using a rule-based or basic ML model.
*   Creation and storage of phishing incidents in a MongoDB database upon detection.
*   Generation of explanations for detected phishing incidents (confidence score, matched indicators).
*   Triggering of an orchestration process (simulated/placeholder for MVP).
*   Updating incident status and timeline in the database.
*   Generation of human-readable text and PDF reports for handled incidents.
*   Processing email input from a Hugging Face dataset (batch processing).
*   Defining explicit states for Incidents (New, Detected, Investigating, Remediated, Closed, False Positive).
*   Implementation of API key authentication for backend API access.
*   Ensuring data encryption at rest (DB) and in transit (API).
*   Establishing structured logging for critical operations and errors.
*   Exposing basic application health metrics (e.g., uptime, request counts, error rates).
*   Implementing an error handling strategy: log errors, update incident status to "Failed" or "Error", notify administrator for unrecoverable errors.

### Out of Scope (explicit exclusions)
*   Real-time email ingestion or processing from live mailboxes.
*   Full, autonomous response actions by the Orchestration Agent (MVP triggers a placeholder orchestration).
*   Advanced LLM-driven response actions.
*   Frontend user interface (this plan defines the backend API for future frontend integration).
*   Complex role-based access control (RBAC) (to be defined in a later phase).
*   Comprehensive distributed tracing (to be considered in a later phase).
*   Automatic retries for unrecoverable errors.

### External Dependencies (databases, frameworks, ML stack)
*   **Database**: MongoDB (cloud instance confirmed for local development).
*   **Frameworks**:
    *   Python 3.11
    *   FastAPI (for potential future API exposure)
    *   Pydantic (for data validation and serialization)
*   **ML Stack**:
    *   scikit-learn (for detection model)
    *   joblib (for model persistence)
    *   datasets (Hugging Face datasets for email input)
    *   Python email module (for email parsing)
*   **Reporting**: `reportlab` (for PDF generation).
*   **Utilities**: `python-dotenv` (for environment variable management), `motor` (async MongoDB driver).

## 2. Key Decisions and Rationale

### Language and framework choices
*   **Python 3.11**: Chosen for its robust ecosystem for ML/AI development, ease of integration with data science tools, and readability. Aligns with existing project components and skillsets.
*   **FastAPI**: Selected for building the backend API due to its high performance (comparable to NodeJS and Go), automatic data validation/serialization via Pydantic, and automatic interactive API documentation (Swagger UI/ReDoc), which accelerates frontend integration.

### ML vs LLM usage boundaries
*   **ML (scikit-learn, rule-based)**: Used for core phishing detection in the MVP. This provides deterministic and explainable results, aligning with the "Responsible AI Usage" and "Deterministic fallback for AI" principles. It ensures the system's core function is predictable and auditable.
*   **LLM (future)**: While LLMs could enhance explanation or response generation, their usage is intentionally limited in the MVP to prevent non-deterministic or unexplainable outcomes in critical security functions. LLMs might be explored in future phases for less critical, human-in-the-loop assistance, ensuring "ACDS Role Preservation" (investigation-preparation focus, not autonomous response).

### Database choice
*   **MongoDB (via Motor)**: Selected as the primary data store for incidents due to its flexible, schema-less (or schema-on-read) document model, which is well-suited for varied and evolving incident data structures. The use of Motor provides asynchronous I/O capabilities, aligning with FastAPI's async nature for better performance. Cloud instance for local development supports agile development without local setup overhead for complex DBs.

### Trade-offs and alignment with Responsible AI and ACDS principles
*   **ACDS Role Preservation**: The module focuses on investigation *preparation*, not fully autonomous response. Analyst decision authority is preserved by providing structured incidents, explanations, and reports, rather than taking direct remediation actions.
*   **Responsible AI Usage**: Initial phishing detection relies on deterministic/explainable ML models (or rule-based systems). This prioritizes transparency and auditability over potentially opaque LLM decisions. Future AI integrations will maintain a clear human-in-the-loop mechanism and deterministic fallbacks.
*   **Technology Stack**: Python and FastAPI align with open-source, non-proprietary lock-in principles. The use of a cloud MongoDB instance for local development is a justified exception for a cloud dependency, as per the constitution, to streamline developer setup.
*   **Performance vs. Complexity**: Prioritizing speed for incident creation and report generation (as per `SC-002`, `SC-006` in `spec.md`) but deferring complex features like full distributed tracing or comprehensive RBAC to maintain MVP focus and reduce initial complexity.

## 3. Interfaces and API Contracts
*   **Base Path**: `/api/v1/phishing-detection`

### Endpoints (Draft)

#### `POST /api/v1/phishing-detection/process-emails`
*   **Description**: Initiates a batch processing of emails for phishing detection. This endpoint is primarily for internal system use or testing with datasets.
*   **Request Body**:
    ```json
    {
      "email_dataset_name": "string",
      "email_split": "string",
      "raw_text_column": "string"
    }
    ```
    (This is a simplified representation assuming processing a Hugging Face dataset. A more robust API would accept raw email content.)
*   **Response**:
    *   `202 Accepted`: Processing initiated.
        ```json
        {
          "message": "Email processing initiated.",
          "task_id": "uuid"
        }
        ```
    *   `400 Bad Request`: Invalid input.
    *   `500 Internal Server Error`: Server error during initiation.

#### `GET /api/v1/phishing-detection/incidents/{incident_id}`
*   **Description**: Retrieves details for a specific phishing incident.
*   **Path Parameters**:
    *   `incident_id`: `string` (UUID) - Unique identifier of the incident.
*   **Response**:
    *   `200 OK`: Incident details.
        ```json
        {
          "id": "uuid",
          "status": "string (enum: New, Detected, Investigating, Remediated, Closed, False Positive)",
          "detection_timestamp": "datetime (ISO 8601)",
          "detection_agent_id": "string",
          "explanation_details": {
            "confidence_score": "float",
            "matched_indicators": ["string"]
          },
          "email_id": "uuid",
          "timeline": [
            {
              "timestamp": "datetime (ISO 8601)",
              "event": "string",
              "details": "object"
            }
          ],
          "assigned_analyst": "string (optional)"
        }
        ```
    *   `404 Not Found`: Incident not found.
    *   `401 Unauthorized`: Invalid API Key.

#### `GET /api/v1/phishing-detection/incidents`
*   **Description**: Retrieves a list of all phishing incidents, with optional filtering and pagination.
*   **Query Parameters**:
    *   `status`: `string` (optional, enum: New, Detected, Investigating, Remediated, Closed, False Positive) - Filter by incident status.
    *   `limit`: `integer` (optional, default: 100) - Maximum number of incidents to return.
    *   `offset`: `integer` (optional, default: 0) - Number of incidents to skip.
*   **Response**:
    *   `200 OK`: List of incidents.
        ```json
        {
          "total": "integer",
          "incidents": [
            {
              "id": "uuid",
              "status": "string",
              "detection_timestamp": "datetime (ISO 8601)",
              "email_id": "uuid",
              "assigned_analyst": "string (optional)"
            }
          ]
        }
        ```
    *   `401 Unauthorized`: Invalid API Key.

#### `GET /api/v1/phishing-detection/incidents/{incident_id}/report/pdf`
*   **Description**: Generates and returns a PDF report for a specific phishing incident.
*   **Path Parameters**:
    *   `incident_id`: `string` (UUID) - Unique identifier of the incident.
*   **Response**:
    *   `200 OK`: Returns the PDF file.
    *   `404 Not Found`: Incident not found.
    *   `401 Unauthorized`: Invalid API Key.
    *   `500 Internal Server Error`: Error generating PDF.

### Versioning Strategy
*   API versioning will be implemented via the URL path (e.g., `/api/v1/`). This is a clear and commonly understood approach for API versioning. Major breaking changes will result in an increment of the version number.

### Error Taxonomy with status codes
*   **2xx Success**:
    *   `200 OK`: Standard success for GET requests.
    *   `202 Accepted`: Request accepted for processing, but processing is not yet complete (e.g., for batch email processing).
*   **4xx Client Errors**:
    *   `400 Bad Request`: General client input error (e.g., malformed JSON, invalid parameters).
    *   `401 Unauthorized`: Request missing valid authentication credentials (API Key).
    *   `404 Not Found`: Resource not found.
    *   `429 Too Many Requests`: Rate limiting applied (future consideration).
*   **5xx Server Errors**:
    *   `500 Internal Server Error`: Generic server-side error.
    *   `503 Service Unavailable`: Temporary server overload or maintenance.