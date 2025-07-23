
NuVex SOC Copilot
A Security Operations Center (SOC) AI agent for analyzing offenses, enriching with threat intelligence, and generating reports.
Setup

Clone the repository:git clone <repo-url>
cd nuvex-mvp


Create directories:mkdir -p reports logs dummy_data


Set up environment variables in .env:MODEL_PROVIDER=openai
OPENAI_API_KEY=your-openai-key
GEMINI_API_KEY=your-gemini-key
VIRUSTOTAL_API_KEY=your-virustotal-key
ABUSEIPDB_API_KEY=your-abuseipdb-key


Build and run with Docker:docker-compose up --build


Test the API:curl -X POST http://localhost:8000/ingest-offense -H "Content-Type: application/json" -d @dummy_data/offense_samples.json



Usage

Send offense data to /ingest-offense endpoint.
Outputs: reports/offense_<id>.txt (escalated) or reports/false_positive_notes.txt (false positives).
Log queries: logs/instructions/.
