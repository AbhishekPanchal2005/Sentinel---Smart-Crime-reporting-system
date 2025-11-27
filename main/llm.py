import json
from openai import OpenAI
from decouple import config

client = OpenAI(api_key=config("OPENAI_API_KEY"))
MODEL = config("OPENAI_MODEL", default="gpt-4o-mini")

PROMPT = """
You are an intelligent assistant for a police crime reporting system.
Given a raw citizen report (may include broken English, Hinglish, or slang),
classify the crime type, assign a severity level (1-5), and priority (Low/Medium/High),
and generate a short summary for officers.

Return your output in strict JSON format as:
{
  "crime_type": "",
  "severity": "",
  "priority": "",
  "summary": ""
}
"""

def analyze_crime_description(description: str):
    try:
        response = client.responses.create(
            model=MODEL,
            input=[
                {"role": "system", "content": PROMPT},
                {"role": "user", "content": f"Citizen report: {description}"}
            ],
            temperature=0.3,
            response_format={ "type": "json_object" }
        )
        data = json.loads(response.output_text)
        return data
    except Exception as e:
        print("LLM Error:", e)
        return {
            "crime_type": "Unknown",
            "severity": "2",
            "priority": "Medium",
            "summary": "Could not analyze due to error."
        }
