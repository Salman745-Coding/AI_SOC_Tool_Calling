import os
import json
import ipaddress
import uuid
from datetime import datetime, timezone

from dotenv import load_dotenv
from openai import OpenAI

load_dotenv()

API_KEY = os.getenv("OPENAI_API_KEY")
MODEL = os.getenv("OPENAI_MODEL", "gpt-6-astra")
if not API_KEY:
    raise RuntimeError("OPENAI_API_KEY is missing. Add it to your .env file.")

client = OpenAI(api_key=API_KEY)
INCIDENTS_FILE = os.path.join("data", "incidents.json")

# DEMO DATA ONLY: these records are simulated, not live threat-intelligence results.
MOCK_THREAT_INTEL = {
    "185.220.101.45": {
        "reputation": "malicious",
        "malicious_reports": 87,
        "categories": ["known scanner", "suspicious network activity"],
        "source": "Simulated SOC threat-intelligence dataset"
    },
    "8.8.8.8": {
        "reputation": "clean",
        "malicious_reports": 0,
        "categories": [],
        "source": "Simulated SOC threat-intelligence dataset"
    },
    "203.0.113.25": {
        "reputation": "suspicious",
        "malicious_reports": 12,
        "categories": ["repeated failed connections"],
        "source": "Simulated SOC threat-intelligence dataset"
    }
}


def lookup_ip_reputation(ip_address: str) -> dict:
    """Look up an IP address in the local simulated threat-intelligence dataset."""
    try:
        normalized_ip = str(ipaddress.ip_address(ip_address))
    except ValueError:
        return {"error": "Invalid IP address format."}

    record = MOCK_THREAT_INTEL.get(normalized_ip)
    if record:
        return {"ip_address": normalized_ip, **record}

    return {
        "ip_address": normalized_ip,
        "reputation": "unknown",
        "malicious_reports": 0,
        "categories": [],
        "source": "Simulated SOC threat-intelligence dataset",
        "note": "No matching record exists in this demo dataset. This does not prove the IP is safe."
    }


def calculate_risk_score(reputation: str, malicious_reports: int) -> dict:
    """Calculate a transparent demo risk score from reputation and report count."""
    reputation_points = {
        "clean": 0,
        "unknown": 10,
        "suspicious": 35,
        "malicious": 60
    }

    if reputation not in reputation_points:
        return {"error": "Unsupported reputation value."}

    if not isinstance(malicious_reports, int) or malicious_reports < 0:
        return {"error": "malicious_reports must be a non-negative integer."}

    score = min(100, reputation_points[reputation] + min(malicious_reports, 40))
    if score >= 70:
        level = "HIGH"
    elif score >= 35:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "risk_score": score,
        "risk_level": level,
        "calculation": (
            f"Reputation points ({reputation_points[reputation]}) + "
            f"report points ({min(malicious_reports, 40)})"
        ),
        "disclaimer": "This is an educational demo formula, not a validated production risk model."
    }


def create_incident_ticket(ip_address: str, summary: str, risk_score: int) -> dict:
    """Create a local JSON incident ticket. No external system is modified."""
    try:
        normalized_ip = str(ipaddress.ip_address(ip_address))
    except ValueError:
        return {"error": "Invalid IP address format."}

    if not isinstance(risk_score, int) or not 0 <= risk_score <= 100:
        return {"error": "risk_score must be an integer from 0 to 100."}

    os.makedirs(os.path.dirname(INCIDENTS_FILE), exist_ok=True)
    if os.path.exists(INCIDENTS_FILE):
        try:
            with open(INCIDENTS_FILE, "r", encoding="utf-8") as file:
                incidents = json.load(file)
        except (json.JSONDecodeError, OSError):
            incidents = []
    else:
        incidents = []

    ticket = {
        "ticket_id": f"SOC-{uuid.uuid4().hex[:8].upper()}",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "ip_address": normalized_ip,
        "summary": summary,
        "risk_score": risk_score,
        "status": "OPEN",
        "source": "AI SOC Tool Calling Demo"
    }
    incidents.append(ticket)

    with open(INCIDENTS_FILE, "w", encoding="utf-8") as file:
        json.dump(incidents, file, indent=4)

    return {"message": "Incident ticket created successfully.", "ticket": ticket}


# JSON schemas tell the model what each Python tool does and which arguments it needs.
TOOLS = [
    {
        "type": "function",
        "name": "lookup_ip_reputation",
        "description": "Look up an IP address in the demo threat-intelligence dataset. Use this when investigating an IP. Results are simulated, not live intelligence.",
        "strict": True,
        "parameters": {
            "type": "object",
            "properties": {
                "ip_address": {
                    "type": "string",
                    "description": "The IPv4 or IPv6 address to investigate."
                }
            },
            "required": ["ip_address"],
            "additionalProperties": False
        }
    },
    {
        "type": "function",
        "name": "calculate_risk_score",
        "description": "Calculate a demo SOC risk score using the reputation and malicious report count returned by the lookup tool.",
        "strict": True,
        "parameters": {
            "type": "object",
            "properties": {
                "reputation": {
                    "type": "string",
                    "enum": ["clean", "unknown", "suspicious", "malicious"]
                },
                "malicious_reports": {
                    "type": "integer",
                    "minimum": 0
                }
            },
            "required": ["reputation", "malicious_reports"],
            "additionalProperties": False
        }
    },
    {
        "type": "function",
        "name": "create_incident_ticket",
        "description": "Create a local JSON incident ticket. Only call this when the calculated risk level is HIGH or the user explicitly requests ticket creation. This is a local demo action.",
        "strict": True,
        "parameters": {
            "type": "object",
            "properties": {
                "ip_address": {"type": "string"},
                "summary": {"type": "string"},
                "risk_score": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 100
                }
            },
            "required": ["ip_address", "summary", "risk_score"],
            "additionalProperties": False
        }
    }
]

TOOL_FUNCTIONS = {
    "lookup_ip_reputation": lookup_ip_reputation,
    "calculate_risk_score": calculate_risk_score,
    "create_incident_ticket": create_incident_ticket
}


def run_soc_assistant(user_prompt: str) -> str:
    """Run the model/tool/model loop until the model returns a final answer."""
    instructions = """
You are an AI SOC analyst assistant for an educational demonstration.
Use the available tools when the user asks to investigate an IP address.
For an IP investigation, look up its reputation first, then calculate a risk score
using the exact reputation and malicious_reports returned by the lookup tool.
Create a local incident ticket when the calculated risk level is HIGH, unless
the user says not to create one. Never claim that simulated data is live intelligence.
If a lookup returns unknown, explain that absence from the demo dataset does not
mean the IP is safe. Clearly explain that the risk formula is illustrative only.
Do not invent tool results or ticket IDs.
"""

    conversation = [{"role": "user", "content": user_prompt}]

    for round_number in range(6):
        response = client.responses.create(
            model=MODEL,
            instructions=instructions,
            tools=TOOLS,
            input=conversation
        )

        function_calls = [
            item for item in response.output
            if getattr(item, "type", None) == "function_call"
        ]

        if not function_calls:
            return response.output_text or "The model returned no text response."

        # Preserve all model output items, including any reasoning items.
        conversation.extend(response.output)

        for tool_call in function_calls:
            function_name = tool_call.name
            print(f"\n[TOOL CALL] {function_name}")
            try:
                arguments = json.loads(tool_call.arguments)
                function_to_call = TOOL_FUNCTIONS.get(function_name)

                if function_to_call is None:
                    result = {"error": f"Tool not found: {function_name}"}
                else:
                    print(f"[ARGUMENTS] {json.dumps(arguments)}")
                    result = function_to_call(**arguments)
            except Exception as error:
                result = {"error": str(error)}

            print(f"[TOOL RESULT] {json.dumps(result, indent=2)}")

            conversation.append({
                "type": "function_call_output",
                "call_id": tool_call.call_id,
                "output": json.dumps(result)
            })

    return "Stopped after reaching the maximum tool-call rounds. Please try a simpler request."


def main():
    print("=" * 65)
    print("       AI-POWERED SOC ASSISTANT | TOOL CALLING DEMO")
    print("=" * 65)
    print("Demo IPs: 185.220.101.45 | 8.8.8.8 | 203.0.113.25")
    print("Type 'exit' to quit.\n")

    while True:
        user_prompt = input("\nYou: ").strip()
        if user_prompt.lower() in {"exit", "quit"}:
            print("Goodbye!")
            break
        if not user_prompt:
            continue

        try:
            answer = run_soc_assistant(user_prompt)
            print("\nAI SOC ASSISTANT:")
            print(answer)
        except Exception as error:
            print(f"\nApplication error: {error}")


if __name__ == "__main__":
    main()
