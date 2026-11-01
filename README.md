# AI-Powered SOC Assistant — Tool Calling with Python

A beginner-friendly project demonstrating OpenAI function/tool calling in a cybersecurity SOC workflow.

## What it demonstrates

The model can choose and call three Python functions:

1. `lookup_ip_reputation()` — searches a local simulated threat-intelligence dataset.
2. `calculate_risk_score()` — calculates an illustrative 0–100 risk score.
3. `create_incident_ticket()` — writes a local incident ticket to `data/incidents.json`.

The application implements the tool-calling loop: send tool definitions to the model, receive function calls, execute the corresponding Python functions, return their outputs to the model, and obtain a final response.

## Requirements

- Python 3.10+
- PyCharm
- An OpenAI API key
- An API model available to your account that supports function calling

## Setup in PyCharm

1. Open this folder as a PyCharm project.
2. Create and activate a virtual environment.
3. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

4. Copy `.env` to `.env`.
5. Add your API key to `.env`.
6. Set `OPENAI_MODEL` to a function-calling-capable model available to your API account. The example defaults to `gpt-6-astra`; change it if that model is not enabled for your API project.
7. Run `main.py`.

## Try these prompts

```text
Investigate IP 185.220.101.45, calculate its risk score, and create an incident ticket if it is high risk.
```

```text
Check the reputation of 8.8.8.8. Do not create a ticket.
```

```text
Investigate 203.0.113.25 and explain why it is suspicious or not.
```

```text
What tools are available to you?
```

After a high-risk investigation, inspect `data/incidents.json` to see the created ticket.

## How tool calling works

1. Python sends the user's request and JSON tool schemas to the OpenAI API.
2. The model decides whether a tool is needed and returns a structured function call.
3. Python parses the arguments and executes the matching local function.
4. Python sends the function result back using the original `call_id`.
5. The model uses the tool result to produce a natural-language answer. It can request further tools if needed.

The model does not directly execute Python code. Your application controls which functions are callable and executes them.

## Important limitations

- Threat-intelligence records are simulated demo data, not live VirusTotal, AbuseIPDB, or MISP results.
- The risk formula is illustrative, not a production risk model.
- Ticket creation only writes to a local JSON file. It does not connect to ServiceNow, Jira, or a SIEM.
- Never commit `.env` or expose your API key.
- Review and validate model-supplied arguments before allowing real-world actions.

## Suggested future enhancements

- Replace mock threat intelligence with a real provider API.
- Add a Streamlit user interface.
- Integrate VirusTotal or AbuseIPDB.
- Add a confirmation step before ticket creation.
- Integrate ServiceNow or Jira in a sandbox.
- Add unit tests and tool-call audit logging.

## Portfolio description

Built an AI-powered SOC assistant using Python and the OpenAI API function-calling workflow. Implemented structured JSON tool schemas and application-side execution to perform simulated threat-intelligence lookups, calculate risk scores, and create local incident tickets. Demonstrated multi-step LLM orchestration, structured arguments, tool outputs, and controlled execution of Python functions.
