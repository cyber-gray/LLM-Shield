import os, json, logging, azure.functions as func
from plugins.prompt_injection_detector import PromptInjectionDetector
from plugins.llm_prompt_classifier import LLMPromptClassifier

# ── environment settings ───────────────────────────────────────────
ENDPOINT        = os.getenv("OPENAI_ENDPOINT")
API_KEY         = os.getenv("OPENAI_KEY")
DEPLOYMENT_NAME = os.getenv("OPENAI_DEPLOYMENT")

if not (ENDPOINT and API_KEY and DEPLOYMENT_NAME):
    logging.error("Missing one or more required OpenAI environment variables.")

# instantiate the LLM‑based classifier once (if config present)
classifier = LLMPromptClassifier(ENDPOINT, API_KEY, DEPLOYMENT_NAME) if (ENDPOINT and API_KEY and DEPLOYMENT_NAME) else None

# ── Functions isolated‑worker app object ───────────────────────────
app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

@app.route(route="llm_shield_endpoint")     # URL path after /api/
async def llm_shield_endpoint(req: func.HttpRequest) -> func.HttpResponse:
    """
    HTTP‑trigger entry point. Expects JSON payload like:
      { "prompt": "user input here" }
    Responds 200 if safe, 403 if prompt blocked.
    """
    try:
        data = req.get_json()
    except ValueError:
        return func.HttpResponse("Invalid JSON body.", status_code=400, headers={"Access-Control-Allow-Origin": "*"})

    prompt = data.get("prompt")
    if not prompt:
        return func.HttpResponse("Missing 'prompt' field.", status_code=400, headers={"Access-Control-Allow-Origin": "*"})

    # ‑‑ layer 1: regex quick check
    if PromptInjectionDetector.is_malicious(prompt):
        logging.warning("Prompt blocked via regex detector.")
        return func.HttpResponse(
            json.dumps({"status": "blocked", "reason": "regex"}),
            status_code=403, mimetype="application/json",
            headers={"Access-Control-Allow-Origin": "*"}
        )

    # ‑‑ layer 2: LLM classifier
    if not classifier:
        logging.error("LLM classifier not initialized due to missing config.")
        return func.HttpResponse(
            json.dumps({"status": "error", "reason": "LLM classifier not configured"}),
            status_code=500, mimetype="application/json",
            headers={"Access-Control-Allow-Origin": "*"}
        )
    verdict = await classifier.classify(prompt)
    if verdict == "MALICIOUS":
        logging.warning("Prompt blocked via LLM classifier.")
        return func.HttpResponse(
            json.dumps({"status": "blocked", "reason": "llm"}),
            status_code=403, mimetype="application/json",
            headers={"Access-Control-Allow-Origin": "*"}
        )
    elif verdict.startswith("ERROR"):
        logging.error(f"LLM classifier error: {verdict}")
        return func.HttpResponse(
            json.dumps({"status": "error", "reason": verdict}),
            status_code=502, mimetype="application/json",
            headers={"Access-Control-Allow-Origin": "*"}
        )

    # safe prompt → (demo) just acknowledge; production would forward to real LLM
    logging.info("Prompt allowed.")
    return func.HttpResponse(
        json.dumps({"status": "allowed"}),
        status_code=200, mimetype="application/json",
        headers={"Access-Control-Allow-Origin": "*"}
    )