# Malware Detonation Sandbox: Achievements & Integration Guide

## 1. What We Have Achieved

We have successfully engineered a robust, stealthy, and highly capable malware detonation sandbox designed specifically to handle phishing email payloads. 

### Core Capabilities Built:
* **True Network Isolation (FakeNet):** Malicious payloads are placed in a hermetically sealed Docker network with no outbound internet access. A custom `FakeNet` container intercepts all DNS and HTTP/TCP traffic, dynamically resolving malicious domains to itself and capturing all outbound communications for IOC extraction.
* **Wine-based PE Detonation:** For Windows executables (`.exe`, `.scr`, `.dll`), the sandbox utilizes a custom-built, lightweight Wine environment. It injects a hooking library (`powrprof.dll`) into the execution flow to intercept API calls, allowing us to monitor process spawning, persistence mechanisms (Registry/Filesystem), and network attempts.
* **Sandbox Evasion Countermeasures:** We addressed critical sandbox evasion techniques. The environment drops all unnecessary Docker capabilities (running purely as `UID 1000`) and intercepts anti-debugging techniques (like `NtSetInformationThread` and `NtQueryObject`) to prevent advanced malware (like `al-khaser`) from detecting the analysis environment.
* **Advanced Office Macro Emulation:** Instead of relying on a native, vulnerable Microsoft Office installation, the sandbox employs `ViperMonkey` (for VBA) and `XLMMacroDeobfuscator` (for Excel 4.0 XLM). These engines safely emulate the execution of heavily obfuscated macros in Python, extracting payloads, URLs, and dropped files without risking native code execution.
* **Automated Scoring Engine:** The API outputs a unified, structured JSON report containing a severity verdict (0-100), high-level explanations for the detection, and a consolidated list of Indicators of Compromise (URLs, IPs, domains).

---

## 2. Integration Blueprint

The Sandbox operates as a decoupled microservice exposing a REST API via FastAPI. It is designed to act as a "plug-and-play" module for your existing Phishing Email Analysis application.

### The Architecture Workflow

1. **Email Parsing (Existing App):** Your main application continues to parse `.eml` files, extracting headers, body content, and identifying attachments.
2. **Handoff (Existing App -> Sandbox):** When an attachment is found, your application extracts the raw file bytes and sends an HTTP `POST` request to the Sandbox API.
3. **Detonation (Sandbox):** The Sandbox orchestrates the containerized analysis (Static analysis, Macro emulation, or Wine execution), aggregates the telemetry, and generates the final JSON report.
4. **Ingestion (Existing App):** The main application parses the JSON report and merges the Sandbox's verdict and IOCs into the final Phishing Report presented to the user.

### API Usage for Integration

Your FastAPI application can interact with the Sandbox using standard Python HTTP libraries (like `httpx` or `requests`).

**Synchronous Execution:**
Use this endpoint if your application's background workers can wait for the analysis to complete (typically 10-30 seconds depending on the file).

```python
import httpx

async def analyze_attachment(file_bytes: bytes, filename: str):
    url = "http://<sandbox-ip>:8090/v1/analyze/sync"
    files = {'file': (filename, file_bytes)}
    
    async with httpx.AsyncClient(timeout=60.0) as client:
        response = await client.post(url, files=files)
        return response.json()
```

### Infrastructure Requirements for Integration

To seamlessly link the two applications, the following infrastructural setup is recommended:

1. **Docker Networking:** Both your existing FastAPI application and the Sandbox stack should run via Docker Compose. You can bridge them by defining an external Docker network. This allows your main application to communicate with the Sandbox API securely without exposing port 8090 to the public internet.
2. **Resource Allocation:** Ensure the host machine has sufficient RAM. While the base sandbox is lightweight, the `sbx-worker-wine` image uses roughly 1.5GB of space, and detonating complex malware requires adequate CPU resources.
3. **Data Mapping:** Your existing application will need a small parsing function to map the Sandbox's output JSON (specifically `verdict.score`, `verdict.level`, and the `iocs` block) into your existing database schema.

---

## 3. Deploying to a Production Server

To run this sandbox alongside your existing application on another server, you do not need to move any of the generated test reports or Docker volumes—you just need the source code.

### What Needs to be Moved
You need to transfer the entire `phishing_email_sandbox` directory, **excluding** the `data/` folder (which contains temporary job files and reports) and any `.git` or `__pycache__` folders to save space.

*   `docker-compose.yml`
*   `Makefile`
*   `.env.example`
*   `services/` (The API and Worker source code)
*   `tests/` (Optional, but good for verifying the new environment)

### Recommended Migration Method

**Method A: Using Git (Recommended)**
If you use version control, simply push this directory to a private Git repository, then clone it on the new server:
```bash
git clone <your-repo-url> phishing_email_sandbox
cd phishing_email_sandbox
```

**Method B: Direct Transfer (rsync or tar)**
If Git isn't an option, compress the directory locally and transfer it securely via SCP/rsync:
```bash
# On your current machine:
tar --exclude='data' --exclude='__pycache__' -czvf sandbox_code.tar.gz phishing_email_sandbox/
scp sandbox_code.tar.gz user@production-server:/path/to/deploy/
```

### Setup on the New Machine
Once the code is on the new server, setting it up takes just three steps:

1.  **Configure Environment:**
    ```bash
    cp .env.example .env
    # Edit .env to set your SANDBOX_HOST_DATA path (e.g., /opt/sandbox/data) and ENABLE_WINE=1
    ```
2.  **Build the Images:**
    The new machine must build the Docker images locally to compile the Wine environment and Python dependencies.
    ```bash
    make build-wine
    ```
3.  **Start the Stack:**
    ```bash
    make up
    ```
The API will then be available on the new machine at `http://127.0.0.1:8090` (or whichever port you specify in `.env`).
