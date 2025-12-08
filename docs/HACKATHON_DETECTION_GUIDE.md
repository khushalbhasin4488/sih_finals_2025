# 🛡️ Hackathon Evaluation Guide: Detection & Analysis Engine (Deep Dive)

**Version:** 1.1 (Advanced Technical Detail)
**Target Structure:** DuckDB (OLAP) $\rightarrow$ Async Orchestrator $\rightarrow$ 7 Parallel Detection Engines

This comprehensive document details the **Analysis Layer** of our Log Analyzer Tool. It serves as the primary technical reference for hackathon judges, explaining the mathematical foundations, algorithmic complexity, and specific implementation details of our defense-in-depth architecture.

---

## 1. System Architecture: The "Seven-Engine" Pipeline

Our analysis layer is an **asynchronous, event-driven pipeline** orchestrated to run 7 distinct detection engines in parallel. This ensures that while one engine performs computationally expensive statistical analysis, others can perform fast pattern matching.

### 📐 High-Level Data Flow

```mermaid
graph TD
    Input[New Logs Batch (10k logs)] --> Orchestrator[Analysis Orchestrator (AsyncIO)]
    
    subgraph "Deterministic Layer (O(N))"
        Orchestrator --> Sig[1. Signature Detector]
        Orchestrator --> Rule[2. Rule Engine (Sigma)]
        Orchestrator --> TI[3. Threat Intel Matcher]
    end
    
    subgraph "Probabilistic Layer (O(N log N))"
        Orchestrator --> Anom[4. Anomaly Detector]
        Orchestrator --> Net[5. Network Analyzer]
        Orchestrator --> Heur[6. Heuristic Analyzer]
        Orchestrator --> Beh[7. Behavioral Analyzer (UEBA)]
    end
    
    Sig & Rule & TI & Anom & Net & Heur & Beh --> Aggregator[Alert Aggregator]
    Aggregator --> Prioritizer[Prioritization & Deduplication]
    Prioritizer --> Output[(DuckDB - Alerts Table)]
```

### ⚙️ Orchestration Implementation (`orchestrator.py`)
*   **Concurrency Model**: Uses Python's `asyncio.gather()` to execute `detector.analyze(logs)` for all 7 detectors simultaneously.
*   **Batch Processing**: Logs are fetched in batches (default: 10,000) to optimize I/O overhead against DuckDB.
*   **Fault Tolerance**: The orchestrator wraps each detector in a `try/except` block; if the ML engine fails, the Signature engine *still* protects the system.

---

## 2. Deep Dive: Detection Methodologies & Math

### 🔍 Engine 1: Signature-Based Detection
*   **Goal**: Zero-latency detection of known threats.
*   **Algorithmic Complexity**: $O(N \times M)$ where $N$ is logs and $M$ is active signatures.
*   **Optimization**:
    *   **Regex Compilation**: All 50+ regex patterns are pre-compiled (`re.compile`) at startup.
    *   **Hash Lookups**: Malware hash checking is $O(1)$ using Python Set lookups.

### 📊 Engine 2: Anomaly Detection (The Math)
*   **Goal**: Detect statistical outliers (Zero-Day Indicators).
*   **Mathematical Model 1: Z-Score (Standard Score)**
    *   **Formula**: $$Z = \frac{x - \mu}{\sigma}$$
    *   **Variables**:
        *   $x$: Current value (e.g., failed logins in last 5m).
        *   $\mu$: Rolling mean of the baseline.
        *   $\sigma$: Standard deviation of the baseline.
    *   **Logic**: If $|Z| > 3.0$, the event is $3\sigma$ away from the mean (0.3% probability in normal distribution) $\rightarrow$ **Alert**.
*   **Mathematical Model 2: Isolation Forest** (Fallback: IQR)
    *   For multi-dimensional data (e.g., packet size vs. frequency), we use Isolation Forests to isolate anomalies by randomly partitioning the feature space. Anomalies are isolated in fewer steps than normal points.

### 🧠 Engine 3: Heuristic Analysis (Stateful Logic)
*   **Goal**: Correlate disparate events across time.
*   **Implementation**: Sliding Window Protocol.
*   **Scenario: Brute Force Detection**
    1.  **Input**: Stream of Login Logs.
    2.  **State**: Dictionary `{ (source_ip, user): [timestamp1, timestamp2, ...] }`.
    3.  **Logic**:
        ```python
        if count(failed_logins) > 5 AND (now - last_fail) < 5_minutes:
            if exists(successful_login) within window:
                Trigger "Brute Force Success" (Severity: High)
        ```

### 👤 Engine 4: Behavioral Analysis (UEBA)
*   **Goal**: Insider Threat Detection / Account Compromise.
*   **Technique**: Bayes-like Probability Modeling.
*   **Metric**: **Rare Probability Probability**.
    *   We build a probability distribution of user actions (e.g., Login Hour).
    *   Let $P(h)$ be the probability of User $U$ logging in at Hour $h$.
    *   If $P(h) < 0.05$ (Event happens <5% of the time), we flag it as an anomaly.
*   **Concept Drift**: Baselines are re-calculated daily to adapt to changing user behavior.

### 🌐 Engine 5: Network Traffic Analysis
*   **Goal**: Detect "Low & Slow" or "Volumetric" attacks.
*   **Advanced Algorithm: C2 Beacon Detection via Coefficient of Variation (CV)**
    *   **Problem**: How to distinguish a human browsing a site vs. malware "phoning home"?
    *   **Solution**: Analyze Inter-Arrival Times (IAT) of packets.
    *   **Formula**: $$CV = \frac{\sigma_{IAT}}{\mu_{IAT}}$$
    *   **Logic**:
        *   **Human**: High Variance (random clicks). $CV \gg 1$.
        *   **Machine (Beacon)**: Low Variance (automated cron job). $CV \approx 0$.
        *   **Threshold**: If $CV < 0.2$, Alert "Potential C2 Beacon".
*   **DDoS Detection**: Time-series aggregation grouping by `dest_ip`. Threshold: >1000 connections/minute.

### 📝 Engine 6: Rule Engine (Sigma-Style)
*   **Implementation**: Custom YAML parser leveraging Boolean Logic.
*   **Structure**: Supports nested logic (`selection` AND `count`).
*   **Code Insight (`rule_engine.py`)**:
    *   Method `_evaluate_rule` recursively checks conditions.
    *   Supports logical operators `contains`, `regex`, `not`.
    *   **Mapping**: Automatically tags alerts with **MITRE ATT&CK** Tactic/Technique IDs (e.g., T1110) defined in the rule YAML.

---

## 3. Scenario Walkthrough: "The Brute Force Attack"

Here is exactly how the system behaves during a live attack:

1.  **T+0s**: Attacker starts guessing passwords.
    *   *System*: **Anomaly Detector** sees "Failed Login Rate" spike ($Z > 3$). $\rightarrow$ **Alert 1 (Medium)**.
2.  **T+10s**: Attacker fails 25 times.
    *   *System*: **Signature Engine** might not catch it (generic logs).
    *   *System*: **Network Analyzer** sees high connection rate (if high volume).
3.  **T+60s**: Attacker guesses correct password and logs in.
    *   *System*: **Heuristic Engine** correlates `25 Fails` + `1 Success`. $\rightarrow$ **Alert 2 (Critical - "Brute Force Success")**.
    *   *System*: **UEBA** sees user login from new IP (Attacker IP) or unusual time. $\rightarrow$ **Alert 3 (High - "Unusual Location")**.
4.  **Result**: The **Prioritizer** sees alerts from 3 different engines for the same user/IP. It bumps the incident priority to **CRITICAL**.

---

## 4. Evaluator Q&A (The "Grilling" Section)

**Q1: "How does your system perform under load? Doesn't Python struggle?"**
> **Answer**:
> 1.  **Architecture**: We use **DuckDB** as the engine, which is an in-process OLAP database capable of effectively processing millions of rows using vectorized execution.
> 2.  **Async**: The analysis pipeline is fully asynchronous (`asyncio`). We don't block on network or disk I/O.
> 3.  **Batching**: We process logs in micro-batches (e.g., 5 seconds or 1000 logs), minimizing transaction overhead.

**Q2: "What is the specific difference between Heuristic and Rule-based detection?"**
> **Answer**:
> *   **Rule-based (Sigma)** is mostly **Stateless** or simple counters. It says "If X happens, Alert".
> *   **Heuristic** is **Stateful and Multi-Stage**. It understands *sequences* of events (Event A *then* Event B *within* Time T). It captures the *narrative* of an attack, not just atomic events.

**Q3: "How do you handle False Positives?"**
> **Answer**: We use a **weighted priority scoring system**.
> *   An alert from just *one* probabilistic engine (Anomaly) gets a low score.
> *   An alert from a deterministic engine (Signature) gets a high score.
> *   **Cross-Validation**: If multiple engines flag the same Entity (IP/User), the score compounds. This suppresses noise and highlights confident threats.

**Q4: "Can this run offline? What about Threat Intel?"**
> **Answer**: Yes. The system is designed for **Air-Gapped Networks**.
> *   **Local DB**: Threat Intel (IPs, Hashes) is stored locally in DuckDB tables.
> *   **Updates**: We support "Sneaker-net" updates via USB. You download a signed update pack on a connected machine and import it into this specialized tool.

**Q5: "Why did you choose Z-Score? Why not Machine Learning?"**
> **Answer**: **Explainability and Stability**.
> *   Deep Learning models are "black boxes" and hard to debug during a hackathon/operation.
> *   **Z-Score** is statistically sound, transparent, and computationally cheap ($O(1)$) to calculate once you have the running variance. It provides 80/20 value: 80% of the detection power for 20% of the compute cost.

---

## 5. Extensibility & Future Work

*   **Adding New Rules**: Simply drop a `.yaml` file into `config/rules/`. The `RuleEngine` auto-reloads.
*   **Custom Analyzers**: The `AnalysisOrchestrator` uses a plugin architecture. Just create a class with an `analyze(logs)` method and add it to the list.
*   **Scalability**: The "Micro-Batch" architecture allows us to potentially offload the Analysis Layer to a separate worker node, decoupling it from the Ingestion Layer.
