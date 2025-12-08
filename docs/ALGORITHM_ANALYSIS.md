# Analysis Algorithms & Implementation Details

This document provides a comprehensive technical breakdown of the detection algorithms implemented in the Log Analysis System. It is designed to assist in technical evaluations and hackathon presentations.

## 1. Overview of Detection Architecture

The system employs a multi-layered detection strategy, combining deterministic (signature-based) and probabilistic (anomaly/behavioral) approaches to maximize detection coverage while minimizing false positives.

| Detection Engine | Methodology | Use Case |
|-----------------|-------------|----------|
| **Signature Detector** | Pattern Matching (Regex, Hash) | Known threats (SQLi, Malware, C2 IPs) |
| **Anomaly Detector** | Statistical Profiling (Z-score, IQR) | Traffic spikes, unusual error rates |
| **Network Analyzer** | Flow Analysis (Windowed Aggregation) | DDoS, Port Scans, Beaconing, Tunneling |
| **Heuristic Analyzer** | Rule-Based Correlation | Multi-stage attacks (Brute Force, Priv Esc) |
| **Behavioral Analyzer (UEBA)** | User Profiling (Baselines) | Insider threats, Compromised accounts |

---

## 2. Detailed Algorithm Analysis

### A. Signature-Based Detection
*File: `backend/analyzers/signature_detector.py`*

**Approach:**
1.  **Regex Pattern Matching:**
    -   **Implementation:** Python `re` module with `re.IGNORECASE | re.MULTILINE` flags.
    -   **Optimization:** Patterns are pre-compiled at startup and cached in memory.
    -   **Logic:** Logs are scanned against a library of YAML-defined rules (e.g., `(union|select|insert).*from`).
2.  **Hash-Based Detection:**
    -   **Implementation:** Dictionary lookup (O(1) complexity).
    -   **Logic:** Extracts file hashes (MD5/SHA256) from logs and checks against a known malware hash database.
3.  **IP Reputation:**
    -   **Implementation:** Set-based membership testing (O(1)).
    -   **Logic:** Checks source IPs against a loaded blocklist of known malicious actors.

### B. Anomaly Detection
*File: `backend/analyzers/anomaly_detector.py`*

**Approach:**
1.  **Statistical Profiling (Z-Score):**
    -   **Use Case:** Login frequency, Command execution rate.
    -   **Formula:** $Z = (X - \mu) / \sigma$
    -   **Logic:** Calculates the number of standard deviations a data point is from the mean. If $Z > 3.0$ (configurable), it's flagged as an anomaly.
2.  **Moving Average:**
    -   **Use Case:** Error rates, Failed login rates.
    -   **Logic:** Compares current window average against a historical moving average to detect sudden spikes rather than gradual trends.
3.  **Isolation Forest (or IQR Fallback):**
    -   **Use Case:** Unique destination IPs.
    -   **Implementation:** `sklearn.ensemble.IsolationForest` (if available) or Interquartile Range (IQR).
    -   **Logic:** Isolates anomalies by randomly partitioning data. Anomalies require fewer partitions to isolate than normal points.
    -   **Fallback:** $Anomaly = X > Q3 + 1.5 * IQR$

### C. Network Traffic Analysis
*File: `backend/analyzers/network_analyzer.py`*

**Approach:**
1.  **DDoS Detection (Time-Window Aggregation):**
    -   **Algorithm:** `Connections per Minute` > Threshold (1000).
    -   **Implementation:** Sliding window aggregation (1 minute) grouping by Destination IP.
2.  **Port Scan Detection:**
    -   **Algorithm:** `Unique Ports` > Threshold (20) per Source IP in 1 minute.
    -   **Logic:** Tracks the set of distinct destination ports accessed by a single IP.
3.  **C2 Beaconing Detection:**
    -   **Algorithm:** Coefficient of Variation (CV) of Inter-Arrival Times.
    -   **Formula:** $CV = \sigma / \mu$
    -   **Logic:** Human traffic is bursty (High CV). Automated beaconing is regular (Low CV < 0.2). If specific IP pairs show extremely regular connection intervals, it indicates malware callback.
4.  **DNS Tunneling:**
    -   **Algorithm:** High volume of DNS queries per Source IP.
    -   **Logic:** Checks for >100 DNS queries/minute, indicating data exfiltration via DNS query records.

### D. Heuristic Analysis
*File: `backend/analyzers/heuristic_analyzer.py`*

**Approach:**
1.  **Multi-Stage Correlation:**
    -   **Logic:** Correlates multiple events across time windows.
    -   **Example (Brute Force):** N failed logins (event A) + 1 successful login (event B) within T minutes.
2.  **Privilege Escalation:**
    -   **Logic:** Detects `Login Event` followed by `Sudo/Admin Command` within 10 minutes.
3.  **Lateral Movement:**
    -   **Logic:** Single User accessing >5 Unique Hosts within 15 minutes.
4.  **Data Exfiltration:**
    -   **Logic:** Sum of `bytes_out` > 100MB within 5 minutes for a single Source IP.

### E. Behavioral Analysis (UEBA)
*File: `backend/analyzers/behavioral_analyzer.py`*

**Approach:**
1.  **User Profiling:**
    -   **Structure:** Maintains a `UserProfile` object for each user containing:
        -   `typical_login_times` (Frequency distribution by hour)
        -   `typical_source_ips` (Set of known IPs)
        -   `typical_resources` (Set of accessed files/DBs)
2.  **Baseline Building:**
    -   **Logic:** Builds profiles from historical data (min 10 data points). Continually updates with new "normal" traffic.
3.  **Deviation Detection:**
    -   **Time:** Calculates probability of login at current hour $P(h)$. If $P(h) < 0.05$ (5%), flag as unusual.
    -   **Location:** If Source IP $\notin$ `typical_source_ips`, flag as anomaly.

---

## 3. Hackathon Evaluator Q&A

### Conceptual Questions

**Q1: How does your system distinguish between a busy user and a DDoS attack?**
*   **A:** We use distinct algorithms. A busy user might have high bandwidth (detected by Bandwidth Anomaly) but usually connects to a few endpoints. A DDoS attack is characterized by a high volume of connections from many sources to a single destination (Network Analyzer) or a single source opening connections to many ports (Port Scan). We specifically look for connection *rate* (req/sec) anomalies rather than just volume.

**Q2: Why do you need both Signature and Anomaly detection?**
*   **A:** Signature detection is highly accurate for *known* threats (zero false positives for checking a known malicious hash) but misses zero-day exploits. Anomaly detection catches *unknown* threats (zero-days) by flagging deviations from normal baselines, even if no signature exists, but carries a higher false positive rate. The combination provides defense-in-depth.

**Q3: How does the Beaconing detection algorithm work?**
*   **A:** We use the Coefficient of Variation (CV) of inter-arrival times. Automated malware (beacons) "checks in" at regular intervals (e.g., every 30s). This results in a very low standard deviation relative to the mean (Low CV). Normal human browsing is erratic/bursty (High CV). We flag connections with $CV < 0.2$.

### Implementation Questions

**Q4: How do you handle scalability with high-volume logs?**
*   **A:** 
    1.  **Async Processing:** We use `asyncio` in Python to handle I/O-bound operations efficiently without blocking.
    2.  **Optimized Regex:** Signatures are pre-compiled (`re.compile`) to avoid runtime overhead.
    3.  **Efficient Storage:** We use DuckDB, an embedded OLAP database optimized for analytical queries on large datasets, avoiding the overhead of client-server DBs for this scale.

**Q5: How does the Heuristic Analyzer correlate events?**
*   **A:** It uses stateful logic over sliding time windows. For example, to detect Brute Force Success, it groups logs by `(source_ip, user)` and sorts them by time. It then iterates through the sorted list maintaining a counter of failed attempts. If the counter exceeds the threshold and is followed by a success within the time window (`window_minutes`), alerts are triggered.

**Q6: What happens if a user's behavior changes legitmately (e.g., traveling)?**
*   **A:** The Behavioral Analyzer (UEBA) is designed to be adaptive. While it initially flags the new IP as unusual, the system can be enhanced to incorporate feedback or slowly decay older baseline data to adapt to new "normals" over time (concept drift). Currently, it flags it for analyst review.

### Algorithm Specifics

**Q7: Why use Z-Score instead of simple thresholds?**
*   **A:** Simple thresholds (e.g., "Alert if > 100 logins") are rigid and don't account for natural variance. Z-Score adapts to the *variability* of the data. If a server normally has 100 logins $\pm$ 5, then 120 is anomalous. If it has 100 $\pm$ 50, then 120 is normal. Z-Score ($>3\sigma$) captures this statistical significance.

**Q8: How do you map alerts to MITRE ATT&CK?**
*   **A:** Each Heuristic Rule and Network Alert types are mapped to specific MITRE Tactic/Technique IDs.
    -   Brute Force $\rightarrow$ **T1110 (Credential Access)**
    -   Port Scan $\rightarrow$ **T1046 (Discovery)**
    -   Beaconing $\rightarrow$ **T1071 (Command & Control)**
    -   This mapping is visualized in the Threat Intel dashboard for strategic context.
