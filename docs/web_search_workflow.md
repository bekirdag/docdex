# Docdex Web Search Workflow (Mermaid)

The diagram below captures the end-to-end web search pipeline as implemented in Docdex.

```mermaid
flowchart TD
    A[Client / MCP caller] --> B[MCP Proxy]
    B --> C{Tool Request}
    C -->|docdex_web_research| D[MCP Server: handle_web_research]
    D --> E[Resolve project_root / repo_path]
    E --> F{skip_local_search?}
    F -->|no| G[ensure_index_ready]
    F -->|yes| H[Skip local indexing]
    G --> I[run_web_research]
    H --> I

    subgraph R[run_web_research]
        I --> J[Detect query intent]
        J --> K{skip_local_search?}
        K -->|no| L[search::run_query (repo + libs)]
        L --> M[LLM local relevance filter (optional)]
        M --> N[Compute top_score / local_match_ratio]
        K -->|yes| O[Empty local hits]
        N --> P[Build completion + scores]
        O --> P
        P --> Q{Web gate enabled?}
        Q -->|no| R1[WebDiscoveryStatus: Disabled]
        Q -->|yes| S{Gate should_attempt?}
        S -->|no| R2[WebDiscoveryStatus: Skipped (confidence)]
        S -->|yes| T[run_web_discovery]
    end

    subgraph W[run_web_discovery]
        T --> U[Load WebConfig (env + config)]
        U --> V[Phrase cache lookup]
        V -->|hit| W1[Serve cached WebFetchResult]
        V -->|miss| X{Browser available?}
        X -->|no| W2[Unavailable: missing_dependency]
        X -->|yes| Y[Init DdgDiscovery + pacer]
        Y --> Z{DDG blocked (24h)?}
        Z -->|yes| AA[Free-first fallback chain]
        Z -->|no| AB[DDG Lite discovery]
        AB -->|blocked| AC[Mark DDG blocked + fallback]
        AB -->|ok| AD[Discovery response]
        AA --> AE[Try configured SearXNG JSON endpoints]
        AE -->|empty/error| AH[Try mSwarm if configured]
        AH -->|empty/error| AI[Try Google CSE]
        AI -->|empty/error| AJ[Try Bing]
        AJ -->|empty/error| AK[Try Tavily then Exa]
        AK -->|empty/error| AG[Try paid Brave API last]
        AE --> AL{response?}
        AG --> AL
        AH --> AL
        AI --> AL
        AJ --> AL
        AK --> AL
        AL -->|none| W3[Unavailable: discovery_empty/failed]
        AL -->|ok| AM[normalize_discovery_response]
        AD --> AM
        AM --> AN[Deduplicate + unwrap DDG redirects]
        AN --> AO[Blocklist + tracking filter]
        AO --> AP[Sort by query category]
        AP --> AQ[Domain diversity cap]
        AQ --> AR[Limit to web_limit]
        AR --> AS[fetch_web_documents]
    end

    subgraph FWD[fetch_web_documents]
        AS --> AT[Resolve fetch URL cap (3x desired)]
        AT --> AU[Resolve fetch budget]
        AU --> AV[Loop URLs (batch size + budget)]
        AV --> AW{Domain cooldown?}
        AW -->|yes| AX[Skip: cooldown]
        AW -->|no| AY[Preflight fetch_status (HEAD/GET)]
        AY --> AZ{Status skip?}
        AZ -->|yes| BA[Skip: preflight]
        AZ -->|no| BB[ScraperEngine: Chrome]
        BB --> BC{Headless fetch OK?}
        BC -->|yes| BD[HTML + text extraction]
        BC -->|no| BE[Direct HTTP fallback]
        BE --> BF{Direct fetch OK?}
        BF -->|no| BG[Failure: fetch]
        BF -->|yes| BD
        BD --> BH[Readability extract]
        BH --> BI[Normalize text]
        BI --> BJ{Cookie wall?}
        BJ -->|yes| BK[Mark domain challenge + skip]
        BJ -->|no| BL{JS challenge?}
        BL -->|yes| BM[Mark domain challenge + skip]
        BL -->|no| BN[Strip banner lines]
        BN --> BO[Boilerplate ratio + penalty]
        BO --> BP[Extract code blocks]
        BP --> BQ{Low content?}
        BQ -->|yes| BR[Skip summary]
        BQ -->|no| BS[LLM summary/eval (budgeted)]
        BR --> BT[Build WebFetchResult]
        BS --> BT
        BT --> BU[Relevance scoring + early stop]
        BU --> BV[Cache URL content + summary]
        BV --> BW[Record domain success]
        BG --> BX[Record domain failure]
        BX --> BY[Cooldown if thresholds met]
    end

    subgraph CH[Headless Chrome Fetch]
        BB --> CH1[ChromeManager get_or_launch]
        CH1 --> CH2[Persistent session + profile dir]
        CH2 --> CH3[CDP connect]
        CH3 --> CH4[Network idle wait (capped)]
        CH4 --> CH5[Dismiss cookie banners]
        CH5 --> CH6[Fetch DOM + inner/text]
        CH6 --> CH7[Return ChromeFetchResult]
    end

    subgraph OUT[Response Assembly]
        R1 --> OUT1[Build response payload]
        R2 --> OUT1
        W1 --> OUT1
        W2 --> OUT1
        W3 --> OUT1
        BT --> OUT1
        OUT1 --> OUT2[Return WebResearchResponse]
        OUT2 --> OUT3[MCP tool response]
    end

    %% Cross-links
    T -.-> U
    AS -.-> BB
    BB -.-> CH1
    BT -.-> OUT1
```
