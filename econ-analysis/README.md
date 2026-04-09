# Economic Model: AI Security ROI Analysis

Part of the AI in Telecom capstone project at Norfolk State University. This component quantifies the return on investment of AI-enhanced security relative to traditional approaches across three telecommunications carrier profiles.

---

## Background

The model answers a single practical question: is AI-enhanced security financially justified for a telecommunications carrier, and under what conditions? It compares three-year total cost of ownership (TCO) for traditional vs AI-enhanced security deployments, incorporating breach cost data from IBM's 2025 Cost of a Data Breach Report [13] and industry benchmarks for staffing and infrastructure.

### What the model is built on

- **Comparative TCO framework** — standard IT economics approach comparing status quo vs investment scenario over a fixed 3-year horizon
- **IBM breach cost differential as the core value driver** — the $1.9M per-breach savings from IBM [13] dominates the ROI calculation; operational cost differences are secondary
- **Carrier segmentation** — three profiles reflect real industry structure (small regional carriers, national large carriers, critical infrastructure operators)
- **Monte Carlo for robustness** — tests whether ROI survives parameter uncertainty across 1,000 simulated scenarios; answers the executive question "what if costs run over and breaches are rare?"
- **Conservative assumptions** — reputational damage, regulatory fines, and customer churn are excluded, so real-world ROI is likely higher than modeled

---

## Data sources

All cost inputs are either directly sourced or derived from published data. Nothing is invented.

| Data point | Value | Source | Hardcoded? |
|---|---|---|---|
| Traditional breach cost | $4.88M | IBM 2025 Cost of a Data Breach [13] | Yes |
| AI-enhanced breach cost | $2.98M | IBM 2025 Cost of a Data Breach [13] | Yes |
| Savings per breach | $1.9M | Derived: $4.88M − $2.98M | Yes |
| Analyst salary | $80K/yr | BLS SOC analyst median | Yes |
| ML engineer salary | $130K/yr | Industry benchmark (Glassdoor/Levels.fyi) | Yes |
| Small carrier analysts (traditional) | 2 FTE | Model assumption | Yes |
| Large carrier analysts (traditional) | 4 FTE | Model assumption | Yes |
| Critical infra analysts (traditional) | 5 FTE | Model assumption | Yes |
| AI analyst reduction | 50% | IBM productivity data [13] | Yes |
| SIEM cost (small) | $100K | Vendor pricing benchmark | Yes |
| SIEM cost (large) | $300K | Vendor pricing benchmark | Yes |
| SIEM cost (critical) | $500K | Vendor pricing benchmark | Yes |
| Setup cost (small) | $100K | 5G Americas guidance [11] | Yes |
| Setup cost (large/critical) | $200K | 5G Americas guidance [11] | Yes |
| Cloud cost (small) | $50K/yr | AWS/Azure security tier pricing | Yes |
| Cloud cost (large/critical) | $150K/yr | AWS/Azure security tier pricing | Yes |
| Breach frequency range | 0.25–3.0 | Scenario sweep | No |
| Monte Carlo iterations | 1,000 | Model design | Yes |
| Breach cost variance | ±20% | Monte Carlo parameter | No |
| Setup cost variance | ±30% | Monte Carlo parameter | No |

**"Savings per breach is derived"** means it is not a number IBM published directly — it is calculated from two numbers they did publish: $4.88M − $2.98M = $1.9M. If IBM's underlying figures change, the savings figure changes automatically. It is not an assumption.

---

## Formulas

**Traditional TCO (3 years):**
```
trad_tco = (analysts × salary × years)
         + siem_cost
         + tools
         + incident_response
```

**AI TCO (3 years):**
```
ai_tco = setup
       + (ai_analysts × salary × years)
       + (ml_engineers × ml_salary × years)
       + (cloud_annual × years)
```

**Total cost with breaches:**
```
trad_total = trad_tco + (breach_freq × breach_cost_traditional)
ai_total   = ai_tco  + (breach_freq × breach_cost_ai)
```

**ROI:**
```
savings = trad_total - ai_total
roi     = (savings / ai_tco) × 100
payback = ai_tco / (savings / years)    # years; multiply by 12 for months
```

**Monte Carlo randomization:**
```
breach_freq       ~ Uniform(0.5, 2.5)
breach_cost_mult  ~ Uniform(0.8, 1.2)    # ±20%
setup_cost_mult   ~ Uniform(0.7, 1.3)    # ±30%
```

---

## Usage

```bash
cd econ-analysis
python economic_model.py
open economic_simulation_results.png
```

### Validate model inputs before running

```bash
python economic_model.py --sanity-check
```

Prints a full cost breakdown for all three carrier types at zero breaches, confirms TCO calculations, and shows break-even breach count. Run this first to verify the model is parameterized correctly before the full simulation.

---

## Understanding the results

The output is a 4-panel figure:

### Panel 1 — ROI vs breach frequency
Three lines (small / large / critical infrastructure) showing ROI % as breach frequency increases over 3 years. A horizontal dashed line marks break-even (ROI = 0%).

- Large and critical carriers reach positive ROI above ~1.0 breach per 3 years
- Small carriers break even at ~0.5 breaches
- ROI scales nonlinearly — each additional breach adds $1.9M to the savings side

### Panel 2 — Cost comparison at 1.0 breach / 3 years
Grouped bars showing traditional vs AI-enhanced total cost per carrier type. Annotations show the savings delta. The dominant cost driver is breach cost avoidance, not operational savings.

### Panel 3 — Monte Carlo ROI distribution
Histogram of ROI outcomes across 1,000 simulated scenarios for a large carrier. Annotations show mean ROI, ±1 standard deviation, and the percentage of positive-ROI scenarios.

- Mean ROI: ~292%
- Std deviation: ~118%
- Positive ROI: ~94% of simulations

The 6% of negative-ROI scenarios cluster at minimum breach frequency + maximum cost overrun — an unlikely but non-zero edge case most relevant to small carriers with low breach history.

### Panel 4 — Payback period by carrier type
Payback period in months as a function of breach frequency. Reference lines at 12 and 24 months.

- Large carrier: ~14 months at 1.5 breaches / 3 years
- Critical infrastructure: ~10 months
- Small carrier at low breach frequency: may exceed 36 months

---

## Carrier profiles

| Profile | Subscribers | Traditional analysts | AI analysts | ML engineers | Setup cost | Cloud/yr |
|---|---|---|---|---|---|---|
| Small | <1M | 2 | 1 | 0.5 FTE | $100K | $50K |
| Large | >5M | 4 | 2 | 1.5 FTE | $200K | $150K |
| Critical infra | >10M | 5 | 3 | 2.0 FTE | $200K | $150K |

Analyst headcount reduction under AI reflects IBM's documented productivity gains from AI-assisted triage and alert prioritization [13]. ML engineers are a net new cost with no traditional equivalent.

---

## Reproducing results

The Monte Carlo simulation is seeded at `np.random.seed(42)` — results are identical across runs. To rerun:

```bash
cd econ-analysis
python economic_model.py
```

To test a different carrier type or parameter range, edit the top of `economic_model.py`:

```python
# Change carrier type
mc_results = monte_carlo_simulation(n_simulations=1000, carrier_type='small')

# Change breach frequency scenarios
breach_scenarios = [0.25, 0.5, 0.75, 1.0, 1.5, 2.0, 2.5, 3.0]
```

---

## Limitations

- Breach costs are IBM US-market figures and may not reflect regional carrier exposure
- Analyst and engineer salaries are US benchmarks — adjust for local market conditions
- Reputational damage, regulatory fines, and customer churn are excluded — actual ROI is likely higher
- Model assumes breach frequency is independent across years — correlated breach risk (e.g. sustained APT campaign) is not modeled
- Setup costs reflect initial deployment only — organizational change management and training costs are not included
