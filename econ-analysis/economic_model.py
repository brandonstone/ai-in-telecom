# File: economic_model.py
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import seaborn as sns

class TelecomSecurityCostModel:
    """
    Economic model comparing Traditional vs AI security costs
    Based on IBM 2025 breach data [13] and industry benchmarks
    """
    
    def __init__(self, subscriber_count, carrier_type='large'):
        self.subscribers = subscriber_count
        self.carrier_type = carrier_type
        
        # Traditional Security Costs (3-year totals)
        if carrier_type == 'small':  # <1M subscribers
            self.trad_analysts = 2
            self.trad_siem_cost = 100000
        elif carrier_type == 'large':  # >5M subscribers
            self.trad_analysts = 4
            self.trad_siem_cost = 300000
        else:  # critical infrastructure
            self.trad_analysts = 5
            self.trad_siem_cost = 500000
            
        self.analyst_salary = 80000
        self.trad_tools = 150000  # Firewalls, IDS, threat intel
        self.trad_incident_response = 150000
        
        # AI Security Costs (3-year totals)
        self.ai_setup = 200000 if carrier_type != 'small' else 100000
        self.ai_cloud_annual = 150000 if carrier_type != 'small' else 50000
        self.ml_engineer_salary = 130000
        
        if carrier_type == 'small':
            self.ai_ml_engineers = 0.5  # Part-time or shared
            self.ai_analysts = 1  # Reduced from 2
        elif carrier_type == 'large':
            self.ai_ml_engineers = 1.5
            self.ai_analysts = 2  # Reduced from 4
        else:
            self.ai_ml_engineers = 2
            self.ai_analysts = 3  # Reduced from 5
        
        # Breach costs from IBM [13]
        self.breach_cost_traditional = 4.88e6  # $4.88M
        self.breach_cost_ai = 2.98e6  # $2.98M
        self.breach_savings = 1.9e6  # $1.9M per breach
    
    def calculate_tco_traditional(self, years):
        """
        Calculate total cost of ownership for traditional security over given period.
        """
        analyst_cost = self.trad_analysts * self.analyst_salary * years
        tco = (
            analyst_cost +
            self.trad_siem_cost +
            self.trad_tools +
            self.trad_incident_response
        )
        return tco
    
    def calculate_tco_ai(self, years):
        """
        Calculate total cost of ownership for AI-enhanced security over given period.
        """
        analyst_cost = self.ai_analysts * self.analyst_salary * years
        engineer_cost = self.ai_ml_engineers * self.ml_engineer_salary * years
        cloud_cost = self.ai_cloud_annual * years
        tco = (
            self.ai_setup +
            analyst_cost +
            engineer_cost +
            cloud_cost
        )
        return tco

def run_scenario_analysis(carrier_type, breach_frequencies):
    """
    Test ROI across different breach frequency scenarios
    """
    model = TelecomSecurityCostModel(
        subscriber_count=5000000 if carrier_type=='large' else 800000,
        carrier_type=carrier_type
    )
    
    results = []
    for breach_freq in breach_frequencies:
        # Calculate costs
        trad_tco = model.calculate_tco_traditional(years=3)
        ai_tco = model.calculate_tco_ai(years=3)
        
        # Add breach costs
        trad_total = trad_tco + (breach_freq * model.breach_cost_traditional)
        ai_total = ai_tco + (breach_freq * model.breach_cost_ai)
        
        # Calculate ROI
        savings = trad_total - ai_total
        roi = (savings / ai_tco) * 100 if ai_tco > 0 else 0
        payback = (ai_tco / (savings / 3)) if savings > 0 else float('inf')
        
        results.append({
            'carrier_type': carrier_type,
            'breach_frequency': breach_freq,
            'traditional_cost': trad_total,
            'ai_cost': ai_total,
            'savings': savings,
            'roi_percent': roi,
            'payback_years': payback
        })
    
    return pd.DataFrame(results)

def calculate_roi(model, breach_freq, years=3):
    """
    Calculate ROI comparing traditional vs AI security over a given period.
    
    Args:
        model: TelecomSecurityCostModel instance
        breach_freq: number of breaches expected over the period
        years: time horizon (default 3)
    
    Returns:
        dict with cost breakdown and ROI metrics
    """
    # Traditional TCO
    trad_analyst_cost = model.trad_analysts * model.analyst_salary * years
    trad_tco = trad_analyst_cost + model.trad_siem_cost + model.trad_tools + model.trad_incident_response

    # AI TCO
    ai_analyst_cost = model.ai_analysts * model.analyst_salary * years
    ai_engineer_cost = model.ai_ml_engineers * model.ml_engineer_salary * years
    ai_cloud_cost = model.ai_cloud_annual * years
    ai_tco = model.ai_setup + ai_analyst_cost + ai_engineer_cost + ai_cloud_cost

    # Add breach costs
    trad_total = trad_tco + (breach_freq * model.breach_cost_traditional)
    ai_total = ai_tco + (breach_freq * model.breach_cost_ai)

    # ROI metrics
    savings = trad_total - ai_total
    roi = (savings / ai_tco) * 100 if ai_tco > 0 else 0
    payback_years = (ai_tco / (savings / years)) if savings > 0 else float('inf')

    return {
        'traditional_tco': trad_tco,
        'ai_tco': ai_tco,
        'traditional_total': trad_total,
        'ai_total': ai_total,
        'savings': savings,
        'roi_percent': roi,
        'payback_years': payback_years,
        'breach_frequency': breach_freq
    }

def monte_carlo_simulation(n_simulations=1000, carrier_type='large'):
    """
    Test ROI robustness across parameter uncertainty
    """
    np.random.seed(42)
    results = []
    
    for i in range(n_simulations):
        # Randomize parameters within realistic ranges
        breach_freq = np.random.uniform(0.5, 2.5)  # Breaches over 3 years
        
        # Vary breach costs ±20%
        breach_cost_mult = np.random.uniform(0.8, 1.2)
        
        # Vary implementation costs ±30%
        setup_cost_mult = np.random.uniform(0.7, 1.3)
        
        # Create model instance with randomized parameters
        model = TelecomSecurityCostModel(
            subscriber_count=5000000,
            carrier_type=carrier_type
        )
        model.breach_cost_traditional *= breach_cost_mult
        model.breach_cost_ai *= breach_cost_mult
        model.ai_setup *= setup_cost_mult
        
        # Calculate ROI for this iteration
        result = calculate_roi(model, breach_freq)
        result['simulation_id'] = i
        results.append(result)
    
    return pd.DataFrame(results)

def sanity_check(years=3):
    """
    Print cost breakdown for all carrier types to validate model numbers
    before running full simulation.
    """
    carrier_types = ['small', 'large', 'critical']
    subscriber_map = {
        'small': 800_000,
        'large': 5_000_000,
        'critical': 10_000_000
    }

    print("=" * 65)
    print(f"COST MODEL SANITY CHECK — {years}-Year Horizon")
    print("=" * 65)

    for carrier in carrier_types:
        m = TelecomSecurityCostModel(
            subscriber_count=subscriber_map[carrier],
            carrier_type=carrier
        )

        trad_tco = m.calculate_tco_traditional(years)
        ai_tco   = m.calculate_tco_ai(years)

        trad_analyst_cost = m.trad_analysts * m.analyst_salary * years
        ai_analyst_cost   = m.ai_analysts * m.analyst_salary * years
        ai_engineer_cost  = m.ai_ml_engineers * m.ml_engineer_salary * years
        ai_cloud_cost     = m.ai_cloud_annual * years

        print(f"\n{'─' * 65}")
        print(f"  {carrier.upper()} CARRIER")
        print(f"{'─' * 65}")

        print(f"  TRADITIONAL")
        print(f"    Analysts ({m.trad_analysts} FTE × ${m.analyst_salary:,}/yr × {years}yr): "
              f"${trad_analyst_cost:>12,.0f}")
        print(f"    SIEM:                                          ${m.trad_siem_cost:>12,.0f}")
        print(f"    Tools:                                         ${m.trad_tools:>12,.0f}")
        print(f"    Incident response reserve:                     ${m.trad_incident_response:>12,.0f}")
        print(f"    {'─' * 50}")
        print(f"    TCO (no breaches):                             ${trad_tco:>12,.0f}")

        print(f"\n  AI-ENHANCED")
        print(f"    Setup:                                         ${m.ai_setup:>12,.0f}")
        print(f"    Analysts ({m.ai_analysts} FTE × ${m.analyst_salary:,}/yr × {years}yr): "
              f"${ai_analyst_cost:>12,.0f}")
        print(f"    ML engineers ({m.ai_ml_engineers} FTE × ${m.ml_engineer_salary:,}/yr × {years}yr): "
              f"${ai_engineer_cost:>12,.0f}")
        print(f"    Cloud ({years}yr):                                   ${ai_cloud_cost:>12,.0f}")
        print(f"    {'─' * 50}")
        print(f"    TCO (no breaches):                             ${ai_tco:>12,.0f}")

        print(f"\n  BREACH IMPACT (per incident)")
        print(f"    Traditional breach cost:                       ${m.breach_cost_traditional:>12,.0f}")
        print(f"    AI breach cost:                                ${m.breach_cost_ai:>12,.0f}")
        print(f"    Savings per breach:                            ${m.breach_savings:>12,.0f}")

        # Break-even breach count
        baseline_diff = trad_tco - ai_tco
        if baseline_diff < 0:
            breakeven = abs(baseline_diff) / m.breach_savings
            print(f"\n  ⚠  AI costs more at zero breaches by ${abs(baseline_diff):,.0f}")
            print(f"     Break-even at {breakeven:.2f} breaches over {years} years")
        else:
            print(f"\n  ✓  AI cheaper even at zero breaches by ${baseline_diff:,.0f}")
            print(f"     Break-even: immediate")

    print(f"\n{'=' * 65}")
    print("  Run sanity_check(years=1) to verify annual figures.")
    print("=" * 65)

# Run for all carrier types
breach_scenarios = [0.25, 0.5, 0.75, 1.0, 1.5, 2.0, 2.5, 3.0]
small_results = run_scenario_analysis('small', breach_scenarios)
large_results = run_scenario_analysis('large', breach_scenarios)
critical_results = run_scenario_analysis('critical', breach_scenarios)

# Monte Carlo Simulation
mc_results = monte_carlo_simulation(n_simulations=1000, carrier_type='large')

# Calculate statistics
roi_mean = mc_results['roi_percent'].mean()
roi_std = mc_results['roi_percent'].std()
positive_roi_pct = (mc_results['roi_percent'] > 0).sum() / len(mc_results) * 100

print(f"Mean ROI: {roi_mean:.1f}%")
print(f"Std Dev: {roi_std:.1f}%")
print(f"Probability of positive ROI: {positive_roi_pct:.1f}%")

sanity_check(years=3)

# Visualize Results
# Set style
plt.rcParams['figure.figsize'] = (14, 10)

sns.set_style("whitegrid")
fig, axes = plt.subplots(2, 2, figsize=(14, 10))
fig.suptitle('AI Security Investment: Economic Simulation Results', 
             fontsize=16, fontweight='bold', y=1.02)

colors = {
    'Small': '#2196F3',
    'Large': '#4CAF50', 
    'Critical': '#F44336',
    'Traditional': '#FF7043',
    'AI': '#42A5F5'
}

# Create 4-panel figure
fig, axes = plt.subplots(2, 2, figsize=(14, 10))

# Panel 1: ROI vs Breach Frequency (all carrier types)
for carrier_type, df in [('Small', small_results), 
                         ('Large', large_results), 
                         ('Critical', critical_results)]:
    axes[0,0].plot(df['breach_frequency'], df['roi_percent'], 
                   marker='o', linewidth=2, label=carrier_type)
axes[0,0].axhline(y=0, color='red', linestyle='--', label='Break-even')
axes[0,0].set_xlabel('Breach Frequency (over 3 years)', fontsize=12)
axes[0,0].set_ylabel('ROI (%)', fontsize=12)
axes[0,0].set_title('AI Security ROI by Carrier Type', fontsize=14, fontweight='bold')
axes[0,0].legend()
axes[0,0].grid(True, alpha=0.3)

# Panel 2: Cost Comparison Bar Chart
ax2 = axes[0, 1]

carrier_labels = ['Small', 'Large', 'Critical']
x = np.arange(len(carrier_labels))
width = 0.35

# Pull costs at median breach frequency (1.0) for each carrier
def get_costs_at_freq(df, freq=1.0):
    row = df[df['breach_frequency'] == freq].iloc[0]
    return row['traditional_cost'], row['ai_cost']

small_t,  small_a  = get_costs_at_freq(small_results)
large_t,  large_a  = get_costs_at_freq(large_results)
crit_t,   crit_a   = get_costs_at_freq(critical_results)

trad_costs = [small_t, large_t, crit_t]
ai_costs   = [small_a, large_a, crit_a]

bars1 = ax2.bar(x - width/2, [c/1e6 for c in trad_costs], width,
                label='Traditional', color=colors['Traditional'], alpha=0.85)
bars2 = ax2.bar(x + width/2, [c/1e6 for c in ai_costs], width,
                label='AI-Enhanced', color=colors['AI'], alpha=0.85)

# Annotate savings delta
for i, (t, a) in enumerate(zip(trad_costs, ai_costs)):
    savings = (t - a) / 1e6
    ax2.annotate(f'−${savings:.2f}M',
                 xy=(i, max(t, a)/1e6 + 0.1),
                 ha='center', fontsize=8.5, color='green', fontweight='bold')

ax2.set_xlabel('Carrier Type', fontsize=11)
ax2.set_ylabel('3-Year Total Cost ($M)', fontsize=11)
ax2.set_title('Cost Comparison at 1.0 Breach / 3 Years', fontsize=13, fontweight='bold')
ax2.set_xticks(x)
ax2.set_xticklabels(carrier_labels)
ax2.legend(fontsize=9)
ax2.grid(True, alpha=0.3, axis='y')

# ── Panel 3: Monte Carlo ROI Distribution ───────────────────────────────────
ax3 = axes[1, 0]

roi_values = mc_results['roi_percent']
roi_mean   = roi_values.mean()
roi_std    = roi_values.std()
pct_positive = (roi_values > 0).mean() * 100

ax3.hist(roi_values, bins=50, color=colors['AI'], alpha=0.75, edgecolor='white')

# Mean and ±1 std dev lines
ax3.axvline(roi_mean, color='navy', linewidth=2, linestyle='-',
            label=f'Mean: {roi_mean:.0f}%')
ax3.axvline(roi_mean - roi_std, color='navy', linewidth=1.5, linestyle='--',
            label=f'±1 SD: {roi_std:.0f}%')
ax3.axvline(roi_mean + roi_std, color='navy', linewidth=1.5, linestyle='--')
ax3.axvline(0, color='red', linewidth=1.5, linestyle='--', label='Break-even')

# Shade negative ROI region
ax3.axvspan(roi_values.min(), 0, alpha=0.08, color='red')

ax3.text(0.97, 0.95, f'{pct_positive:.1f}% positive ROI',
         transform=ax3.transAxes, ha='right', va='top',
         fontsize=10, fontweight='bold', color='green',
         bbox=dict(boxstyle='round,pad=0.3', facecolor='white', edgecolor='green'))

ax3.set_xlabel('ROI (%)', fontsize=11)
ax3.set_ylabel('Frequency (out of 1,000 simulations)', fontsize=11)
ax3.set_title('Monte Carlo ROI Distribution\n(Large Carrier, n=1,000)', 
              fontsize=13, fontweight='bold')
ax3.legend(fontsize=9)
ax3.grid(True, alpha=0.3)

# ── Panel 4: Payback Period vs Breach Frequency ──────────────────────────────
ax4 = axes[1, 1]

for label, df in [('Small', small_results), 
                  ('Large', large_results), 
                  ('Critical', critical_results)]:
    # Cap infinite payback at 5 years for readability
    payback = df['payback_years'].clip(upper=5)
    ax4.plot(df['breach_frequency'], payback * 12,  # convert to months
             marker='o', linewidth=2, label=label, color=colors[label])

# Reference lines
ax4.axhline(y=12, color='gray', linestyle=':', linewidth=1.5, label='12 months')
ax4.axhline(y=24, color='gray', linestyle='--', linewidth=1.5, label='24 months')

ax4.set_xlabel('Breach Frequency (over 3 years)', fontsize=11)
ax4.set_ylabel('Payback Period (months)', fontsize=11)
ax4.set_title('Payback Period by Carrier Type', fontsize=13, fontweight='bold')
ax4.set_ylim(0, 60)
ax4.legend(fontsize=9)
ax4.grid(True, alpha=0.3)

plt.tight_layout()
plt.savefig('economic_simulation_results.png', dpi=300, bbox_inches='tight')
plt.show()

plt.tight_layout()
plt.savefig('economic_simulation_results.png', dpi=300, bbox_inches='tight')