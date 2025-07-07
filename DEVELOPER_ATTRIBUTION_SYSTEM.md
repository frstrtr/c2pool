# C2Pool Developer Attribution System

## Overview

C2Pool implements a developer attribution system that ensures every block mined includes a developer attribution output in the coinbase transaction, while allowing miners to control the fee amount.

## Behavior Summary

### When `--dev-donation 0` (Default)
- **Attribution**: Exactly 1 satoshi is allocated to the developer address
- **Purpose**: Software marking and attribution without significant fee
- **Benefit**: Miners keep 99.999999% of block rewards
- **Example**: On a 12.5 LTC block (1,250,000,000 satoshis), only 1 satoshi goes to attribution

### When `--dev-donation X` (X > 0)
- **Attribution**: X% of block reward goes to developer address
- **Purpose**: Voluntary support for development
- **Range**: 0.1% to 50% maximum
- **Example**: `--dev-donation 2.5` allocates 2.5% of block rewards

## Implementation Details

### Core Logic (in `payout_manager.cpp`)
```cpp
uint64_t DeveloperPayoutConfig::get_developer_amount(uint64_t block_reward) const {
    if (configured_fee_percent == 0.0 && minimal_attribution_mode) {
        // Use minimal attribution (1 satoshi) for software marking
        return MINIMAL_ATTRIBUTION_SATOSHIS;  // = 1
    }
    
    // Use percentage-based calculation for donations
    double percentage = get_total_developer_fee();
    return static_cast<uint64_t>(block_reward * percentage / 100.0);
}
```

### CLI Usage
```bash
# Minimal attribution (1 satoshi only)
c2pool --dev-donation 0

# Voluntary donation examples
c2pool --dev-donation 1.0    # 1% donation
c2pool --dev-donation 2.5    # 2.5% donation
c2pool --dev-donation 5.0    # 5% donation
```

## Comparison with Traditional Fees

| Scenario | Dev Fee | Amount (12.5 LTC block) | Miner Gets |
|----------|---------|-------------------------|-------------|
| Traditional 0.5% | 0.5% | 6,250,000 satoshis (0.0625 LTC) | 99.5% |
| **C2Pool minimal** | **1 satoshi** | **1 satoshi (0.00000001 LTC)** | **99.999999%** |
| Voluntary 1% | 1.0% | 12,500,000 satoshis (0.125 LTC) | 99.0% |
| Voluntary 2.5% | 2.5% | 31,250,000 satoshis (0.3125 LTC) | 97.5% |

## Benefits

1. **Miner-Friendly**: When no donation is specified, miners keep almost all rewards
2. **Software Attribution**: Blocks are still marked as produced by C2Pool software
3. **Voluntary Support**: Users can choose to support development with any percentage
4. **Transparent**: Clear documentation of fee behavior
5. **No Hidden Fees**: No mandatory percentage fees beyond minimal attribution

## Multi-Blockchain Support

The system supports developer addresses for:
- **Litecoin (LTC)**: Full implementation
- **Bitcoin (BTC)**: Address validation ready
- **Ethereum (ETH)**: Planned
- **Monero (XMR)**: Planned
- **Zcash (ZEC)**: Planned
- **Dogecoin (DOGE)**: Planned

## Node Owner Fees

Additionally, pool operators can configure:
```bash
c2pool --node-owner-fee 1.5 --node-owner-address YOUR_ADDRESS
```

This is separate from developer attribution and allows pool operators to take a small fee for running the pool infrastructure.

## Configuration Validation

The system enforces:
- Developer donation: 0-50% maximum
- Node owner fee: 0-50% maximum
- Combined fees cannot exceed 51% (miners always get ≥49%)
- Address validation for all configured addresses
- Automatic fallback to minimal attribution if configuration errors occur

This ensures miners always receive the majority of block rewards while allowing flexible support for development and pool operation.
