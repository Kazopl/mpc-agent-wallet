# DeFi Agent Example

An automated DeFi agent that uses the MPC wallet to run DeFi strategies while keeping the user in control.

## Features

- Automated DeFi operations with human approval
- Yield farming strategy execution
- Token swaps via DEX aggregators
- Liquidity provision management
- Portfolio rebalancing
- Risk management with spending limits

## Installation

```bash
npm install
```

## Configuration

Create a `.env` file:

```env
# Wallet
WALLET_PASSWORD=your-secure-password
WALLET_KEY_PATH=./keys/agent-share.json

# Relay
RELAY_URL=wss://relay.mpc-wallet.example.com

# RPCs
ETH_RPC_URL=https://eth.llamarpc.com
ARBITRUM_RPC_URL=https://arb1.arbitrum.io/rpc

# Strategy Settings
MAX_SLIPPAGE=0.5
REBALANCE_THRESHOLD=5
```

## Strategies

### 1. Yield Farming

```typescript
const strategy = new YieldFarmingStrategy({
  protocols: ['aave', 'compound'],
  targetAPY: 5,
  maxAllocation: '10', // 10 ETH max
  rebalanceInterval: '1d',
});

agent.addStrategy(strategy);
```

### 2. Liquidity Provision

```typescript
const lpStrategy = new LiquidityStrategy({
  pool: 'uniswap-v3-eth-usdc',
  range: { lower: 0.95, upper: 1.05 }, // +/-5% range
  autoCompound: true,
});

agent.addStrategy(lpStrategy);
```

### 3. Portfolio Rebalancing

```typescript
const rebalanceStrategy = new RebalanceStrategy({
  target: {
    ETH: 50,
    USDC: 30,
    WBTC: 20,
  },
  threshold: 5, // Rebalance when >5% drift
  minTradeSize: '0.1', // Min 0.1 ETH equivalent
});

agent.addStrategy(rebalanceStrategy);
```

## Architecture

```
+-------------------------------------------------------------+
|                        DeFi Agent                           |
|  +--------------+  +--------------+  +--------------+       |
|  |  Strategy    |  |   Market     |  |    Risk      |       |
|  |   Engine     |  |   Monitor    |  |   Manager    |       |
|  +------+-------+  +------+-------+  +------+-------+       |
+---------+-----------------+-----------------+---------------+
          |                 |                 |
          +-----------------+-----------------+
                            |
                            v
+-------------------------------------------------------------+
|                      MPC Wallet SDK                         |
|  +--------------+  +--------------+                         |
|  |   Policy     |  |  Threshold   |                         |
|  |   Engine     |  |   Signing    |                         |
|  +--------------+  +--------------+                         |
+-------------------------------------------------------------+
          |
          v
    User Approval via Telegram/Mobile
```

## Usage

### Start the Agent

```bash
npm start
```

### Agent Commands

The agent can be controlled via CLI or API:

```typescript
// Start a strategy
await agent.startStrategy('yield-farming');

// Pause all operations
await agent.pause();

// Check portfolio value
const value = await agent.getPortfolioValue();

// Manual trade (still requires approval)
await agent.executeTrade({
  type: 'swap',
  tokenIn: 'ETH',
  tokenOut: 'USDC',
  amount: '1.0',
});
```

## Project Structure

```
defi-agent/
├── src/
│   ├── index.ts              # Entry point
│   ├── agent.ts              # Main agent class
│   ├── strategies/
│   │   ├── base.ts           # Base strategy class
│   │   ├── yield.ts          # Yield farming
│   │   ├── liquidity.ts      # LP strategies
│   │   └── rebalance.ts      # Portfolio rebalancing
│   ├── protocols/
│   │   ├── uniswap.ts        # Uniswap integration
│   │   ├── aave.ts           # Aave integration
│   │   └── types.ts          # Protocol interfaces
│   └── utils/
│       ├── pricing.ts        # Price fetching
│       └── risk.ts           # Risk calculations
├── package.json
└── tsconfig.json
```

## Safety Features

1. **Policy Enforcement**: All trades checked against spending limits
2. **User Approval**: High-value operations require explicit approval
3. **Risk Limits**: Maximum position sizes and loss limits
4. **Circuit Breaker**: Auto-pause on anomalous market conditions
5. **Audit Trail**: Full logging of all operations

## Example Workflow

```
1. Agent monitors market conditions
   --> Detects yield opportunity on Aave (8% APY)

2. Agent evaluates opportunity
   --> Checks risk parameters
   --> Calculates optimal allocation

3. Agent requests approval
   +---------------------------------------+
   | DeFi Strategy Proposal                |
   |                                       |
   | Strategy: Yield Farming               |
   | Protocol: Aave                        |
   | Action: Deposit 2 ETH                 |
   | Expected APY: 8%                      |
   | Risk Level: Low                       |
   |                                       |
   | [Approve] [Reject] [Details]          |
   +---------------------------------------+

4. User approves via Telegram

5. Agent executes transaction
   --> MPC signing with 2-of-3 parties
   --> Transaction broadcast

6. Agent confirms execution
   --> Updates portfolio tracking
   --> Notifies user of success
```

## Customization

### Custom Strategy

```typescript
import { BaseStrategy, StrategyContext, StrategyAction } from './strategies/base';

class CustomStrategy extends BaseStrategy {
  name = 'custom-strategy';

  async evaluate(ctx: StrategyContext): Promise<StrategyAction | null> {
    // Your custom logic here
    const opportunity = await this.findOpportunity();

    if (opportunity.expectedReturn > this.config.minReturn) {
      return {
        type: 'swap',
        params: opportunity.params,
        reason: `Found ${opportunity.expectedReturn}% opportunity`,
      };
    }

    return null;
  }
}
```

### Risk Parameters

```typescript
const riskConfig = {
  maxPositionSize: '10', // Max 10 ETH per position
  maxDailyLoss: '1',     // Stop if >1 ETH daily loss
  maxSlippage: 0.5,      // Max 0.5% slippage
  minLiquidity: 1000000, // Min $1M pool liquidity
};

agent.setRiskParameters(riskConfig);
```

## Monitoring

The agent exposes metrics for monitoring:

```typescript
// Get current status
const status = await agent.getStatus();
console.log(status);
// {
//   running: true,
//   activeStrategies: ['yield-farming'],
//   portfolioValue: '12.5 ETH',
//   pendingApprovals: 0,
//   dailyPnL: '+0.15 ETH',
// }
```

## Security Best Practices

1. **Start Small**: Test strategies with small amounts first
2. **Set Limits**: Configure conservative spending limits
3. **Monitor**: Set up alerts for unusual activity
4. **Review**: Regularly audit agent decisions
5. **Pause**: Use circuit breaker during volatility

## Next Steps

- See [ElizaOS Plugin](../elizaos-plugin/) for AI agent integration
- See [Telegram Bot](../telegram-bot/) for approval via Telegram
