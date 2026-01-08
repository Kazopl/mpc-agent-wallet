#!/usr/bin/env python3
"""
Basic LangChain Agent Example

Demonstrates how to create and use a LangChain agent with MPC wallet tools.
"""

import os
from dotenv import load_dotenv

from mpc_wallet import (
    MpcAgentWallet,
    WalletConfig,
    PolicyConfig,
    PartyRole,
    ChainType,
)

# Import our LangChain tools
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src import create_wallet_agent

# Load environment variables
load_dotenv()


def main():
    print("MPC Wallet LangChain Agent Example\n")

    # =========================================================================
    # Step 1: Initialize MPC Wallet with Policy
    # =========================================================================
    print("[1] Initializing MPC Wallet...")

    wallet = MpcAgentWallet(WalletConfig(
        role=PartyRole.AGENT,
        policy=PolicyConfig()
            .with_spending_limits(
                ChainType.EVM,
                per_tx=int(1e18),    # 1 ETH per transaction
                daily=int(10e18),    # 10 ETH daily
                weekly=int(50e18),   # 50 ETH weekly
            )
            .with_whitelist([
                "0x742d35Cc6634C0532925a3b844Bc9e7595f12345",  # Example
                "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45",  # Uniswap
            ]),
    ))

    # In production, load existing key share
    # await wallet.load_key_share("my-wallet", os.environ["WALLET_PASSWORD"])

    print("    [OK] Wallet initialized with spending policy\n")

    # =========================================================================
    # Step 2: Create LangChain Agent
    # =========================================================================
    print("[2] Creating LangChain Agent...")

    agent = create_wallet_agent(
        wallet=wallet,
        model="gpt-4",
        temperature=0,
        relay_url=os.environ.get("RELAY_URL", ""),
        verbose=True,
    )

    print("    [OK] Agent created with wallet tools\n")

    # =========================================================================
    # Step 3: Run Example Queries
    # =========================================================================
    print("[3] Running example queries...\n")

    queries = [
        "What's my wallet address?",
        "Check my balance on Ethereum",
        "Would I be able to send 0.5 ETH to 0x742d35Cc6634C0532925a3b844Bc9e7595f12345?",
        "Can I send 10 ETH to 0x742d35Cc6634C0532925a3b844Bc9e7595f12345?",
    ]

    for query in queries:
        print(f"Query: {query}")
        print("-" * 50)

        try:
            response = agent.invoke({"input": query})
            print(f"Response: {response['output']}")
        except Exception as e:
            print(f"[ERROR] {e}")

        print("\n")

    # =========================================================================
    # Step 4: Interactive Mode
    # =========================================================================
    print("[4] Interactive Mode (type 'quit' to exit)\n")

    while True:
        try:
            user_input = input("You: ").strip()

            if user_input.lower() in ['quit', 'exit', 'q']:
                print("Goodbye!")
                break

            if not user_input:
                continue

            response = agent.invoke({"input": user_input})
            print(f"Agent: {response['output']}\n")

        except KeyboardInterrupt:
            print("\nGoodbye!")
            break
        except Exception as e:
            print(f"Error: {e}\n")


if __name__ == "__main__":
    main()
