"""
LangChain Agent setup for MPC Wallet

Updated for LangChain v1.2.3+ with latest agent patterns.
"""

from typing import Optional
from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain_openai import ChatOpenAI
from langchain.memory import ConversationBufferWindowMemory
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder

from mpc_wallet import MpcAgentWallet
from .tools import create_wallet_tools
from .prompts import WALLET_SYSTEM_PROMPT


def create_wallet_agent(
    wallet: MpcAgentWallet,
    model: str = "gpt-4o",
    temperature: float = 0,
    relay_url: str = "",
    rpc_urls: Optional[dict] = None,
    memory_window: int = 10,
    verbose: bool = False,
) -> AgentExecutor:
    """
    Create a LangChain agent with MPC wallet tools.

    Uses the latest LangChain v1.2.3+ patterns with tool calling agents.

    Args:
        wallet: Initialized MpcAgentWallet instance
        model: OpenAI model to use (default: gpt-4o)
        temperature: LLM temperature
        relay_url: URL of the relay service
        rpc_urls: Dict of chain -> RPC URL mappings
        memory_window: Number of messages to keep in memory
        verbose: Whether to print agent steps

    Returns:
        Configured AgentExecutor
    """
    # Create LLM
    llm = ChatOpenAI(
        model=model,
        temperature=temperature,
    )

    # Create tools
    tools = create_wallet_tools(
        wallet=wallet,
        relay_url=relay_url,
        rpc_urls=rpc_urls,
    )

    # Create prompt with latest pattern
    prompt = ChatPromptTemplate.from_messages([
        ("system", WALLET_SYSTEM_PROMPT),
        MessagesPlaceholder(variable_name="chat_history", optional=True),
        ("human", "{input}"),
        MessagesPlaceholder(variable_name="agent_scratchpad"),
    ])

    # Create memory
    memory = ConversationBufferWindowMemory(
        memory_key="chat_history",
        k=memory_window,
        return_messages=True,
    )

    # Create agent using latest tool calling pattern
    agent = create_tool_calling_agent(llm, tools, prompt)

    # Create executor
    executor = AgentExecutor(
        agent=agent,
        tools=tools,
        memory=memory,
        verbose=verbose,
        handle_parsing_errors=True,
        max_iterations=5,
    )

    return executor


async def create_async_wallet_agent(
    wallet: MpcAgentWallet,
    model: str = "gpt-4o",
    **kwargs,
) -> AgentExecutor:
    """
    Create an async-capable wallet agent.

    Same as create_wallet_agent but configured for async operations.

    Args:
        wallet: Initialized MpcAgentWallet instance
        model: OpenAI model to use
        **kwargs: Additional arguments passed to create_wallet_agent

    Returns:
        Configured AgentExecutor with async support
    """
    # Create the standard agent
    agent = create_wallet_agent(wallet, model, **kwargs)

    # The AgentExecutor already supports async via ainvoke
    return agent


def create_simple_wallet_chain(
    wallet: MpcAgentWallet,
    model: str = "gpt-4o",
) -> AgentExecutor:
    """
    Create a simple wallet chain without memory.

    Useful for stateless operations or when you manage memory externally.

    Args:
        wallet: Initialized MpcAgentWallet instance
        model: OpenAI model to use

    Returns:
        Configured AgentExecutor without memory
    """
    llm = ChatOpenAI(model=model, temperature=0)
    tools = create_wallet_tools(wallet)

    prompt = ChatPromptTemplate.from_messages([
        ("system", WALLET_SYSTEM_PROMPT),
        ("human", "{input}"),
        MessagesPlaceholder(variable_name="agent_scratchpad"),
    ])

    agent = create_tool_calling_agent(llm, tools, prompt)

    return AgentExecutor(
        agent=agent,
        tools=tools,
        verbose=False,
        handle_parsing_errors=True,
    )
