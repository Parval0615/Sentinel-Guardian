from langchain.agents import AgentExecutor
from langchain.memory import ConversationBufferMemory
from langchain.retrievers import BaseRetriever
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.tools import tool
from langchain_openai import ChatOpenAI
from langgraph.graph import END, START, StateGraph


@tool
def search(query: str) -> str:
    return query


def answer(state: dict) -> dict:
    return state


def route(state: dict) -> str:
    return "done" if state else "retry"


def build():
    ChatPromptTemplate.from_template("Answer with evidence")
    ConversationBufferMemory()
    BaseRetriever()
    graph = StateGraph(dict)
    graph.add_node("research", search)
    graph.add_node("answer", answer)
    graph.add_edge(START, "research")
    graph.add_conditional_edges("research", route, {"done": "answer", "retry": "research"})
    graph.add_edge("answer", END)
    graph.set_entry_point("research")
    model = ChatOpenAI()
    bound = model.bind_tools([search])
    AgentExecutor(agent=bound, tools=[search])
    return graph.compile()
