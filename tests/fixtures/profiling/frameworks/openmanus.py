from app.agent.toolcall import ToolCallAgent
from app.flow.planning import PlanningFlow
from app.tool import BaseTool, ToolCollection
from app.tool.ask_human import AskHuman
from app.tool.mcp import MCPClients
from openai import OpenAI


class SearchTool(BaseTool):
    pass


class Manus(ToolCallAgent):
    pass


def build():
    OpenAI()
    tools = ToolCollection(SearchTool(), AskHuman(), MCPClients())
    PlanningFlow(agents={"manus": Manus()})
    return tools
